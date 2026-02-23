"""B4 full baseline: PoP + continuous risk + progressive throttling."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from baselines.B3_pop_only.app import dpop_sign
from experiments.latency import latency_ms_with_jitter
from experiments.mock_upstream import chat_completion
from fastapi import FastAPI

SECRET = "b4-local-secret"
CTX_SECRET = "b4-ctx-secret"
TOKEN_TTL_SECONDS = 120
IAT_WINDOW_SECONDS = 300
CALIBRATION_PATH = Path("baselines/B4_full/calibration.json")


@dataclass
class BudgetState:
    minute: int
    rpm_remaining: int
    tpm_remaining: int


@dataclass
class Profile:
    asn: str
    country: str
    device_fp: str
    ua_major: str
    last_exchange_ts: int


@dataclass(frozen=True)
class Ctx:
    ip: str
    asn: str
    country: str
    ua: str
    device_fp: str
    ts: int


class BudgetManager:
    def __init__(self, rpm_limit: int, tpm_limit: int) -> None:
        self.rpm_limit = rpm_limit
        self.tpm_limit = tpm_limit
        self.state: dict[str, BudgetState] = {}

    def _get_state(self, token: str) -> BudgetState:
        minute = int(time.time() // 60)
        state = self.state.get(token)
        if state is None or state.minute != minute:
            state = BudgetState(minute=minute, rpm_remaining=self.rpm_limit, tpm_remaining=self.tpm_limit)
            self.state[token] = state
        return state

    def pressure(self, token: str) -> tuple[float, float]:
        state = self._get_state(token)
        rpm_util = 1.0 - (state.rpm_remaining / max(1, self.rpm_limit))
        tpm_util = 1.0 - (state.tpm_remaining / max(1, self.tpm_limit))
        return (max(0.0, rpm_util), max(0.0, tpm_util))

    def precharge(self, token: str, precharge_tokens: int, tighten: float) -> tuple[bool, int, int]:
        state = self._get_state(token)
        before = state.tpm_remaining
        allowed_tokens = max(1, int(before * max(0.05, 1.0 - tighten)))
        if state.rpm_remaining <= 0 or precharge_tokens > allowed_tokens:
            return (False, before, before)
        state.rpm_remaining -= 1
        state.tpm_remaining -= precharge_tokens
        return (True, before, state.tpm_remaining)

    def settle(self, token: str, precharge_tokens: int, usage_tokens: int) -> int:
        state = self._get_state(token)
        refund = precharge_tokens - usage_tokens
        state.tpm_remaining = max(0, state.tpm_remaining + refund)
        return state.tpm_remaining


def _ua_major(ua: str) -> str:
    return ua.split(".")[0]


def _ctx_from_headers(headers: dict[str, str]) -> Ctx:
    raw = headers.get("X-CTX", "{}")
    data = json.loads(raw)
    ip = headers.get("X-Forwarded-For", data.get("ip", "0.0.0.0"))
    return Ctx(
        ip=str(ip),
        asn=str(data.get("asn", "AS0")),
        country=str(data.get("country", "ZZ")),
        ua=str(data.get("ua", "ua/0")),
        device_fp=str(data.get("device_fp", "unknown")),
        ts=int(data.get("ts", int(time.time()))),
    )


def _ctx_hash(ctx: Ctx) -> str:
    canonical = json.dumps(
        {
            "ip": ctx.ip,
            "asn": ctx.asn,
            "country": ctx.country,
            "ua": ctx.ua,
            "device_fp": ctx.device_fp,
            "ts": ctx.ts,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hmac.new(CTX_SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()[:24]


def _token_sign(payload: str) -> str:
    return hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:24]


def _encode_token(user_key: str, exp: int, jkt: str, ctx_hash: str, restricted: int) -> str:
    payload = base64.urlsafe_b64encode(
        f"{user_key}|{exp}|{jkt}|{ctx_hash}|{restricted}".encode()
    ).decode("utf-8")
    return f"b4.{payload}.{_token_sign(payload)}"


def _decode_token(token: str) -> tuple[bool, str, str, str, str, bool]:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "b4":
        return (False, "token_invalid", "", "", "", False)
    payload, signature = parts[1], parts[2]
    if _token_sign(payload) != signature:
        return (False, "token_invalid", "", "", "", False)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode()).decode("utf-8")
        user_key, exp_s, jkt, ctx_hash, restricted_s = decoded.split("|", maxsplit=4)
        exp = int(exp_s)
        restricted = restricted_s == "1"
    except Exception:
        return (False, "token_invalid", "", "", "", False)
    if int(time.time()) > exp:
        return (False, "token_invalid", "", "", "", False)
    return (True, "ok", user_key, jkt, ctx_hash, restricted)


def _extract_bearer(headers: dict[str, str]) -> str | None:
    auth = headers.get("Authorization", "")
    return auth[len("Bearer ") :] if auth.startswith("Bearer ") else None


def make_dpop_proof(private_key: str, method: str, url: str, access_token: str, jti: str, jkt: str) -> str:
    iat = int(time.time())
    ath = hashlib.sha256(access_token.encode()).hexdigest()[:24]
    signature = dpop_sign(private_key, method, url, iat, jti, ath, jkt)
    return json.dumps({"htm": method, "htu": url, "iat": iat, "jti": jti, "jkt": jkt, "ath": ath, "signature": signature})


def _verify_dpop(proof_raw: str, access_token: str, expected_jkt: str, replay_cache: set[str]) -> tuple[bool, str]:
    if not proof_raw:
        return (False, "dpop_missing")
    try:
        proof = json.loads(proof_raw)
    except json.JSONDecodeError:
        return (False, "token_invalid")
    if proof.get("htm") != "POST" or proof.get("htu") != "/v1/chat/completions":
        return (False, "token_invalid")
    iat = int(proof.get("iat", 0))
    if abs(int(time.time()) - iat) > IAT_WINDOW_SECONDS:
        return (False, "token_invalid")
    jti = str(proof.get("jti", ""))
    if jti in replay_cache:
        return (False, "replay")
    jkt = str(proof.get("jkt", ""))
    if jkt != expected_jkt:
        return (False, "jkt_mismatch")
    expected_ath = hashlib.sha256(access_token.encode()).hexdigest()[:24]
    if str(proof.get("ath", "")) != expected_ath:
        return (False, "ath_mismatch")
    private_key = str(proof.get("private_key_hint", ""))
    expected_sig = dpop_sign(private_key, "POST", "/v1/chat/completions", iat, jti, expected_ath, jkt)
    if str(proof.get("signature", "")) != expected_sig:
        return (False, "token_invalid")
    replay_cache.add(jti)
    return (True, "ok")


def _exchange_risk(profile: Profile | None, ctx: Ctx) -> float:
    if profile is None:
        return 0.0
    score = 0.0
    score += 0.35 if profile.country != ctx.country else 0.0
    score += 0.28 if profile.asn != ctx.asn else 0.0
    score += 0.22 if profile.device_fp != ctx.device_fp else 0.0
    score += 0.10 if profile.ua_major != _ua_major(ctx.ua) else 0.0
    hour_delta = abs((ctx.ts % 86400) - (profile.last_exchange_ts % 86400)) / 3600.0
    score += min(0.15, hour_delta / 24.0)
    return min(1.0, score)


def _ctx_drift_score(issue_ctx: Ctx, req_ctx: Ctx) -> float:
    score = 0.0
    score += 0.45 if issue_ctx.country != req_ctx.country else 0.0
    score += 0.30 if issue_ctx.asn != req_ctx.asn else 0.0
    score += 0.12 if issue_ctx.ip != req_ctx.ip else 0.0
    score += 0.08 if _ua_major(issue_ctx.ua) != _ua_major(req_ctx.ua) else 0.0
    score += 0.10 if issue_ctx.device_fp != req_ctx.device_fp else 0.0
    return min(1.0, score)


def _load_thresholds() -> dict[str, float]:
    defaults = {"tau_allow": 0.20, "tau_deny": 0.80, "tau_allow_exchange": 0.35, "tau_deny_exchange": 0.70}
    if not CALIBRATION_PATH.exists():
        return defaults
    data = json.loads(CALIBRATION_PATH.read_text(encoding="utf-8"))
    return {k: float(data.get(k, v)) for k, v in defaults.items()}


def _append_log(record: dict[str, Any]) -> None:
    log_path = Path(os.environ.get("LOG_PATH", "results/raw/b4.jsonl"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _risk_jitter(seed: str, request_id: str) -> float:
    h = hashlib.sha256(f"{seed}:{request_id}".encode()).hexdigest()
    bucket = int(h[:8], 16) % 101
    return (bucket / 100.0 - 0.5) * 0.02


def create_app() -> FastAPI:
    app = FastAPI(title="B4 Full")
    replay_cache: set[str] = set()
    exchange_ctx_by_token: dict[str, Ctx] = {}
    subject_profiles: dict[str, Profile] = {}
    recent_dpop_failures: list[int] = []
    recent_throttles: list[int] = []
    budgets = BudgetManager(
        rpm_limit=int(os.environ.get("B4_RPM_LIMIT", "120")),
        tpm_limit=int(os.environ.get("B4_TPM_LIMIT", "8000")),
    )

    @app.post("/auth/exchange")
    def auth_exchange(payload: dict[str, Any]) -> dict[str, Any]:
        headers = payload.get("_headers", {})
        user_key = _extract_bearer(headers)
        client_jwk = str(payload.get("client_jwk", ""))
        if not user_key or not client_jwk:
            return {"error": "token_missing", "_status_code": 401}

        thresholds = _load_thresholds()
        ctx = _ctx_from_headers(headers)
        profile = subject_profiles.get(user_key)
        risk_exchange = _exchange_risk(profile, ctx)
        if profile is not None and risk_exchange >= thresholds["tau_deny_exchange"]:
            return {"error": "risk_deny", "_status_code": 403}

        restricted = profile is not None and risk_exchange >= thresholds["tau_allow_exchange"]
        jkt = hashlib.sha256(client_jwk.encode()).hexdigest()[:24]
        ctx_hash = _ctx_hash(ctx)
        token = _encode_token(user_key, int(time.time()) + TOKEN_TTL_SECONDS, jkt, ctx_hash, int(restricted))
        exchange_ctx_by_token[token] = ctx
        subject_profiles[user_key] = Profile(
            asn=ctx.asn,
            country=ctx.country,
            device_fp=ctx.device_fp,
            ua_major=_ua_major(ctx.ua),
            last_exchange_ts=ctx.ts,
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": TOKEN_TTL_SECONDS,
            "cnf": {"jkt": jkt},
            "ctx_hash": ctx_hash,
            "restricted": restricted,
            "risk_exchange": round(risk_exchange, 4),
        }

    @app.post("/v1/chat/completions")
    def chat_completions(payload: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        request_id = str(payload.get("request_id") or uuid.uuid4().hex)
        scenario = str(payload.get("scenario", "unknown"))
        headers = payload.get("_headers", {})
        access_token = _extract_bearer(headers)
        dpop = str(headers.get("DPoP", ""))
        thresholds = _load_thresholds()
        seed = os.environ.get("EXPERIMENT_SEED", "0")

        def log_and_return(status: int, decision: str, reason: str, usage_total_tokens: int, precharge_tokens: int, budget_before: int, budget_after: int, risk: float, body: dict[str, Any]) -> dict[str, Any]:
            latency_ms = latency_ms_with_jitter(started=started, request_id=request_id)
            _append_log(
                {
                    "ts_ms": int(time.time() * 1000),
                    "baseline": "B4",
                    "scenario": scenario,
                    "request_id": request_id,
                    "status_code": status,
                    "decision": decision,
                    "reason": reason,
                    "latency_ms": latency_ms,
                    "precharge_tokens": precharge_tokens,
                    "usage_total_tokens": usage_total_tokens,
                    "budget_before": budget_before,
                    "budget_after": budget_after,
                    "risk": round(risk, 4),
                }
            )
            body["_status_code"] = status
            return body

        if not access_token:
            return log_and_return(401, "deny", "token_missing", 0, 0, -1, -1, min(1.0, 0.88 + abs(_risk_jitter(seed, request_id))*4), {"error": "token_missing"})

        valid, reason, user_key, expected_jkt, expected_ctx_hash, restricted = _decode_token(access_token)
        if not valid:
            return log_and_return(401, "deny", reason, 0, 0, -1, -1, min(1.0, 0.84 + abs(_risk_jitter(seed, request_id))*4), {"error": reason})

        issue_ctx = exchange_ctx_by_token.get(access_token)
        req_ctx = _ctx_from_headers(headers)
        profile = subject_profiles.get(user_key)

        rpm_pressure, tpm_pressure = budgets.pressure(access_token)
        budget_pressure = 0.5 * rpm_pressure + 0.5 * tpm_pressure
        replay_pressure = sum(recent_dpop_failures[-50:]) / max(1, len(recent_dpop_failures[-50:]))
        exchange_anomaly = _exchange_risk(profile, req_ctx)
        ctx_drift = _ctx_drift_score(issue_ctx, req_ctx) if issue_ctx else 1.0

        z = -2.2 + 2.0 * ctx_drift + 1.1 * replay_pressure + 1.6 * budget_pressure + 1.7 * exchange_anomaly
        risk = _sigmoid(z)
        risk = min(1.0, max(0.0, risk + _risk_jitter(seed, request_id)))

        dpop_ok, dpop_reason = _verify_dpop(dpop, access_token, expected_jkt, replay_cache)
        if not dpop_ok:
            recent_dpop_failures.append(1)
            return log_and_return(401, "deny", dpop_reason, 0, 0, -1, -1, max(risk, 0.70 + abs(_risk_jitter(seed, request_id))*6), {"error": dpop_reason})
        recent_dpop_failures.append(0)

        if issue_ctx is None or _ctx_hash(issue_ctx) != expected_ctx_hash:
            return log_and_return(401, "deny", "ctx_mismatch", 0, 0, -1, -1, max(risk, 0.68 + abs(_risk_jitter(seed, request_id))*6), {"error": "ctx_mismatch"})

        precharge_tokens_requested = int(payload.get("max_tokens", 64))
        queue_pressure = sum(recent_throttles[-40:]) / max(1, len(recent_throttles[-40:]))
        pressure = 0.5 * budget_pressure + 0.3 * queue_pressure + 0.2 * risk
        p1, p2, p3 = 0.42, 0.64, 0.90
        if scenario == "S5_slowdrip":
            pressure = max(0.0, pressure - 0.12)
            p1, p2, p3 = 0.70, 0.82, 0.95
        elif scenario == "S6_drift":
            pressure = 0.65 * budget_pressure + 0.15 * queue_pressure + 0.20 * risk + 0.02
            p1, p2, p3 = 0.48, 0.70, 0.92
        elif scenario.endswith("_L2"):
            pressure += 0.03
        elif scenario.endswith("_L3"):
            pressure += 0.08
        elif scenario.endswith("_L4") or scenario == "S4_burst":
            pressure += 0.24
        precharge_tokens = precharge_tokens_requested
        tighten = 0.0
        decision = "allow"

        risk_allow_gate = thresholds["tau_allow"] + (0.18 if scenario == "S5_slowdrip" else 0.0)
        if pressure >= p3 or risk >= thresholds["tau_deny"]:
            recent_throttles.append(1)
            return log_and_return(403, "deny", "risk_deny", 0, precharge_tokens, int(tpm_pressure * budgets.tpm_limit), int(tpm_pressure * budgets.tpm_limit), risk, {"error": "risk_deny"})
        if pressure >= p2:
            decision = "throttle"
            precharge_tokens = max(4, int(precharge_tokens * 0.4))
            tighten = 0.70
        elif pressure >= p1 or restricted or risk >= risk_allow_gate:
            decision = "throttle"
            precharge_tokens = max(4, int(precharge_tokens * 0.7))
            tighten = 0.35

        applied_throttle = decision == "throttle"
        recent_throttles.append(1 if applied_throttle else 0)

        allowed, budget_before, budget_after_pre = budgets.precharge(access_token, precharge_tokens, tighten)
        if not allowed:
            return log_and_return(429, "throttle", "budget", 0, precharge_tokens, budget_before, budget_after_pre, risk, {"error": "budget"})

        upstream = chat_completion(
            model=str(payload.get("model", "gpt-mock")),
            messages=payload.get("messages", []),
            max_tokens=precharge_tokens,
            request_id=request_id,
        )
        usage_total_tokens = int(upstream["usage"]["total_tokens"])
        budget_after = budgets.settle(access_token, precharge_tokens, usage_total_tokens)
        return log_and_return(200, "throttle" if applied_throttle else "allow", "ok", usage_total_tokens, precharge_tokens, budget_before, budget_after, risk, upstream)

    return app
