"""B4 full baseline: PoP + context tolerance + calibrated risk + adaptive budgets."""

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


class BudgetManager:
    def __init__(self, rpm_limit: int, tpm_limit: int) -> None:
        self.rpm_limit = rpm_limit
        self.tpm_limit = tpm_limit
        self.state: dict[str, BudgetState] = {}

    def _get_state(self, token: str) -> BudgetState:
        minute = int(time.time() // 60)
        state = self.state.get(token)
        if state is None or state.minute != minute:
            state = BudgetState(
                minute=minute,
                rpm_remaining=self.rpm_limit,
                tpm_remaining=self.tpm_limit,
            )
            self.state[token] = state
        return state

    def precharge(
        self,
        token: str,
        precharge_tokens: int,
        risk: float,
    ) -> tuple[bool, int, int]:
        state = self._get_state(token)
        before = state.tpm_remaining
        shrink = math.exp(-6.0 * risk)
        allowed_tokens = max(1, int(before * shrink))
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


@dataclass(frozen=True)
class Ctx:
    ip: str
    asn: str
    country: str
    ua: str
    device_fp: str
    ts: int


def _ctx_from_headers(headers: dict[str, str]) -> Ctx:
    raw = headers.get("X-CTX", "{}")
    data = json.loads(raw)
    # server uses deterministic forwarded IP
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


def _encode_token(user_key: str, exp: int, jkt: str, ctx_hash: str) -> str:
    payload = base64.urlsafe_b64encode(f"{user_key}|{exp}|{jkt}|{ctx_hash}".encode()).decode(
        "utf-8"
    )
    return f"b4.{payload}.{_token_sign(payload)}"


def _decode_token(token: str) -> tuple[bool, str, str, str]:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "b4":
        return (False, "token_invalid", "", "")
    payload, signature = parts[1], parts[2]
    if _token_sign(payload) != signature:
        return (False, "token_invalid", "", "")
    try:
        decoded = base64.urlsafe_b64decode(payload.encode()).decode("utf-8")
        _, exp_s, jkt, ctx_hash = decoded.split("|", maxsplit=3)
        exp = int(exp_s)
    except Exception:
        return (False, "token_invalid", "", "")
    if int(time.time()) > exp:
        return (False, "token_invalid", "", "")
    return (True, "ok", jkt, ctx_hash)


def _extract_bearer(headers: dict[str, str]) -> str | None:
    auth = headers.get("Authorization", "")
    return auth[len("Bearer ") :] if auth.startswith("Bearer ") else None


def make_dpop_proof(
    private_key: str,
    method: str,
    url: str,
    access_token: str,
    jti: str,
    jkt: str,
) -> str:
    iat = int(time.time())
    ath = hashlib.sha256(access_token.encode()).hexdigest()[:24]
    signature = dpop_sign(private_key, method, url, iat, jti, ath, jkt)
    return json.dumps(
        {
            "htm": method,
            "htu": url,
            "iat": iat,
            "jti": jti,
            "jkt": jkt,
            "ath": ath,
            "signature": signature,
        }
    )


def _verify_dpop(
    proof_raw: str,
    access_token: str,
    expected_jkt: str,
    replay_cache: set[str],
) -> tuple[bool, str]:
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
    expected_sig = dpop_sign(
        private_key, "POST", "/v1/chat/completions", iat, jti, expected_ath, jkt
    )
    if str(proof.get("signature", "")) != expected_sig:
        return (False, "token_invalid")
    replay_cache.add(jti)
    return (True, "ok")


def _ua_major(ua: str) -> str:
    return ua.split(".")[0]


def _ctx_tolerance(exchange_ctx: Ctx, req_ctx: Ctx) -> tuple[bool, float, str | None]:
    if exchange_ctx.country != req_ctx.country:
        return (False, 1.0, "ctx_mismatch")

    risk = 0.0
    if exchange_ctx.asn != req_ctx.asn:
        risk += 0.45
    if exchange_ctx.ip != req_ctx.ip and exchange_ctx.asn == req_ctx.asn:
        risk += 0.30
    if _ua_major(exchange_ctx.ua) != _ua_major(req_ctx.ua):
        risk += 0.20
    if exchange_ctx.device_fp != req_ctx.device_fp:
        risk += 0.35
    return (True, min(1.0, risk), None)


def _load_thresholds() -> tuple[float, float]:
    if not CALIBRATION_PATH.exists():
        return (0.25, 0.70)
    data = json.loads(CALIBRATION_PATH.read_text(encoding="utf-8"))
    return (float(data.get("tau_allow", 0.25)), float(data.get("tau_deny", 0.70)))


def _append_log(record: dict[str, Any]) -> None:
    log_path = Path(os.environ.get("LOG_PATH", "results/raw/b4.jsonl"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def create_app() -> FastAPI:
    app = FastAPI(title="B4 Full")
    replay_cache: set[str] = set()
    exchange_ctx_by_token: dict[str, Ctx] = {}
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
        jkt = hashlib.sha256(client_jwk.encode()).hexdigest()[:24]
        ctx = _ctx_from_headers(headers)
        ctx_hash = _ctx_hash(ctx)
        token = _encode_token(user_key, int(time.time()) + TOKEN_TTL_SECONDS, jkt, ctx_hash)
        exchange_ctx_by_token[token] = ctx
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": TOKEN_TTL_SECONDS,
            "cnf": {"jkt": jkt},
            "ctx_hash": ctx_hash,
        }

    @app.post("/v1/chat/completions")
    def chat_completions(payload: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        request_id = str(payload.get("request_id") or uuid.uuid4().hex)
        scenario = str(payload.get("scenario", "unknown"))
        headers = payload.get("_headers", {})
        access_token = _extract_bearer(headers)
        dpop = str(headers.get("DPoP", ""))
        tau_allow, tau_deny = _load_thresholds()

        def log_and_return(
            status: int,
            decision: str,
            reason: str,
            usage_total_tokens: int,
            precharge_tokens: int,
            budget_before: int,
            budget_after: int,
            risk: float,
            body: dict[str, Any],
        ) -> dict[str, Any]:
            latency_ms = int((time.perf_counter() - started) * 1000) + 1
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
            return log_and_return(
                401, "deny", "token_missing", 0, 0, -1, -1, 1.0, {"error": "token_missing"}
            )

        valid, reason, expected_jkt, expected_ctx_hash = _decode_token(access_token)
        if not valid:
            return log_and_return(401, "deny", reason, 0, 0, -1, -1, 1.0, {"error": reason})

        dpop_ok, dpop_reason = _verify_dpop(dpop, access_token, expected_jkt, replay_cache)
        if not dpop_ok:
            return log_and_return(
                401, "deny", dpop_reason, 0, 0, -1, -1, 1.0, {"error": dpop_reason}
            )

        exchange_ctx = exchange_ctx_by_token.get(access_token)
        req_ctx = _ctx_from_headers(headers)
        if exchange_ctx is None or _ctx_hash(exchange_ctx) != expected_ctx_hash:
            return log_and_return(
                401, "deny", "ctx_mismatch", 0, 0, -1, -1, 1.0, {"error": "ctx_mismatch"}
            )

        tolerated, base_risk, mismatch_reason = _ctx_tolerance(exchange_ctx, req_ctx)
        if not tolerated:
            return log_and_return(
                401,
                "deny",
                mismatch_reason or "ctx_mismatch",
                0,
                0,
                -1,
                -1,
                1.0,
                {"error": "ctx_mismatch"},
            )

        precharge_tokens = int(payload.get("max_tokens", 64))
        pressure_probe_before = budgets._get_state(access_token).tpm_remaining
        pressure = 1.0 - (pressure_probe_before / max(1, budgets.tpm_limit))
        risk = min(1.0, base_risk + 0.20 * pressure)

        deny_threshold = max(tau_deny, 0.90)
        if risk >= deny_threshold:
            return log_and_return(
                403,
                "deny",
                "risk_deny",
                0,
                precharge_tokens,
                pressure_probe_before,
                pressure_probe_before,
                risk,
                {"error": "risk_deny"},
            )

        if risk >= tau_allow:
            precharge_tokens = max(1, int(precharge_tokens * math.exp(-5.0 * risk)))
            decision = "throttle"
        else:
            decision = "allow"

        allowed, budget_before, budget_after_pre = budgets.precharge(
            access_token, precharge_tokens, risk
        )
        if not allowed:
            return log_and_return(
                429,
                "throttle",
                "budget",
                0,
                precharge_tokens,
                budget_before,
                budget_after_pre,
                risk,
                {"error": "budget"},
            )

        upstream = chat_completion(
            model=str(payload.get("model", "gpt-mock")),
            messages=payload.get("messages", []),
            max_tokens=precharge_tokens,
            request_id=request_id,
        )
        usage_total_tokens = int(upstream["usage"]["total_tokens"])
        budget_after = budgets.settle(access_token, precharge_tokens, usage_total_tokens)
        return log_and_return(
            200,
            decision,
            "ok",
            usage_total_tokens,
            precharge_tokens,
            budget_before,
            budget_after,
            risk,
            upstream,
        )

    return app
