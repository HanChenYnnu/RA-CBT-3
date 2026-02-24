"""B3 proof-of-possession baseline with DPoP, replay checks, and budgets."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from experiments.latency import latency_ms_with_jitter
from experiments.mock_upstream import chat_completion
from fastapi import FastAPI

SECRET = "b3-local-secret"
TOKEN_TTL_SECONDS = 120
IAT_WINDOW_SECONDS = 300


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

    def precharge(self, token: str, precharge_tokens: int) -> tuple[bool, int, int]:
        state = self._get_state(token)
        before = state.tpm_remaining
        if state.rpm_remaining <= 0 or state.tpm_remaining < precharge_tokens:
            return (False, before, before)
        state.rpm_remaining -= 1
        state.tpm_remaining -= precharge_tokens
        return (True, before, state.tpm_remaining)

    def settle(self, token: str, precharge_tokens: int, usage_tokens: int) -> int:
        state = self._get_state(token)
        refund = precharge_tokens - usage_tokens
        state.tpm_remaining = max(0, state.tpm_remaining + refund)
        return state.tpm_remaining


def jwk_thumbprint(jwk: str) -> str:
    return hashlib.sha256(jwk.encode()).hexdigest()[:24]


def dpop_sign(
    private_key: str,
    htm: str,
    htu: str,
    iat: int,
    jti: str,
    ath: str,
    jkt: str,
) -> str:
    payload = f"{htm}|{htu}|{iat}|{jti}|{ath}|{jkt}"
    return hmac.new(private_key.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]


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


def _append_log(record: dict[str, Any]) -> None:
    log_path = Path(os.environ.get("LOG_PATH", "results/raw/b3.jsonl"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def _token_sign(payload: str) -> str:
    return hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:24]


def _encode_token(user_key: str, exp: int, jkt: str) -> str:
    payload = base64.urlsafe_b64encode(f"{user_key}|{exp}|{jkt}".encode()).decode("utf-8")
    return f"b3.{payload}.{_token_sign(payload)}"


def _decode_token(token: str) -> tuple[bool, str, str]:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "b3":
        return (False, "token_invalid", "")
    payload, signature = parts[1], parts[2]
    if _token_sign(payload) != signature:
        return (False, "token_invalid", "")
    try:
        decoded = base64.urlsafe_b64decode(payload.encode()).decode("utf-8")
        _, exp_s, jkt = decoded.split("|", maxsplit=2)
        exp = int(exp_s)
    except Exception:
        return (False, "token_invalid", "")
    if int(time.time()) > exp:
        return (False, "token_invalid", "")
    return (True, "ok", jkt)


def _extract_bearer(headers: dict[str, str]) -> str | None:
    auth = headers.get("Authorization", "")
    return auth[len("Bearer ") :] if auth.startswith("Bearer ") else None


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
        private_key,
        "POST",
        "/v1/chat/completions",
        iat,
        jti,
        expected_ath,
        jkt,
    )
    if str(proof.get("signature", "")) != expected_sig:
        return (False, "token_invalid")

    replay_cache.add(jti)
    return (True, "ok")


def create_app() -> FastAPI:
    app = FastAPI(title="B3 PoP Only")
    replay_cache: set[str] = set()
    budgets = BudgetManager(
        rpm_limit=int(os.environ.get("B3_RPM_LIMIT", "120")),
        tpm_limit=int(os.environ.get("B3_TPM_LIMIT", "8000")),
    )

    @app.post("/auth/exchange")
    def auth_exchange(payload: dict[str, Any]) -> dict[str, Any]:
        headers = payload.get("_headers", {})
        user_key = _extract_bearer(headers)
        client_jwk = str(payload.get("client_jwk", ""))
        if not user_key or not client_jwk:
            return {"error": "token_missing", "_status_code": 401}
        jkt = jwk_thumbprint(client_jwk)
        token = _encode_token(user_key, int(time.time()) + TOKEN_TTL_SECONDS, jkt)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": TOKEN_TTL_SECONDS,
            "cnf": {"jkt": jkt},
        }

    @app.post("/v1/chat/completions")
    def chat_completions(payload: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        request_id = str(payload.get("request_id") or uuid.uuid4().hex)
        scenario = str(payload.get("scenario", "unknown"))
        headers = payload.get("_headers", {})
        access_token = _extract_bearer(headers)
        dpop = str(headers.get("DPoP", ""))

        def log_and_return(
            status: int,
            decision: str,
            reason: str,
            usage_total_tokens: int,
            precharge_tokens: int,
            budget_before: int,
            budget_after: int,
            body: dict[str, Any],
        ) -> dict[str, Any]:
            latency_ms = latency_ms_with_jitter(started=started, request_id=request_id)
            _append_log(
                {
                    "ts_ms": int(time.time() * 1000),
                    "baseline": "B3",
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
                    "risk": -1.0,
                }
            )
            body["_status_code"] = status
            return body

        if not access_token:
            return log_and_return(
                401,
                "deny",
                "token_missing",
                0,
                0,
                -1,
                -1,
                {"error": "token_missing"},
            )

        valid, reason, expected_jkt = _decode_token(access_token)
        if not valid:
            return log_and_return(401, "deny", reason, 0, 0, -1, -1, {"error": reason})

        dpop_ok, dpop_reason = _verify_dpop(dpop, access_token, expected_jkt, replay_cache)
        if not dpop_ok:
            return log_and_return(
                401,
                "deny",
                dpop_reason,
                0,
                0,
                -1,
                -1,
                {"error": dpop_reason},
            )

        precharge_tokens = int(payload.get("max_tokens", 64))
        allowed, budget_before, budget_after_pre = budgets.precharge(access_token, precharge_tokens)
        if not allowed:
            return log_and_return(
                429,
                "throttle",
                "budget",
                0,
                precharge_tokens,
                budget_before,
                budget_after_pre,
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
            "allow",
            "ok",
            usage_total_tokens,
            precharge_tokens,
            budget_before,
            budget_after,
            upstream,
        )

    return app
