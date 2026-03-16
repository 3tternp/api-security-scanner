from typing import List, Dict
import base64
import json
import hmac
import hashlib
import httpx
from app.scanner.rules.base import BaseRule


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _build_none_alg_jwt(payload: dict) -> str:
    """Build a JWT signed with alg:none (empty signature)."""
    header = {"alg": "none", "typ": "JWT"}
    header_enc = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_enc}.{payload_enc}."


def _build_hs256_jwt(payload: dict, secret: str) -> str:
    """Build a JWT signed with HS256 using a known weak secret."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_enc = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_enc}.{payload_enc}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_enc}.{payload_enc}.{_b64url_encode(sig)}"


def _build_expired_jwt(payload: dict) -> str:
    """Build a JWT that is already expired (exp in the past), alg:none for simplicity."""
    expired_payload = dict(payload)
    expired_payload["exp"] = 1  # epoch second 1 — far in the past
    return _build_none_alg_jwt(expired_payload)


ADMIN_PAYLOAD = {
    "sub": "admin",
    "role": "admin",
    "is_admin": True,
    "exp": 9999999999,
}

WEAK_SECRETS = ["secret", "password", "123456", "changeme", "jwt_secret"]

AUTH_PATH_KEYWORDS = ["/login", "/auth", "/token", "/signin", "/oauth"]


class JWTSecurityRule(BaseRule):
    id = "JWT-001"
    name = "JWT Security Misconfiguration"
    severity = "critical"
    impact = (
        "An attacker can forge arbitrary JWT tokens, bypass authentication entirely, "
        "and gain elevated privileges including admin access."
    )
    remediation = (
        "Reject tokens with alg:none. Use strong, randomly generated secrets (>=256 bits). "
        "Enforce token expiration strictly. Validate the 'alg' field against a server-side allowlist."
    )
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    attack_vector = "Network"
    attack_complexity = "Low"
    privileges_required = "None"
    user_interaction = "None"
    scope = "Unchanged"
    confidentiality = "High"
    integrity = "High"
    availability = "None"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []

        # Identify auth-looking endpoints; fall back to all endpoints
        auth_endpoints = [
            ep for ep in endpoints
            if any(kw in ep.get("path", "").lower() for kw in AUTH_PATH_KEYWORDS)
        ]
        if not auth_endpoints:
            auth_endpoints = endpoints

        none_jwt = _build_none_alg_jwt(ADMIN_PAYLOAD)
        expired_jwt = _build_expired_jwt(ADMIN_PAYLOAD)
        weak_jwts = {secret: _build_hs256_jwt(ADMIN_PAYLOAD, secret) for secret in WEAK_SECRETS}

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for ep in auth_endpoints:
                path = ep.get("path", "/")
                method = ep.get("method", "GET").upper()
                url = f"{target_url.rstrip('/')}{path}"

                # --- Test 1: alg:none ---
                try:
                    resp = await client.request(
                        method,
                        url,
                        headers={"Authorization": f"Bearer {none_jwt}"},
                        json={} if method in ("POST", "PUT", "PATCH") else None,
                    )
                    if resp.status_code in (200, 201):
                        findings.append(self.build_finding(
                            description="JWT with alg:none accepted by the server.",
                            details=(
                                f"The endpoint accepted a JWT token with the 'none' algorithm, "
                                f"meaning no signature validation is performed. "
                                f"An attacker can forge any token payload. "
                                f"URL: {url}, Method: {method}, HTTP status: {resp.status_code}"
                            ),
                            endpoint=path,
                            method=method,
                            proof_of_concept=(
                                f"Authorization: Bearer {none_jwt}\n"
                                f"Response: HTTP {resp.status_code}"
                            ),
                        ))
                except Exception:
                    pass

                # --- Test 2: weak secrets ---
                for secret, weak_jwt in weak_jwts.items():
                    try:
                        resp = await client.request(
                            method,
                            url,
                            headers={"Authorization": f"Bearer {weak_jwt}"},
                            json={} if method in ("POST", "PUT", "PATCH") else None,
                        )
                        if resp.status_code in (200, 201):
                            findings.append(self.build_finding(
                                description=f"JWT signed with weak secret '{secret}' was accepted.",
                                details=(
                                    f"The endpoint accepted a JWT token signed with the commonly "
                                    f"known weak secret '{secret}'. This allows an attacker to forge "
                                    f"arbitrary tokens. "
                                    f"URL: {url}, Method: {method}, HTTP status: {resp.status_code}"
                                ),
                                endpoint=path,
                                method=method,
                                proof_of_concept=(
                                    f"HS256 JWT signed with secret='{secret}'\n"
                                    f"Authorization: Bearer {weak_jwt}\n"
                                    f"Response: HTTP {resp.status_code}"
                                ),
                            ))
                            break  # one finding per endpoint for weak secrets
                    except Exception:
                        pass

                # --- Test 3: expired token ---
                try:
                    resp = await client.request(
                        method,
                        url,
                        headers={"Authorization": f"Bearer {expired_jwt}"},
                        json={} if method in ("POST", "PUT", "PATCH") else None,
                    )
                    if resp.status_code in (200, 201):
                        findings.append(self.build_finding(
                            description="Expired JWT token accepted by the server.",
                            details=(
                                f"The endpoint accepted a JWT with an expiration time (exp) set to "
                                f"epoch second 1 (far in the past). The server is not validating "
                                f"token expiration. "
                                f"URL: {url}, Method: {method}, HTTP status: {resp.status_code}"
                            ),
                            endpoint=path,
                            method=method,
                            proof_of_concept=(
                                f"JWT with exp=1 (expired):\n"
                                f"Authorization: Bearer {expired_jwt}\n"
                                f"Response: HTTP {resp.status_code}"
                            ),
                        ))
                except Exception:
                    pass

        return findings
