import base64
import os
import re
from typing import List, Dict, Optional

import httpx

from app.scanner.rules.base import BaseRule, bounded_gather

# Matches an OpenAPI-style `{param}` or Postman-style `{{param}}` / `:param`
# path template segment — the position we substitute our probe values into.
TEMPLATE_SEGMENT_RE = re.compile(r"^\{\{?[^{}]+\}?\}$|^:[A-Za-z0-9_]+$")

# Response text that indicates *which stage* of decoding/decryption failed.
# Three distinct stages firing on three progressively-more-valid probes is
# the signature of a CBC/ECB padding oracle (Vaudenay-style attack surface):
# an attacker can use the oracle to decrypt or forge the value without the key.
ENCODING_STAGE_MARKERS = ["illegal base64", "invalid base64", "invalid character", "base64"]
LENGTH_STAGE_MARKERS = ["multiple of", "block size", "input length", "wrong final block length"]
# Kept specific to an actual padding failure — generic words like "cipher" or
# "decrypt" also show up in the length-stage message above and would collide.
PADDING_STAGE_MARKERS = ["not properly padded", "padding is invalid", "bad padding", "mac check failed", "bad key"]


def _classify(body: str) -> Optional[str]:
    text = (body or "").lower()
    # Order matters: check the most specific phrasing first so a message
    # that happens to contain an overlapping generic word (e.g. "cipher")
    # still lands in the right stage.
    if any(m in text for m in LENGTH_STAGE_MARKERS):
        return "length"
    if any(m in text for m in PADDING_STAGE_MARKERS):
        return "padding"
    if any(m in text for m in ENCODING_STAGE_MARKERS):
        return "encoding"
    return None


def _urlsafe_b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class CryptoOracleRule(BaseRule):
    id = "CRYPTO-ORACLE"
    name = "Cryptographic Error Oracle"
    description = (
        "Checks whether an endpoint that accepts an encoded/encrypted path or "
        "query value leaks distinct, stage-specific error messages for "
        "malformed-encoding vs. wrong-length vs. bad-padding inputs — the "
        "signature of a padding-oracle attack surface."
    )
    severity = "critical"

    impact = (
        "An unauthenticated attacker can use the distinguishable error responses as "
        "an oracle to decrypt the ciphertext byte-by-byte (Vaudenay-style padding "
        "oracle attack) or forge new valid encrypted values without knowing the key, "
        "potentially exposing or redirecting to data belonging to other tenants/records."
    )
    remediation = (
        "Return a single generic error (same status code and body) for every "
        "decryption failure, regardless of which stage failed. Use an "
        "authenticated encryption mode (AES-GCM) instead of a padded CBC/ECB "
        "cipher so padding and integrity are checked together and failures are "
        "indistinguishable."
    )
    cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
    attack_vector = "Network"
    attack_complexity = "High"
    privileges_required = "None"
    user_interaction = "None"
    scope = "Unchanged"
    confidentiality = "High"
    integrity = "High"
    availability = "None"

    def _candidate_positions(self, path: str):
        """Yield (index, segment) for every templated path segment."""
        segments = path.split("/")
        for i, seg in enumerate(segments):
            if TEMPLATE_SEGMENT_RE.match(seg):
                yield i, segments

    async def _probe(self, client: httpx.AsyncClient, target_url: str, segments: List[str], idx: int, value: str):
        segs = list(segments)
        segs[idx] = value
        url = f"{target_url.rstrip('/')}{'/'.join(segs)}"
        try:
            resp = await client.get(url)
            return resp.status_code, resp.text
        except Exception:
            return None, ""

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []

        candidates = []
        for ep in endpoints:
            if ep.get("method", "GET").upper() != "GET":
                continue
            for idx, segments in self._candidate_positions(ep["path"]):
                candidates.append((ep, idx, segments))

        if not candidates:
            return findings

        probes = {
            "encoding": "!!!not-valid-base64!!!",
            # 5 raw bytes -> not a multiple of the common 16-byte AES block size
            "length": _urlsafe_b64(os.urandom(5)),
            # 16 raw bytes -> block-aligned, but padding/content is garbage
            "padding": _urlsafe_b64(os.urandom(16)),
        }

        async def check_one(client, ep, idx, segments):
            results = {}
            for stage, value in probes.items():
                status, body = await self._probe(client, target_url, segments, idx, value)
                results[stage] = (status, body)
            return ep, results

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            tasks = [check_one(client, ep, idx, segments) for ep, idx, segments in candidates]
            all_results = await bounded_gather(tasks, limit=10)

            for r in all_results:
                if not r or isinstance(r, Exception):
                    continue
                ep, results = r

                classified = {stage: _classify(body) for stage, (status, body) in results.items()}
                distinct_stages = {v for v in classified.values() if v}

                signals = []
                if classified.get("encoding") == "encoding":
                    signals.append("encoding_stage_disclosed")
                if classified.get("length") == "length":
                    signals.append("length_stage_disclosed")
                if classified.get("padding") == "padding":
                    signals.append("padding_stage_disclosed")

                # The oracle condition: at least two distinct failure stages are
                # each identifiable from the response text, so an attacker can
                # tell which stage rejected their guess.
                if len(distinct_stages) < 2:
                    continue

                proof_lines = []
                for stage, (status, body) in results.items():
                    snippet = (body or "")[:200].replace("\n", " ")
                    proof_lines.append(f"[{stage}] probe -> HTTP {status}: {snippet}")

                findings.append(self.build_finding(
                    description=(
                        f"Endpoint {ep['method']} {ep['path']} discloses distinct, "
                        f"decryption-stage-specific error messages for malformed "
                        f"encoded/encrypted input, indicating a padding-oracle attack surface."
                    ),
                    details={
                        "owasp": "API8: Security Misconfiguration",
                        "distinct_stages_disclosed": sorted(distinct_stages),
                        "responses": {stage: {"status": s, "body": b[:500]} for stage, (s, b) in results.items()},
                    },
                    endpoint=ep["path"],
                    method="GET",
                    proof_of_concept="\n".join(proof_lines),
                    signals=signals,
                ))

        return findings
