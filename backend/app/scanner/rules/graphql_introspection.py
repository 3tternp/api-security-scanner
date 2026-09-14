import httpx
from typing import List, Dict
from app.scanner.rules.base import BaseRule

GRAPHQL_PATH_HINTS = ["graphql", "gql"]

INTROSPECTION_QUERY = {
    "query": "query IntrospectionCheck { __schema { queryType { name } types { name } } }"
}


class GraphQLIntrospectionRule(BaseRule):
    id = "GRAPHQL-INTROSPECTION"
    name = "GraphQL Introspection Enabled"
    description = "Checks whether a discovered GraphQL endpoint exposes its full schema via introspection."
    severity = "medium"

    impact = (
        "An exposed schema lets an attacker enumerate every type, field, query, and "
        "mutation the API supports — including ones never referenced by the client "
        "application — significantly speeding up reconnaissance for further attacks."
    )
    remediation = "Disable introspection in production deployments, or restrict it to authenticated internal callers."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    confidentiality = "Low"

    def _looks_like_graphql(self, path: str) -> bool:
        lower = (path or "").lower()
        return any(hint in lower for hint in GRAPHQL_PATH_HINTS)

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []

        candidate_paths = {ep["path"] for ep in endpoints if self._looks_like_graphql(ep.get("path", ""))}
        # Even when discovery/spec didn't surface it, /graphql is a common
        # enough default to be worth one direct, targeted probe.
        candidate_paths.add("/graphql")

        headers = {}
        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]

        async with httpx.AsyncClient(verify=False, timeout=8.0, headers=headers) as client:
            for path in candidate_paths:
                url = f"{target_url.rstrip('/')}{path}"

                try:
                    resp = await client.post(url, json=INTROSPECTION_QUERY)
                except Exception:
                    continue

                if resp.status_code != 200:
                    continue

                try:
                    body = resp.json()
                except Exception:
                    continue

                schema = body.get("data", {}).get("__schema") if isinstance(body, dict) else None
                types = schema.get("types") if isinstance(schema, dict) else None

                if not isinstance(types, list) or not types:
                    continue

                # Requiring a real, non-trivial schema (not a coincidental
                # small JSON shape that happens to nest data.__schema.types)
                # is what keeps this check from firing on a non-GraphQL API.
                signals = ["introspection_query_returned_schema"]
                if len(types) > 10:
                    signals.append("substantial_type_count")

                findings.append(self.build_finding(
                    description="GraphQL introspection is enabled, exposing the full API schema.",
                    details={
                        "url": url,
                        "type_count": len(types),
                        "sample_types": [t.get("name") for t in types[:10] if isinstance(t, dict)],
                        "owasp": "API9: Improper Inventory Management",
                    },
                    endpoint=path,
                    method="POST",
                    proof_of_concept=(
                        f"POST {url}\n"
                        f"Body: {INTROSPECTION_QUERY['query']}\n"
                        f"Response contained {len(types)} schema types."
                    ),
                    signals=signals,
                ))

        return findings
