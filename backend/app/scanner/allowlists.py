"""
Shared keyword/name lists used across scanner rules, kept in one place so
false-positive fixes (e.g. tightening a keyword match) only need to happen
once instead of being duplicated per rule.
"""
import re

# Paths that are conventionally public by design — rules that look for
# "missing auth" should not flag these on their own.
PUBLIC_PATH_KEYWORDS = [
    "/login", "/logout", "/register", "/signup", "/health", "/healthz",
    "/status", "/ping", "/version", "/docs", "/redoc", "/openapi",
    "/public", "/static", "/favicon", "/robots.txt", "/.well-known",
]

# Cloud-metadata response markers that indicate an SSRF payload actually
# reached an internal metadata endpoint (not just "got a 200 back").
SSRF_METADATA_MARKERS = [
    "ami-id", "instance-id", "instance-type", "local-ipv4", "local-hostname",
    "iam/security-credentials", "compute.internal", "metadata-flavor",
    "\"kind\": \"compute#", "project/project-id",
]

# PII field-name tokens: a field is treated as PII only if one of its
# underscore/camelCase-split tokens matches exactly (not a substring match),
# so "automobile_type" or "adobe_key" don't false-positive on "mobile"/"dob".
_PII_TOKENS = {
    "ssn", "dob", "passport", "mobile", "phone", "citizenship",
    "creditcard", "cardnumber", "cvv", "iban", "birthdate",
}

# Compound field names checked as a whole (after stripping non-alnum chars),
# for PII concepts that are naturally multi-word.
_PII_COMPOUND_NAMES = {
    "socialsecuritynumber", "socialsecurity", "idnumber", "dateofbirth",
    "creditcardnumber", "passportnumber", "phonenumber", "mobilenumber",
}

# Fields that would otherwise match a PII token but are not PII themselves.
_PII_TOKEN_EXCEPTIONS = {
    "phone_verified", "mobile_verified", "phone_type",
}

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _tokenize(field_name: str):
    spaced = _CAMEL_BOUNDARY.sub("_", field_name)
    return [t for t in re.split(r"[_\-\s]+", spaced.lower()) if t]


def is_pii_field(field_name: str) -> bool:
    """Whether a schema field name represents a PII concept, using whole-token
    matching rather than substring matching to avoid false positives like
    'automobile_type' (contains 'mobile') or 'adobe_key' (contains 'dob')."""
    if not field_name:
        return False
    if field_name.lower() in _PII_TOKEN_EXCEPTIONS:
        return False

    compact = re.sub(r"[^a-z0-9]", "", field_name.lower())
    if compact in _PII_COMPOUND_NAMES:
        return True

    return any(tok in _PII_TOKENS for tok in _tokenize(field_name))


def is_public_path(path: str) -> bool:
    lower = (path or "").lower()
    return any(kw in lower for kw in PUBLIC_PATH_KEYWORDS)
