"""Reference data for cryptographic algorithms (CBOM Table 9 / QBOM quantum risk).

classical: classical security strength in bits (NIST SP 800-57 Pt1 Rev5 Table 2);
nistq: NIST PQC security category (0 = broken by a cryptographically relevant quantum computer).
quantum: "vulnerable" (Shor), "weakened" (Grover; prefer larger keys), "resistant", "broken" (classically).
"""
from __future__ import annotations

import re

PQC_KEM = "ML-KEM-768 (FIPS 203), or hybrid X25519MLKEM768 for TLS"
PQC_SIG = "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"


def _a(primitive, classical, nistq, quantum, oid=None, mode=None, functions=(), param=None, rec=None, curve=None):
    return {"primitive": primitive, "classical": classical, "nistq": nistq, "quantum": quantum, "oid": oid,
            "mode": mode, "functions": list(functions), "param": param, "recommendation": rec, "curve": curve}


ENC = ("keygen", "encrypt", "decrypt")
AE = ("keygen", "encrypt", "decrypt", "tag")
SIG = ("keygen", "sign", "verify")

ALGORITHMS: dict[str, dict] = {
    # symmetric
    "AES-128-GCM": _a("ae", 128, 1, "weakened", "2.16.840.1.101.3.4.1.6", "gcm", AE, "128", "Prefer AES-256-GCM for long-lived data"),
    "AES-192-GCM": _a("ae", 192, 3, "resistant", "2.16.840.1.101.3.4.1.26", "gcm", AE, "192"),
    "AES-256-GCM": _a("ae", 256, 5, "resistant", "2.16.840.1.101.3.4.1.46", "gcm", AE, "256"),
    "AES-128-CBC": _a("block-cipher", 128, 1, "weakened", "2.16.840.1.101.3.4.1.2", "cbc", ENC, "128", "Use AES-256-GCM (authenticated)"),
    "AES-256-CBC": _a("block-cipher", 256, 5, "resistant", "2.16.840.1.101.3.4.1.42", "cbc", ENC, "256", "Prefer authenticated mode (GCM)"),
    "AES-ECB": _a("block-cipher", None, None, "broken", None, "ecb", ENC, None, "ECB leaks plaintext patterns; use AES-256-GCM"),
    "AES-GCM": _a("ae", None, None, "weakened", None, "gcm", AE, None, "Key size not visible; ensure 256-bit keys"),
    "AES-CBC": _a("block-cipher", None, None, "weakened", None, "cbc", ENC, None, "Use AES-256-GCM"),
    "AES": _a("block-cipher", None, None, "weakened", None, None, ENC, None, "Key size/mode not visible; ensure AES-256-GCM"),
    "ChaCha20-Poly1305": _a("ae", 256, 5, "resistant", "1.2.840.113549.1.9.16.3.18", None, AE, "256"),
    "3DES": _a("block-cipher", 112, 0, "broken", "1.2.840.113549.3.7", "cbc", ENC, "168", "Disallowed after 2023 (SP 800-131A); use AES-256-GCM"),
    "DES": _a("block-cipher", 56, 0, "broken", "1.3.14.3.2.7", "cbc", ENC, "56", "Broken; use AES-256-GCM"),
    "RC4": _a("stream-cipher", None, 0, "broken", "1.2.840.113549.3.4", None, ENC, None, "Broken (RFC 7465); use AES-256-GCM/ChaCha20-Poly1305"),
    # hashes / MACs / KDFs
    "MD5": _a("hash", 0, 0, "broken", "1.2.840.113549.2.5", None, ("digest",), "128", "Collision-broken; use SHA-256 or SHA-3"),
    "SHA-1": _a("hash", 0, 0, "broken", "1.3.14.3.2.26", None, ("digest",), "160", "Collision-broken (SHAttered); use SHA-256+"),
    "SHA-256": _a("hash", 128, 2, "resistant", "2.16.840.1.101.3.4.2.1", None, ("digest",), "256"),
    "SHA-384": _a("hash", 192, 4, "resistant", "2.16.840.1.101.3.4.2.2", None, ("digest",), "384"),
    "SHA-512": _a("hash", 256, 5, "resistant", "2.16.840.1.101.3.4.2.3", None, ("digest",), "512"),
    "SHA3-256": _a("hash", 128, 2, "resistant", "2.16.840.1.101.3.4.2.8", None, ("digest",), "256"),
    "SHA3-512": _a("hash", 256, 5, "resistant", "2.16.840.1.101.3.4.2.10", None, ("digest",), "512"),
    "HMAC-SHA256": _a("mac", 256, 5, "resistant", "1.2.840.113549.2.9", None, ("tag",), "256"),
    "HMAC-SHA1": _a("mac", 128, 1, "weakened", "1.2.840.113549.2.7", None, ("tag",), "160", "Migrate to HMAC-SHA256"),
    "PBKDF2": _a("kdf", None, None, "resistant", "1.2.840.113549.1.5.12", None, ("keyderive",), None, "Use >=600k iterations (OWASP) or Argon2id"),
    "Argon2": _a("kdf", None, None, "resistant", None, None, ("keyderive",), None),
    "bcrypt": _a("kdf", None, None, "resistant", None, None, ("keyderive",), None),
    "scrypt": _a("kdf", None, None, "resistant", "1.3.6.1.4.1.11591.4.11", None, ("keyderive",), None),
    # public key (Shor-vulnerable)
    "RSA-1024": _a("pke", 80, 0, "broken", "1.2.840.113549.1.1.1", None, ENC + ("sign", "verify"), "1024", "Below 112-bit; replace with " + PQC_KEM),
    "RSA-2048": _a("pke", 112, 0, "vulnerable", "1.2.840.113549.1.1.1", None, ENC + ("sign", "verify"), "2048", "Plan migration to " + PQC_KEM + " / " + PQC_SIG),
    "RSA-3072": _a("pke", 128, 0, "vulnerable", "1.2.840.113549.1.1.1", None, ENC + ("sign", "verify"), "3072", "Plan migration to " + PQC_KEM + " / " + PQC_SIG),
    "RSA-4096": _a("pke", 140, 0, "vulnerable", "1.2.840.113549.1.1.1", None, ENC + ("sign", "verify"), "4096", "Plan migration to " + PQC_KEM + " / " + PQC_SIG),
    "RSA": _a("pke", None, 0, "vulnerable", "1.2.840.113549.1.1.1", None, ENC + ("sign", "verify"), None, "Plan migration to " + PQC_KEM + " / " + PQC_SIG),
    "SHA256withRSA": _a("signature", 112, 0, "vulnerable", "1.2.840.113549.1.1.11", None, SIG, None, "Migrate to " + PQC_SIG),
    "SHA384withRSA": _a("signature", 112, 0, "vulnerable", "1.2.840.113549.1.1.12", None, SIG, None, "Migrate to " + PQC_SIG),
    "SHA512withRSA": _a("signature", 112, 0, "vulnerable", "1.2.840.113549.1.1.13", None, SIG, None, "Migrate to " + PQC_SIG),
    "SHA1withRSA": _a("signature", 0, 0, "broken", "1.2.840.113549.1.1.5", None, SIG, None, "SHA-1 signatures are forgeable; re-issue with " + PQC_SIG),
    "RSASSA-PSS": _a("signature", 112, 0, "vulnerable", "1.2.840.113549.1.1.10", None, SIG, None, "Migrate to " + PQC_SIG),
    # key algorithms: OID is the named-curve OID (RFC 5480)
    "ECDSA-P256": _a("signature", 128, 0, "vulnerable", "1.2.840.10045.3.1.7", None, SIG, "P-256", "Migrate to " + PQC_SIG, "secp256r1"),
    "ECDSA-P384": _a("signature", 192, 0, "vulnerable", "1.3.132.0.34", None, SIG, "P-384", "Migrate to " + PQC_SIG, "secp384r1"),
    # certificate signature algorithms (RFC 5758)
    "SHA256withECDSA": _a("signature", 128, 0, "vulnerable", "1.2.840.10045.4.3.2", None, SIG, None, "Migrate to " + PQC_SIG),
    "SHA384withECDSA": _a("signature", 192, 0, "vulnerable", "1.2.840.10045.4.3.3", None, SIG, None, "Migrate to " + PQC_SIG),
    "ECDSA": _a("signature", None, 0, "vulnerable", "1.2.840.10045.2.1", None, SIG, None, "Migrate to " + PQC_SIG),
    "Ed25519": _a("signature", 128, 0, "vulnerable", "1.3.101.112", None, SIG, None, "Migrate to " + PQC_SIG, "Ed25519"),
    "Ed448": _a("signature", 224, 0, "vulnerable", "1.3.101.113", None, SIG, None, "Migrate to " + PQC_SIG, "Ed448"),
    "X25519": _a("key-agree", 128, 0, "vulnerable", "1.3.101.110", None, ("keygen", "keyderive"), None, "Use hybrid X25519MLKEM768", "Curve25519"),
    "ECDH": _a("key-agree", None, 0, "vulnerable", "1.3.132.1.12", None, ("keygen", "keyderive"), None, "Use " + PQC_KEM),
    "DH": _a("key-agree", None, 0, "vulnerable", "1.2.840.10046.2.1", None, ("keygen", "keyderive"), None, "Use " + PQC_KEM),
    "DSA": _a("signature", None, 0, "broken", "1.2.840.10040.4.1", None, SIG, None, "DSA withdrawn in FIPS 186-5; use " + PQC_SIG),
    # post-quantum (FIPS 203/204/205)
    "ML-KEM-512": _a("kem", 128, 1, "resistant", "2.16.840.1.101.3.4.4.1", None, ("keygen", "encapsulate", "decapsulate"), "512"),
    "ML-KEM-768": _a("kem", 192, 3, "resistant", "2.16.840.1.101.3.4.4.2", None, ("keygen", "encapsulate", "decapsulate"), "768"),
    "ML-KEM-1024": _a("kem", 256, 5, "resistant", "2.16.840.1.101.3.4.4.3", None, ("keygen", "encapsulate", "decapsulate"), "1024"),
    "ML-KEM": _a("kem", None, 3, "resistant", None, None, ("keygen", "encapsulate", "decapsulate")),
    "ML-DSA-44": _a("signature", 128, 2, "resistant", "2.16.840.1.101.3.4.3.17", None, SIG, "44"),
    "ML-DSA-65": _a("signature", 192, 3, "resistant", "2.16.840.1.101.3.4.3.18", None, SIG, "65"),
    "ML-DSA-87": _a("signature", 256, 5, "resistant", "2.16.840.1.101.3.4.3.19", None, SIG, "87"),
    "ML-DSA": _a("signature", None, 3, "resistant", None, None, SIG),
    "SLH-DSA": _a("signature", None, 1, "resistant", None, None, SIG),
}

# OID -> catalogue name, for certificates
OID_TO_ALG = {a["oid"]: n for n, a in ALGORITHMS.items() if a["oid"]}
OID_TO_ALG["1.2.840.113549.1.1.1"] = "RSA"

# Source-code detection patterns (most specific first). Case-insensitive.
SOURCE_PATTERNS: list[tuple[str, re.Pattern]] = [(n, re.compile(p, re.I)) for n, p in [
    ("AES-256-GCM", r"aes[-_]?256[-_/]?gcm"),
    ("AES-128-GCM", r"aes[-_]?128[-_/]?gcm"),
    ("AES-256-CBC", r"aes[-_]?256[-_/]?cbc"),
    ("AES-128-CBC", r"aes[-_]?128[-_/]?cbc"),
    ("AES-ECB", r"AES/ECB|MODE_ECB|aes[-_]\d*[-_]?ecb|modes\.ECB"),
    ("AES-GCM", r"AES/GCM|MODE_GCM|AESGCM|modes\.GCM|aes-gcm"),
    ("AES-CBC", r"AES/CBC|MODE_CBC|modes\.CBC"),
    ("ChaCha20-Poly1305", r"chacha20[-_]?poly1305"),
    ("3DES", r"\b(3des|tripledes|des-?ede3?|DESede)\b"),
    ("RC4", r"\b(rc4|arcfour)\b"),
    ("MD5", r"\bmd5\b"),
    ("SHA-1", r"\bsha[-_]?1\b(?![-_]?\d)"),
    ("SHA3-256", r"\bsha3[-_]?256\b"),
    ("SHA-256", r"\bsha[-_]?256\b"),
    ("SHA-384", r"\bsha[-_]?384\b"),
    ("SHA-512", r"\bsha[-_]?512\b"),
    ("HMAC-SHA256", r"hmac[-_]?sha[-_]?256|HmacSHA256"),
    ("HMAC-SHA1", r"hmac[-_]?sha[-_]?1\b|HmacSHA1\b"),
    ("PBKDF2", r"\bpbkdf2"),
    ("Argon2", r"\bargon2"),
    ("bcrypt", r"\bbcrypt\b"),
    ("scrypt", r"\bscrypt\b"),
    ("RSA-1024", r"\b(key_?size\s*=\s*1024|RSA[-_ ]?1024)\b"),
    ("RSA-2048", r"\b(key_?size\s*=\s*2048|RSA[-_ ]?2048)\b"),
    ("RSA-4096", r"\b(key_?size\s*=\s*4096|RSA[-_ ]?4096)\b"),
    ("SHA256withRSA", r"SHA256withRSA|sha256WithRSAEncryption|RS256"),
    ("SHA1withRSA", r"SHA1withRSA|sha1WithRSAEncryption"),
    ("RSASSA-PSS", r"RSASSA[-_]?PSS|\bPS256\b|padding\.PSS"),
    ("RSA", r"\brsa\b"),
    ("ECDSA-P256", r"secp256r1|prime256v1|\bP-?256\b|\bES256\b"),
    ("ECDSA-P384", r"secp384r1|\bP-?384\b|\bES384\b"),
    ("ECDSA", r"\becdsa\b"),
    ("Ed25519", r"\bed25519\b|\bEdDSA\b"),
    ("X25519", r"\bx25519\b"),
    ("ECDH", r"\becdhe?\b"),
    ("DSA", r"(?<![-_a-z])dsa\b"),  # not ML-DSA / SLH-DSA / ECDSA
    ("ML-KEM-768", r"ml[-_]?kem[-_]?768|kyber[-_]?768"),
    ("ML-KEM", r"ml[-_]?kem|\bkyber"),
    ("ML-DSA-65", r"ml[-_]?dsa[-_]?65|dilithium[-_]?3"),
    ("ML-DSA", r"ml[-_]?dsa|dilithium"),
    ("SLH-DSA", r"slh[-_]?dsa|sphincs"),
]]

# Generic names suppressed when a more specific variant matched on the same line
GENERIC_PARENTS = {
    "AES-GCM": "AES", "AES-CBC": "AES", "AES-256-GCM": "AES-GCM", "AES-128-GCM": "AES-GCM",
    "AES-256-CBC": "AES-CBC", "AES-128-CBC": "AES-CBC", "RSA-2048": "RSA", "RSA-4096": "RSA", "RSA-1024": "RSA",
    "SHA256withRSA": "RSA", "SHA1withRSA": "RSA", "ECDSA-P256": "ECDSA", "ECDSA-P384": "ECDSA",
    "ML-KEM-768": "ML-KEM", "ML-DSA-65": "ML-DSA", "HMAC-SHA256": "SHA-256", "HMAC-SHA1": "SHA-1",
}

TLS_VERSIONS = {
    "TLSv1": ("1.0", "broken"), "TLSv1.1": ("1.1", "broken"), "TLSv1.2": ("1.2", "vulnerable"),
    "TLSv1.3": ("1.3", "vulnerable"), "SSLv3": ("3.0", "broken"),
}


def quantum_risk(name: str) -> str:
    return (ALGORITHMS.get(name) or {}).get("quantum", "unknown")
