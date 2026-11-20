"""Digital signatures (CERT-In 5.3.3.2 / 5.4, QBOM & AIBOM "Attestations").

Embeds a JSON Signature Format (JSF) Ed25519 signature in the CycloneDX document:
the document with ``signature`` minus ``value`` is canonicalised (sorted keys,
no whitespace, UTF-8 - equivalent to RFC 8785 JCS for the strings/integers BOMs
contain) and signed. Requires the optional ``cryptography`` package.
"""
from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as e:  # pragma: no cover
        raise SystemExit("signing needs the 'cryptography' package: pip install cryptography") from e
    return serialization, ed25519


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def keygen(out_dir: str | Path) -> tuple[Path, Path]:
    serialization, ed25519 = _crypto()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    key = ed25519.Ed25519PrivateKey.generate()
    priv, pub = out / "bom-signing.key", out / "bom-signing.pub"
    if priv.exists():
        raise FileExistsError(f"{priv} already exists - refusing to overwrite a signing key")
    priv.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    os.chmod(priv, 0o600)
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub


def sign(doc: dict, private_key_pem: bytes) -> dict:
    serialization, ed25519 = _crypto()
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("only Ed25519 keys are supported (use `certin-bom keygen`)")
    raw_pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    out = copy.deepcopy(doc)
    out.pop("signature", None)
    out["signature"] = {"algorithm": "Ed25519", "publicKey": {"kty": "OKP", "crv": "Ed25519", "x": _b64u(raw_pub)}}
    out["signature"]["value"] = _b64u(key.sign(canonical(out)))
    return out


def verify(doc: dict, public_key_pem: bytes | None = None) -> tuple[bool, str]:
    serialization, ed25519 = _crypto()
    sig = doc.get("signature")
    if not sig or "value" not in sig:
        return False, "document is not signed"
    if sig.get("algorithm") != "Ed25519":
        return False, f"unsupported algorithm {sig.get('algorithm')}"
    embedded = _unb64u(sig["publicKey"]["x"])
    if public_key_pem:
        trusted = serialization.load_pem_public_key(public_key_pem)
        trusted_raw = trusted.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if trusted_raw != embedded:
            return False, "signature made with a different key than the trusted public key"
    body = copy.deepcopy(doc)
    value = _unb64u(body["signature"].pop("value"))
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(embedded).verify(value, canonical(body))
    except Exception:  # noqa: BLE001 - cryptography raises InvalidSignature
        return False, "signature does not match document content (tampered or re-serialised)"
    return True, "valid" + ("" if public_key_pem else " (embedded key only - pass --pubkey to check signer identity)")
