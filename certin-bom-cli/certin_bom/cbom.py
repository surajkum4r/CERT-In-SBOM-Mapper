"""CBOM generator (CERT-In Table 9) - CycloneDX 1.6 cryptographic-asset components.

Sources:
  * source code / config files: regex detection of algorithm usage (with file:line evidence)
  * certificate and key files (.pem/.crt/.cer/.der/.key)
  * live TLS endpoints (host:port)
"""
from __future__ import annotations

import hashlib
import logging
import os
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path

from .config import NS
from .crypto_catalog import ALGORITHMS, GENERIC_PARENTS, OID_TO_ALG, SOURCE_PATTERNS, TLS_VERSIONS
from .cyclonedx import prop, skeleton
from .util import UNKNOWN

log = logging.getLogger(__name__)

SOURCE_EXT = {".py", ".java", ".kt", ".kts", ".go", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".c", ".cc",
              ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".rs", ".swift", ".scala", ".m", ".mm", ".conf", ".cfg",
              ".ini", ".yaml", ".yml", ".toml", ".properties", ".xml", ".tf", ".sh", ".env", ".gradle"}
CERT_EXT = {".pem", ".crt", ".cer", ".der", ".cert", ".key", ".pub"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", "target", ".tox",
             ".mypy_cache", ".pytest_cache", "vendor", ".idea", ".gradle", "site-packages"}
MAX_FILE = 2_000_000
MAX_EVIDENCE = 25
TLS_OID = "1.3.18.0.2.32.104"  # OID used for TLS in the CycloneDX CBOM examples


def _have_cryptography() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


class CbomBuilder:
    def __init__(self) -> None:
        self.components: dict[str, dict] = {}
        self.findings: list[str] = []

    # -------------------------------------------------------------- algorithms
    def algorithm(self, name: str, location: str | None = None, line: int | None = None) -> str:
        ref = f"crypto/algorithm/{name}"
        comp = self.components.get(ref)
        if comp is None:
            spec = ALGORITHMS.get(name, {})
            ap: dict = {}
            unknowns, na = [], []
            if spec.get("primitive"):
                ap["primitive"] = spec["primitive"]
            else:
                unknowns.append("primitive")
            if spec.get("param"):
                ap["parameterSetIdentifier"] = spec["param"]
            if spec.get("curve"):
                ap["curve"] = spec["curve"]
            if spec.get("mode"):
                ap["mode"] = spec["mode"]
            elif spec.get("primitive") in ("block-cipher",) or not spec:
                unknowns.append("mode")
            else:
                na.append("mode")
            if spec.get("functions"):
                ap["cryptoFunctions"] = spec["functions"]
            else:
                unknowns.append("crypto_functions")
            if spec.get("classical") is not None:
                ap["classicalSecurityLevel"] = spec["classical"]
            else:
                unknowns.append("classical_security_level")
            if spec.get("nistq") is not None:
                ap["nistQuantumSecurityLevel"] = spec["nistq"]
            cp: dict = {"assetType": "algorithm", "algorithmProperties": ap}
            if spec.get("oid"):
                cp["oid"] = spec["oid"]
            else:
                unknowns.append("oid")
            props = [prop("quantum_risk", spec.get("quantum", UNKNOWN))]
            if spec.get("recommendation"):
                props.append(prop("recommendation", spec["recommendation"]))
            if unknowns:
                props.append(prop("known_unknowns", ",".join(unknowns)))
            if na:
                props.append(prop("not_applicable", ",".join(na)))
            comp = {"type": "cryptographic-asset", "bom-ref": ref, "name": name, "cryptoProperties": cp,
                    "properties": props}
            self.components[ref] = comp
        if location:
            occ = comp.setdefault("evidence", {}).setdefault("occurrences", [])
            if len(occ) < MAX_EVIDENCE:
                occ.append({"location": location, **({"line": line} if line else {})})
        return ref

    # -------------------------------------------------------------- source scan
    def scan_source(self, root: Path) -> None:
        files = [root] if root.is_file() else _walk(root)
        for path in files:
            if path.suffix.lower() not in SOURCE_EXT or path.stat().st_size > MAX_FILE:
                continue
            rel = os.path.relpath(path, root if root.is_dir() else root.parent)
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for no, text in enumerate(lines, 1):
                if len(text) > 2000:  # minified bundles
                    continue
                hits = {name for name, rx in SOURCE_PATTERNS if rx.search(text)}
                if not hits:
                    continue
                for name in list(hits):  # drop generic names implied by a specific match
                    parent = GENERIC_PARENTS.get(name)
                    while parent:
                        hits.discard(parent)
                        parent = GENERIC_PARENTS.get(parent)
                for name in sorted(hits):
                    self.algorithm(name, rel, no)

    # -------------------------------------------------------------- keys / certs
    def scan_crypto_files(self, root: Path) -> None:
        files = [root] if root.is_file() else _walk(root)
        for path in files:
            if path.suffix.lower() not in CERT_EXT or path.stat().st_size > MAX_FILE:
                continue
            data = path.read_bytes()
            rel = os.path.relpath(path, root if root.is_dir() else root.parent)
            if b"PRIVATE KEY-----" in data:
                self._private_key(data, rel)
            if b"BEGIN CERTIFICATE" in data or (path.suffix.lower() in (".der", ".cer") and data[:1] == b"\x30"):
                self._certificates(data, rel, path)
            elif b"BEGIN PUBLIC KEY" in data:
                self._public_key_file(data, rel)

    def _private_key(self, data: bytes, rel: str) -> None:
        size, alg = None, None
        if _have_cryptography():
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            try:
                key = load_pem_private_key(data, password=None)
                size, alg = _key_size_alg(key)
            except Exception:  # noqa: BLE001 - encrypted or unsupported key
                pass
        ref = f"crypto/key/private/{rel}"
        rcm = {"type": "private-key", "id": f"file:{rel}"}
        unknowns = ["state", "creation_date", "activation_date"]
        if size:
            rcm["size"] = size
        else:
            unknowns.append("size")
        if alg:
            rcm["algorithmRef"] = self.algorithm(alg)
        self.components[ref] = {
            "type": "cryptographic-asset", "bom-ref": ref, "name": f"private key {Path(rel).name}",
            "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": rcm},
            "evidence": {"occurrences": [{"location": rel}]},
            "properties": [prop("finding", "private key material present in scanned tree - move to a secrets manager/HSM"),
                           prop("known_unknowns", ",".join(unknowns))],
        }
        self.findings.append(f"Private key stored in source tree: {rel}")

    def _public_key_file(self, data: bytes, rel: str) -> None:
        if not _have_cryptography():
            self.findings.append(f"Public key {rel} not parsed (install 'cryptography')")
            return
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        try:
            self.public_key(load_pem_public_key(data), name=f"public key {Path(rel).name}", location=rel)
        except Exception as e:  # noqa: BLE001
            log.warning("cannot parse %s: %s", rel, e)

    def public_key(self, key, name: str, location: str | None = None, active: bool | None = None,
                   activation: str | None = None) -> str:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        spki = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        fp = hashlib.sha256(spki).hexdigest()
        ref = f"crypto/key/public/{fp[:16]}"
        if ref in self.components:
            return ref
        size, alg = _key_size_alg(key)
        rcm: dict = {"type": "public-key", "id": f"sha256:{fp}"}
        unknowns = ["creation_date"]
        if size:
            rcm["size"] = size
        if alg:
            rcm["algorithmRef"] = self.algorithm(alg)
        if active is not None:
            rcm["state"] = "active" if active else "deactivated"
        else:
            unknowns.append("state")
        if activation:
            rcm["activationDate"] = activation
        else:
            unknowns.append("activation_date")
        comp = {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
                "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": rcm},
                "properties": [prop("known_unknowns", ",".join(unknowns))]}
        if location:
            comp["evidence"] = {"occurrences": [{"location": location}]}
        self.components[ref] = comp
        return ref

    def _certificates(self, data: bytes, rel: str, path: Path) -> None:
        if _have_cryptography():
            from cryptography import x509
            try:
                certs = x509.load_pem_x509_certificates(data) if b"BEGIN CERTIFICATE" in data \
                    else [x509.load_der_x509_certificate(data)]
            except Exception as e:  # noqa: BLE001
                log.warning("cannot parse certificate %s: %s", rel, e)
                return
            for cert in certs:
                self.certificate(cert, rel, path.suffix.lower() or ".pem")
            return
        # stdlib fallback: subject/issuer/validity only
        try:
            info = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
        except Exception as e:  # noqa: BLE001
            log.warning("cannot parse certificate %s without 'cryptography': %s", rel, e)
            return
        dn = lambda t: ",".join(f"{k}={v}" for rdn in t for k, v in rdn)  # noqa: E731
        nb = _ssl_time(info.get("notBefore"))
        na = _ssl_time(info.get("notAfter"))
        ref = f"crypto/certificate/{rel}"
        self.components[ref] = {
            "type": "cryptographic-asset", "bom-ref": ref, "name": _cn(dn(info.get("subject", ()))) or rel,
            "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
                "subjectName": dn(info.get("subject", ())), "issuerName": dn(info.get("issuer", ())),
                "notValidBefore": nb, "notValidAfter": na, "certificateFormat": "X.509",
                "certificateExtension": path.suffix.lower()}},
            "evidence": {"occurrences": [{"location": rel}]},
            "properties": [prop("known_unknowns", "signature_algorithm_ref,subject_public_key_ref")],
        }

    def certificate(self, cert, location: str, extension: str = ".pem") -> str:
        from cryptography.hazmat.primitives import hashes
        fp = cert.fingerprint(hashes.SHA256()).hex()
        ref = f"crypto/certificate/{fp[:16]}"
        if ref in self.components:
            return ref
        nb, na = _utc(cert, "not_valid_before"), _utc(cert, "not_valid_after")
        now = datetime.now(timezone.utc)
        valid = nb <= now <= na
        sig_oid = cert.signature_algorithm_oid.dotted_string
        sig_name = OID_TO_ALG.get(sig_oid)
        sig_ref = self.algorithm(sig_name) if sig_name else self._unknown_algorithm(sig_oid)
        key_ref = self.public_key(cert.public_key(), name=f"public key of {_cn(cert.subject.rfc4514_string()) or fp[:16]}",
                                  active=valid, activation=_iso(nb))
        props = [prop("fingerprint_sha256", fp), prop("validity", "valid" if valid else ("expired" if now > na else "not yet valid"))]
        days = (na - now).days
        if not valid or days < 30:
            self.findings.append(f"Certificate {cert.subject.rfc4514_string()} ({location}) "
                                 + ("is not currently valid" if not valid else f"expires in {days} days"))
        self.components[ref] = {
            "type": "cryptographic-asset", "bom-ref": ref,
            "name": _cn(cert.subject.rfc4514_string()) or cert.subject.rfc4514_string() or fp[:16],
            "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
                "subjectName": cert.subject.rfc4514_string(), "issuerName": cert.issuer.rfc4514_string(),
                "notValidBefore": _iso(nb), "notValidAfter": _iso(na), "signatureAlgorithmRef": sig_ref,
                "subjectPublicKeyRef": key_ref, "certificateFormat": "X.509", "certificateExtension": extension}},
            "evidence": {"occurrences": [{"location": location}]},
            "properties": props,
        }
        return ref

    def _unknown_algorithm(self, oid: str) -> str:
        ref = f"crypto/algorithm/oid-{oid}"
        self.components.setdefault(ref, {
            "type": "cryptographic-asset", "bom-ref": ref, "name": f"OID {oid}",
            "cryptoProperties": {"assetType": "algorithm", "oid": oid, "algorithmProperties": {}},
            "properties": [prop("quantum_risk", UNKNOWN),
                           prop("known_unknowns", "primitive,mode,crypto_functions,classical_security_level")]})
        return ref

    # -------------------------------------------------------------- TLS
    def scan_tls(self, endpoint: str, timeout: float = 10.0) -> None:
        host, _, port_s = endpoint.rpartition(":")
        host, port = (host or endpoint).strip("[]"), int(port_s) if port_s.isdigit() else 443
        verified = True
        try:
            version, cipher, der = _tls_handshake(host, port, ssl.create_default_context(), timeout)
        except ssl.SSLCertVerificationError as e:
            verified = False
            self.findings.append(f"TLS {host}:{port}: certificate verification failed ({e.verify_message})")
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            version, cipher, der = _tls_handshake(host, port, ctx, timeout)
        except OSError as e:
            self.findings.append(f"TLS {host}:{port}: connection failed ({e})")
            return
        ver, risk = TLS_VERSIONS.get(version or "", (version or UNKNOWN, UNKNOWN))
        suite_algs = [self.algorithm(a) for a in _suite_algorithms(cipher[0] if cipher else "")]
        ref = f"crypto/protocol/tls/{host}:{port}"
        props = [prop("endpoint", f"{host}:{port}"), prop("quantum_risk", risk),
                 prop("certificate_verified", str(verified).lower()),
                 prop("key_exchange", "not observable via Python ssl; classical ECDHE assumed unless a hybrid "
                                      "PQC group (X25519MLKEM768) is configured"),
                 prop("oid_note", "TLS has no IANA-assigned OID; value follows the CycloneDX CBOM examples")]
        if risk == "broken":
            self.findings.append(f"TLS {host}:{port} negotiated deprecated {version}")
        self.components[ref] = {
            "type": "cryptographic-asset", "bom-ref": ref, "name": f"TLS {ver} ({host}:{port})",
            "cryptoProperties": {"assetType": "protocol", "oid": TLS_OID, "protocolProperties": {
                "type": "tls", "version": ver,
                "cipherSuites": [{"name": cipher[0], "algorithms": suite_algs}] if cipher else [],
            }},
            "properties": props,
        }
        if der and _have_cryptography():
            from cryptography import x509
            self.certificate(x509.load_der_x509_certificate(der), f"tls://{host}:{port}", ".der")

    # -------------------------------------------------------------- output
    def document(self, author: str | None = None) -> dict:
        doc = skeleton("CBOM", authors=[author] if author else None,
                       extra_props=[prop("finding", f) for f in self.findings])
        doc["components"] = sorted(self.components.values(), key=lambda c: c["bom-ref"])
        deps = []
        for c in doc["components"]:
            cp = c["cryptoProperties"]
            refs = [cp.get("certificateProperties", {}).get(k) for k in ("signatureAlgorithmRef", "subjectPublicKeyRef")]
            refs.append(cp.get("relatedCryptoMaterialProperties", {}).get("algorithmRef"))
            for suite in cp.get("protocolProperties", {}).get("cipherSuites", []):
                refs += suite.get("algorithms", [])
            refs = sorted({r for r in refs if r})
            if refs:
                deps.append({"ref": c["bom-ref"], "provides": refs})
        if deps:
            doc["dependencies"] = deps
        return doc


# ------------------------------------------------------------------ helpers
def _walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for f in filenames:
            yield Path(dirpath) / f


def _tls_handshake(host, port, ctx, timeout):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            return s.version(), s.cipher(), s.getpeercert(binary_form=True)


def _suite_algorithms(suite: str) -> list[str]:
    s = suite.upper().replace("-", "_")
    out = []
    if "ECDHE" in s:
        out.append("ECDH")
    elif "DHE" in s:
        out.append("DH")
    if "_RSA_" in f"_{s}_" or s.startswith("RSA_") or "ECDHE_RSA" in s:
        out.append("RSA")
    if "ECDSA" in s:
        out.append("ECDSA")
    for name, needle in (("AES-256-GCM", "AES_256_GCM"), ("AES-128-GCM", "AES_128_GCM"), ("AES-256-GCM", "AES256_GCM"),
                         ("AES-128-GCM", "AES128_GCM"), ("AES-256-CBC", "AES256_SHA"), ("AES-128-CBC", "AES128_SHA"),
                         ("ChaCha20-Poly1305", "CHACHA20_POLY1305"), ("3DES", "3DES"), ("RC4", "RC4")):
        if needle in s and name not in out:
            out.append(name)
    for name, needle in (("SHA-384", "SHA384"), ("SHA-256", "SHA256")):
        if s.endswith(needle):
            out.append(name)
            break
    return out


def _key_size_alg(key) -> tuple[int | None, str | None]:
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x25519
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        n = f"RSA-{key.key_size}"
        return key.key_size, n if n in ALGORITHMS else "RSA"
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return key.key_size, {"secp256r1": "ECDSA-P256", "secp384r1": "ECDSA-P384"}.get(key.curve.name, "ECDSA")
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return 256, "Ed25519"
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return 456, "Ed448"
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return 256, "X25519"
    return getattr(key, "key_size", None), None


def _utc(cert, attr: str) -> datetime:
    val = getattr(cert, attr + "_utc", None)
    return val if val is not None else getattr(cert, attr).replace(tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ssl_time(value: str | None) -> str | None:
    if not value:
        return None
    return _iso(datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc))


def _cn(dn: str) -> str | None:
    for part in dn.split(","):
        if part.strip().upper().startswith("CN="):
            return part.split("=", 1)[1]
    return None


def build_cbom(paths: list[str], tls: list[str], author: str | None = None, timeout: float = 10.0) -> dict:
    b = CbomBuilder()
    for p in paths:
        root = Path(p)
        if not root.exists():
            raise FileNotFoundError(p)
        b.scan_source(root)
        b.scan_crypto_files(root)
    for ep in tls:
        b.scan_tls(ep, timeout)
    if not _have_cryptography():
        b.findings.append("'cryptography' not installed: certificate signature algorithms and key sizes not extracted")
    return b.document(author)
