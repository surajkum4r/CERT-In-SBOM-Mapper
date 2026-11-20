"""certin-bom command line."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from . import GUIDELINE, __version__
from .config import Config
from .logging_setup import setup_logging
from .util import read_json, write_json

TEMPLATES = Path(__file__).parent / "templates"


def _cfg(a) -> Config:
    flag = lambda name: True if getattr(a, name, False) else None  # noqa: E731
    return Config.load(getattr(a, "config", None), author=getattr(a, "author", None),
                       organization=getattr(a, "org", None), online=flag("online"),
                       criticality_heuristic=flag("criticality_heuristic"), nvd=flag("nvd"),
                       osv_db=getattr(a, "osv_db", None),
                       kev=False if getattr(a, "no_kev", False) else None,
                       epss=False if getattr(a, "no_epss", False) else None)


def cmd_vulndb(a) -> int:
    from .vulns import update_offline_db
    meta = update_offline_db(a.dir, a.ecosystem, with_kev=not a.no_kev, with_epss=not a.no_epss)
    print(json.dumps(meta, indent=2))
    return 0


def _out(path: str | None, doc: dict) -> None:
    if path:
        write_json(path, doc)
        print(f"wrote {path}", file=sys.stderr)
    else:
        json.dump(doc, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")


def cmd_sbom(a) -> int:
    from .sbom import build_sbom
    practices = read_json(a.practices) if a.practices else None
    doc, _ = build_sbom(a.input, _cfg(a), a.overrides, practices)
    _out(a.output, doc)
    return 0


def cmd_cbom(a) -> int:
    from .cbom import build_cbom
    _out(a.output, build_cbom(a.paths, a.tls or [], _cfg(a).author or None))
    return 0


def cmd_qbom(a) -> int:
    from .qbom import build_qbom
    _out(a.output, build_qbom(read_json(a.cbom), read_json(a.device) if a.device else None, _cfg(a).author or None))
    return 0


def cmd_aibom(a) -> int:
    from .aibom import build_aibom
    _out(a.output, build_aibom(read_json(a.spec), a.sbom, _cfg(a).author or None))
    return 0


def cmd_hbom(a) -> int:
    from .hbom import build_hbom
    _out(a.output, build_hbom(read_json(a.spec), _cfg(a).author or None))
    return 0


def cmd_vex(a) -> int:
    from .vex import csaf_vex, cyclonedx_vex, load_triage
    sbom, triage = read_json(a.sbom), load_triage(a.triage)
    if not sbom.get("vulnerabilities"):
        print("SBOM has no vulnerabilities section; generate it with `sbom --online` first", file=sys.stderr)
    if not (a.cdx or a.csaf):
        a.cdx = "-"
    if a.cdx:
        _out(None if a.cdx == "-" else a.cdx, cyclonedx_vex(sbom, triage, _cfg(a).author or None))
    if a.csaf:
        _out(a.csaf, csaf_vex(sbom, triage, a.publisher, a.namespace))
    return 0


def cmd_split(a) -> int:
    from .split import split
    pub, priv = split(read_json(a.bom), _cfg(a).private_properties)
    _out(a.public, pub)
    _out(a.private, priv)
    return 0


def cmd_keygen(a) -> int:
    from .sign import keygen
    priv, pub = keygen(a.out_dir)
    print(f"private key: {priv} (keep secret)\npublic key:  {pub} (publish)")
    return 0


def cmd_sign(a) -> int:
    from .sign import sign
    _out(a.output, sign(read_json(a.bom), Path(a.key).read_bytes()))
    return 0


def cmd_verify(a) -> int:
    from .sign import verify
    ok, msg = verify(read_json(a.bom), Path(a.pubkey).read_bytes() if a.pubkey else None)
    print(("OK: " if ok else "FAILED: ") + msg)
    return 0 if ok else 1


def cmd_validate(a) -> int:
    from .report import to_markdown
    from .validate import validate
    result = validate(read_json(a.bom), a.type)
    if a.json:
        write_json(a.json, result)
    md = to_markdown(result)
    if a.md:
        Path(a.md).write_text(md, encoding="utf-8")
    if not a.quiet:
        print(md)
    s = result["summary"]
    print(f"{result['bom_type']}: {s['verdict']} | conformance {s['conformance_pct']}% | "
          f"completeness {s['completeness_pct']}%", file=sys.stderr)
    if a.fail_under is not None and s["conformance_pct"] < a.fail_under:
        return 2
    return 0


def cmd_init(a) -> int:
    src = TEMPLATES / f"{a.kind}.json"
    dest = Path(a.output or f"{a.kind}.json")
    if dest.exists() and not a.force:
        print(f"{dest} exists (use --force)", file=sys.stderr)
        return 1
    shutil.copyfile(src, dest)
    print(f"wrote template {dest}")
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="certin-bom", description=f"BOM tooling for {GUIDELINE}")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="count", default=0)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, out=True):
        sp.add_argument("--config", help="JSON config file (see `init config`)")
        sp.add_argument("--author", help="Author of BOM data (person/organisation)")
        if out:
            sp.add_argument("-o", "--output", help="output file (default: stdout)")

    s = sub.add_parser("sbom", help="Enrich a CycloneDX/SPDX SBOM to the 21 CERT-In Table 5 fields")
    s.add_argument("input")
    s.add_argument("--org", help="your organisation (first-party origin detection)")
    s.add_argument("--overrides", help="per-component field overrides (see `init overrides`)")
    s.add_argument("--practices", help="Table 5 Practices & Processes declaration (see `init practices`)")
    s.add_argument("--online", action="store_true",
                   help="metadata (PyPI, npm, Maven Central, crates.io, RubyGems, deps.dev, endoflife.date) + "
                        "vulnerabilities (OSV, CISA KEV, EPSS)")
    s.add_argument("--nvd", action="store_true", help="with --online: also query NVD by CPE for components OSV "
                                                      "cannot cover (set NVD_API_KEY for faster rate limits)")
    s.add_argument("--osv-db", metavar="DIR", help="offline vulnerability DB from `vulndb update` (air-gapped use)")
    s.add_argument("--no-kev", action="store_true", help="skip CISA KEV lookup")
    s.add_argument("--no-epss", action="store_true", help="skip EPSS lookup")
    s.add_argument("--criticality-heuristic", action="store_true", help="direct=high, transitive=medium, optional=low")
    common(s)
    s.set_defaults(func=cmd_sbom)

    s = sub.add_parser("vulndb", help="Build/refresh an offline vulnerability database (OSV + KEV + EPSS)")
    vsub = s.add_subparsers(dest="vcmd", required=True)
    u = vsub.add_parser("update", help="download OSV ecosystems, CISA KEV and EPSS")
    u.add_argument("--dir", default="vulndb")
    u.add_argument("--ecosystem", nargs="+", default=["PyPI", "npm", "Maven", "Go", "crates.io", "NuGet",
                                                      "RubyGems", "Packagist", "Debian", "Alpine", "Ubuntu"],
                   help="OSV ecosystem names (see https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt)")
    u.add_argument("--no-kev", action="store_true")
    u.add_argument("--no-epss", action="store_true")
    u.set_defaults(func=cmd_vulndb)

    s = sub.add_parser("cbom", help="Inventory cryptographic assets (Table 9) from code, certs/keys and TLS endpoints")
    s.add_argument("paths", nargs="*", default=[])
    s.add_argument("--tls", action="append", metavar="HOST:PORT", help="probe a TLS endpoint (repeatable)")
    common(s)
    s.set_defaults(func=cmd_cbom)

    s = sub.add_parser("qbom", help="Quantum-risk BOM (Table 8) from a CBOM and optional device spec")
    s.add_argument("--cbom", required=True)
    s.add_argument("--device", help="Table 8 device spec (see `init qbom`)")
    common(s)
    s.set_defaults(func=cmd_qbom)

    s = sub.add_parser("aibom", help="AIBOM (Table 10) from a model spec")
    s.add_argument("spec")
    s.add_argument("--sbom", help="application SBOM to pull ML framework dependencies from")
    common(s)
    s.set_defaults(func=cmd_aibom)

    s = sub.add_parser("hbom", help="HBOM (Table 11) from a hardware spec")
    s.add_argument("spec")
    common(s)
    s.set_defaults(func=cmd_hbom)

    s = sub.add_parser("vex", help="VEX (CycloneDX) and CSAF 2.0 advisory from an SBOM + triage file")
    s.add_argument("sbom")
    s.add_argument("--triage", help="triage decisions (see `init triage`)")
    s.add_argument("--cdx", help="CycloneDX VEX output ('-' for stdout)")
    s.add_argument("--csaf", help="CSAF 2.0 VEX output")
    s.add_argument("--publisher", default="Unknown publisher")
    s.add_argument("--namespace", default="https://example.invalid", help="publisher namespace URL for CSAF")
    common(s, out=False)
    s.set_defaults(func=cmd_vex)

    s = sub.add_parser("split", help="Produce public and private SBOMs (5.3.2)")
    s.add_argument("bom")
    s.add_argument("--public", required=True)
    s.add_argument("--private", required=True)
    common(s, out=False)
    s.set_defaults(func=cmd_split)

    s = sub.add_parser("keygen", help="Generate an Ed25519 signing key pair")
    s.add_argument("--out-dir", default="keys")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("sign", help="Embed a JSF Ed25519 signature")
    s.add_argument("bom")
    s.add_argument("--key", required=True)
    s.add_argument("-o", "--output")
    s.set_defaults(func=cmd_sign)

    s = sub.add_parser("verify", help="Verify an embedded signature")
    s.add_argument("bom")
    s.add_argument("--pubkey", help="trusted public key PEM")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("validate", help="Audit any BOM against CERT-In minimum elements")
    s.add_argument("bom")
    s.add_argument("--type", choices=["SBOM", "CBOM", "QBOM", "AIBOM", "HBOM"], help="override auto-detection")
    s.add_argument("--json", help="write JSON results")
    s.add_argument("--md", help="write Markdown report")
    s.add_argument("--fail-under", type=float, help="exit 2 if conformance %% is below this (CI gate)")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=cmd_validate)

    s = sub.add_parser("init", help="Write an input template")
    s.add_argument("kind", choices=sorted(p.stem for p in TEMPLATES.glob("*.json")))
    s.add_argument("-o", "--output")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)
    return p


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    setup_logging(a.verbose)
    try:
        return a.func(a)
    except (FileNotFoundError, ValueError, FileExistsError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
