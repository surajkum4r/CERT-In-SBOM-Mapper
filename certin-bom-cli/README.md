# certin-bom

Generate, enrich, sign and **audit** Bills of Materials against the
**CERT-In Technical Guidelines on SBOM | QBOM & CBOM | AIBOM | HBOM, Version 2.0 (09.07.2025)**.

Output is CycloneDX 1.6 JSON, validated against the official strict schema. Input can be any
CycloneDX 1.4–1.6 or SPDX 2.2/2.3 JSON SBOM (Syft, Trivy, cdxgen, Maven/Gradle plugins, ...).
The tool uses only the Python standard library. The `cryptography` package is optional and is
needed for signing and for certificate/key parsing.

| BOM | CERT-In table | Command | Source of data |
|---|---|---|---|
| SBOM | Table 5 (21 data fields + practices) | `sbom` | existing SBOM + heuristics + overrides + optional online lookups |
| CBOM | Table 9 (algorithms, keys, protocols, certificates) | `cbom` | source-code scan, cert/key files, live TLS endpoints |
| QBOM | Table 8 + Table 9 | `qbom` | a CBOM + device spec; adds quantum risk and migration priority |
| AIBOM | Table 10 (19 elements) | `aibom` | model spec (+ ML frameworks pulled from an SBOM) |
| HBOM | Table 11 (product + recursive components) | `hbom` | hardware spec |
| VEX / CSAF | Section 6 | `vex` | SBOM + triage decisions |
| Public/private | 5.3.2 | `split` | strips vulnerability data from the public copy |
| Signature | 5.3.3.2, 5.4, "Attestations" | `keygen` / `sign` / `verify` | Ed25519 JSF signature embedded in the BOM |
| Audit | all tables | `validate` | **any** CycloneDX/SPDX BOM, e.g. one received from a supplier |

---

## Setup on your machine (step by step)

### Step 1: Check prerequisites

You need **Python 3.9 or newer** and `git` (or a downloaded copy of this folder).

```bash
python3 --version        # must print 3.9 or higher
```

* **macOS:** `brew install python` if needed.
* **Ubuntu/Debian:** `sudo apt install python3 python3-venv python3-pip`.
* **Windows:** install from python.org and tick *"Add python.exe to PATH"*. On Windows, use
  `python` wherever this guide says `python3`.

### Step 2: Get the code

```bash
git clone https://github.com/surajkum4r/CERT-In-SBOM-Mapper.git
cd CERT-In-SBOM-Mapper/certin-bom-cli
```

The repository also contains the CERT-In SBOM Mapper web app at its root. This CLI lives in
`certin-bom-cli/` and runs independently of it. All commands below are run from that folder.

### Step 3: Create a virtual environment

This keeps the tool's packages separate from your system Python.

```bash
python3 -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .venv\Scripts\Activate.ps1       # Windows PowerShell
```

Your prompt now starts with `(.venv)`. Run the `activate` line again in every new terminal.

### Step 4: Install

```bash
pip install --upgrade pip
pip install -e '.[crypto]'         # Windows PowerShell: pip install -e ".[crypto]"
```

`[crypto]` adds the `cryptography` package for signing and certificate parsing. You can leave it
out (`pip install -e .`); everything else still works. You can also run the tool without
installing it, as `python3 -m certin_bom ...` from this folder.

pip may print a notice about an *"Editable installation"*. That's expected for `-e` installs and
can be ignored. To install a fixed copy instead, for example on a build server, use
`pip install '.[crypto]'`.

### Step 5: Verify the install

```bash
certin-bom --version                               # certin-bom 0.1.0
python3 -m unittest discover -s tests -t .         # all tests pass, no network needed
certin-bom validate tests/fixtures/sample.cdx.json -q
# -> SBOM: NON-CONFORMANT | conformance 30.2% ...   (the sample is deliberately incomplete)
```

### Step 6: Create your configuration

```bash
mkdir -p config out
certin-bom init config    -o config/config.json      # your organisation, author, defaults
certin-bom init overrides -o config/overrides.json   # per-component criticality, CPEs, export control
certin-bom init practices -o config/practices.json   # Table 5 "Practices and Processes"
```

Edit the three files:

* `config.json`: set `author`, `organization` and `first_party_patterns` (strings that identify
  your own packages, e.g. `"com.yourorg"`, `"@yourorg/"`).
* `overrides.json`: set fields only a human can decide, such as `criticality`,
  `usage_restrictions` (export control) and `cpe` for vendored components.
* `practices.json`: describe how often you regenerate BOMs, their depth, distribution and so on.

### Step 7: Set up the NVD API key (recommended)

The NVD is only used with `--nvd`. See the next section for what the key is, where to keep it and
how to check it.

### Step 8: Run your first SBOM

```bash
certin-bom sbom your-sbom.json --config config/config.json --overrides config/overrides.json \
    --practices config/practices.json --online --nvd -o out/sbom.cdx.json
certin-bom validate out/sbom.cdx.json --md out/report.md
```

Open `out/report.md` for the conformance verdict, field coverage and the prioritised
vulnerability list.

If you don't have an SBOM yet, generate one with any standard tool:

* [Syft](https://github.com/anchore/syft): `syft dir:. -o cyclonedx-json > your-sbom.json`, or
  `syft <image> -o cyclonedx-json` for a container image
* [Trivy](https://github.com/aquasecurity/trivy): `trivy fs --format cyclonedx -o your-sbom.json .`
* [cdxgen](https://github.com/CycloneDX/cdxgen): `cdxgen -o your-sbom.json .`

---

## NVD API key

### What the NVD is used for

The [National Vulnerability Database](https://nvd.nist.gov/) (NIST) is queried only when you pass
`--online --nvd`. It is used for two things:

1. **Components without a package ecosystem.** Examples: vendored C/C++ libraries (OpenSSL,
   zlib), binaries such as nginx, appliances and firmware. OSV cannot match these, but the NVD can,
   by **CPE** (for example `cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*`).
   * If a component has no CPE, the tool searches the NVD CPE dictionary for it. When exactly one
     vendor matches, it uses that CPE.
   * When several vendors match, it reports a coverage gap. Set the CPE yourself in
     `overrides.json`.
2. **Scoring unscored CVEs.** Distro advisories (Debian, Ubuntu) often arrive without a CVSS
   score. The NVD fills in score, vector and CWE for them.

### Why you want a key

The key is free. Without one, the NVD allows **5 requests per 30 seconds**, so the tool waits
about 6.5 s between calls. A scan of a container image took about 2 minutes, and score
back-filling is capped at 40 CVEs per run. With a key the limit is **50 requests per 30 seconds**
(about 0.7 s between calls) and there is no back-fill cap.

### How to get one

1. Open <https://nvd.nist.gov/developers/request-an-api-key>.
2. Enter your organisation name, email address and organisation type, accept the terms of use,
   and submit.
3. NVD emails you a link. Open it to activate and view the key (a UUID such as
   `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`). Activate it promptly, because the link expires.

### Where to keep it

The tool reads the key from the **`NVD_API_KEY` environment variable**. There is deliberately no
command-line flag, so the key never lands in your shell history or CI logs.

| Where you run the tool | Where to put the key |
|---|---|
| Your laptop (macOS/Linux, zsh) | `echo 'export NVD_API_KEY="your-key"' >> ~/.zshrc && source ~/.zshrc` |
| Your laptop (bash) | `echo 'export NVD_API_KEY="your-key"' >> ~/.bashrc && source ~/.bashrc` |
| Windows | `setx NVD_API_KEY "your-key"`, then open a new terminal |
| One session only | `export NVD_API_KEY="your-key"` (gone when the terminal closes) |
| GitHub Actions | repository **Settings → Secrets and variables → Actions → New secret** named `NVD_API_KEY`, then `env: NVD_API_KEY: ${{ secrets.NVD_API_KEY }}` in the workflow |
| GitLab CI | **Settings → CI/CD → Variables**, add `NVD_API_KEY` with *Masked* and *Protected* ticked |
| Jenkins | a *Secret text* credential, bound with `withCredentials([string(credentialsId: 'nvd', variable: 'NVD_API_KEY')])` |

`config.json` also accepts `"nvd_api_key"`. Use it only if that file is kept out of version
control; the environment variable is preferred.

**Do not** commit the key, paste it into an issue, or put it in `overrides.json`. The included
`.gitignore` already excludes `.env`, `*.key`, `keys/` and `vulndb/`.

### Check that the key works

1. Confirm the variable is set in this terminal. It should print your key; if it prints nothing,
   open a new terminal or re-run the `source` command.

   ```bash
   echo "$NVD_API_KEY"
   ```

2. Call the API with the key and print the HTTP status:

   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" -H "apiKey: $NVD_API_KEY" \
     "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
   ```

   `200` means the key is accepted. `403` or `404` means the key is wrong or not yet activated.
   The NVD also answers *without* a key, so do step 1 first; a `200` alone doesn't prove the key
   is set.

3. Run a scan with `-v`. With a key, NVD lookups run about one per second, not one every 6–7
   seconds.

### Terms of use

NVD's terms of use require products that use the NVD API to display this notice:

> This product uses the NVD API but is not endorsed or certified by the NVD.

---

## Usage

```bash
# 1. Audit a supplier SBOM as-is
certin-bom validate vendor-sbom.json --md report.md

# 2. Enrich it to CERT-In Table 5
certin-bom sbom vendor-sbom.json --config config/config.json --overrides config/overrides.json \
    --practices config/practices.json --online --nvd -o out/sbom.cdx.json
certin-bom validate out/sbom.cdx.json --fail-under 100      # CI gate: exit 2 below 100% conformance

# 3. VEX + CSAF, public/private copies, signatures
certin-bom init triage -o config/triage.json
certin-bom vex out/sbom.cdx.json --triage config/triage.json --cdx out/vex.cdx.json \
    --csaf out/vex.csaf.json --publisher "Your Org" --namespace https://your-org.example
certin-bom split out/sbom.cdx.json --public out/sbom.public.json --private out/sbom.private.json
certin-bom keygen --out-dir keys                 # once; keep keys/bom-signing.key secret
certin-bom sign out/sbom.public.json --key keys/bom-signing.key -o out/sbom.public.signed.json
certin-bom verify out/sbom.public.signed.json --pubkey keys/bom-signing.pub

# 4. Cryptography and quantum readiness
certin-bom cbom ./src ./deploy/certs --tls api.your-org.example:443 -o out/cbom.json
certin-bom init qbom -o config/qbom.json
certin-bom qbom --cbom out/cbom.json --device config/qbom.json -o out/qbom.json

# 5. AI and hardware
certin-bom init aibom -o config/aibom.json && certin-bom aibom config/aibom.json --sbom out/sbom.cdx.json -o out/aibom.cdx.json
certin-bom init hbom  -o config/hbom.json  && certin-bom hbom config/hbom.json -o out/hbom.cdx.json
```

Add `-v` (or `-vv`) before the command for progress logs, e.g. `certin-bom -v sbom ...`.

### Offline / air-gapped use

1. On a machine with internet access, build the database. It refreshes OSV, CISA KEV and EPSS;
   run it again daily or weekly.

   ```bash
   certin-bom vulndb update --dir vulndb                       # all default ecosystems
   certin-bom vulndb update --dir vulndb --ecosystem PyPI Maven Debian   # or only what you need
   ```

2. Copy the `vulndb/` folder to the audit machine.
3. Scan without any network access:

   ```bash
   certin-bom sbom your-sbom.json --osv-db vulndb --config config/config.json -o out/sbom.cdx.json
   ```

The offline database gives the same results as the live OSV API. NVD lookups need network
access, so they are not available offline. For vendored components, set `cpe` in overrides now,
and run an online `--nvd` scan when you can.

---

## How the 21 SBOM fields are filled

Every field ends up in one of four states, recorded in the BOM itself:

* **present**: from the source SBOM or an override
* **derived**: filled by a documented rule; the rule is written to `cert-in:derivation:<field>`
* **known unknown**: value `unknown`, listed in `cert-in:known_unknowns` (the "Known Unknowns" practice in Table 5)
* **missing**: a gap that `validate` reports

`validate` reports two numbers:

* **Conformance %**: no field is silently missing.
* **Completeness %**: fields carry real values.

| # | Field | CycloneDX location | Fill strategy |
|---|---|---|---|
| 1-3 | Name, Version, Description | native | source; `--online` adds description |
| 4 | Supplier | `supplier.name` | source → purl namespace (maven/npm/go) → registry |
| 5 | License | `licenses` | normalised to SPDX ids; unknown text → `LicenseRef-*` |
| 6 | Origin | `cert-in:origin` | first-party patterns → SPDX OSS licence → licence text |
| 7 | Dependencies | `dependencies` | source graph (SPDX relationships mapped) |
| 8 | Vulnerabilities | `vulnerabilities` | source, OSV, NVD (see below) |
| 9 | Patch Status | `cert-in:patch_status` | computed from fix versions; upgrade target stays on the same release line |
| 10-11 | Release / EOL date | `cert-in:release_date`, `cert-in:eol_date` | SPDX dates, PyPI/npm/Maven/crates.io/RubyGems/deps.dev, endoflife.date |
| 12 | Criticality | `cert-in:criticality` | override → config default → graph heuristic |
| 13 | Usage Restrictions | `cert-in:usage_restrictions` | licence analysis (copyleft/non-commercial); export control via override |
| 14 | Hashes | `hashes` | source, registry digests; MD5/SHA-1-only flagged |
| 15 | Comments | `cert-in:comments` | override, or an auto summary of derived fields and unknowns |
| 16-17 | Author, Timestamp | `cert-in:sbom_author`, `metadata.timestamp` | config |
| 18-20 | Executable / Archive / Structured | `cert-in:*` | component type, purl type, file extension |
| 21 | Unique Identifier | `purl` | source, or a generated `pkg:generic/<supplier>/<name>@<version>` |

## Vulnerability coverage

| Source | Covers | Flag |
|---|---|---|
| OSV (api.osv.dev) | PyPI, npm, Maven, Go, crates.io, NuGet, RubyGems, Packagist, Hex, Pub; Debian, Ubuntu, Alpine OS packages; GitHub advisories; malicious-package (MAL-) reports | `--online` |
| OSV offline DB | the same, air-gapped | `--osv-db DIR` |
| NVD CVE API 2.0 | components with no package ecosystem, matched by CPE; scores for unscored CVEs | `--online --nvd` + `NVD_API_KEY` |
| CISA KEV | marks actively exploited CVEs, including ransomware use | default with `--online` / `--osv-db` (`--no-kev` to skip) |
| FIRST EPSS | exploit probability for each CVE | default with `--online` / `--osv-db` (`--no-epss` to skip) |

Accuracy safeguards:

* **Querying.** OS packages are queried by distro release and *source* package (`upstream=`),
  because that is how Debian, Ubuntu and Alpine key their advisories. Purl qualifiers are not sent.
* **Duplicates and bundles.** GHSA, PYSEC, DEBIAN-CVE and NVD records for the same CVE are merged,
  and the CVE becomes the primary ID. Bundled advisories (DSA, USN) listing several CVEs are never
  used to merge records; they are folded in only when every CVE they list is already tracked.
* **False positives.** An NVD hit is kept only if the version falls inside a *vulnerable* CPE range.
  This removes matches where the product appears only as a platform or in a different version line.
* **Withdrawn advisories** are dropped.
* **Scoring.** CVSS v3.x base scores are computed from vectors when a feed gives only the vector.
* **Upgrade advice** stays on the component's release line (Django 4.2.7 → 4.2.30, not 6.x).
* **Priority:**
  * P0: CISA KEV
  * P1: critical severity, EPSS ≥ 10%, or a malicious package
  * P2: high severity
  * P3: everything else

  VEX `not_affected` and `fixed` close a vulnerability.
* **Coverage gaps.** `validate` reports which components no source could match, with the reason.
  Add a `cpe` in `overrides.json` to close a gap:

  ```json
  { "components": { "openssl@3.0.1": { "cpe": "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*" } } }
  ```

  Find the right CPE at <https://nvd.nist.gov/products/cpe/search>.

## Privacy

`--online` sends package names and versions (not your source code) to api.osv.dev, pypi.org,
registry.npmjs.org, repo1.maven.org, crates.io, rubygems.org, api.deps.dev, endoflife.date,
cisa.gov and api.first.org. `--nvd` adds services.nvd.nist.gov. All of this is off by default.
For sensitive inventories, use the offline database (`--osv-db`) instead.
`cbom --tls` connects only to the endpoints you name. Private key files found during a scan are
reported by path; their contents are never written to the BOM.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `certin-bom: command not found` | Activate the venv (`source .venv/bin/activate`), or use `python3 -m certin_bom`. |
| `signing needs the 'cryptography' package` | `pip install -e '.[crypto]'` |
| NVD scan is very slow | No API key is set: `echo $NVD_API_KEY` should print it (see [NVD API key](#nvd-api-key)). |
| `NVD backfill limited to 40 of N unscored CVEs` | Same cause: set `NVD_API_KEY`. |
| `HTTP 403` from services.nvd.nist.gov | The key is wrong or not activated, or you are rate-limited. Wait 30 s and retry. |
| `ambiguous CPE vendor for X` in a report | Set the exact `cpe` for X in `overrides.json`. |
| `offline DB has no <Ecosystem> index` | `certin-bom vulndb update --dir vulndb --ecosystem <Ecosystem>` |
| Network errors behind a corporate proxy | `export HTTPS_PROXY=http://proxy.your-org:8080` before running. |
| Installation fails with a setuptools error | `pip install --upgrade pip setuptools`, then reinstall. |

## Limitations

* The CBOM source scan uses regular expressions. It shows *where* algorithms are referenced and
  can report false positives (for example, a string in a comment). Treat it as an inventory to
  confirm, not proof that an algorithm is in use.
* The Python `ssl` module does not expose the negotiated TLS key-exchange group, so classical
  ECDHE is assumed unless configured otherwise.
* Signatures canonicalise JSON with sorted keys and no whitespace. This matches RFC 8785 for the
  strings and integers that BOMs contain, but is not a full JCS implementation for every float.
* Version-range matching in offline mode uses a generic version comparator. Exact version lists
  are matched precisely; Debian/RPM epoch ordering edge cases may differ from the live API.
* SPDX is supported as input only; output is CycloneDX 1.6.

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
```

The tests mock all network calls, so they run offline in under a second.

---

This product uses the NVD API but is not endorsed or certified by the NVD.
