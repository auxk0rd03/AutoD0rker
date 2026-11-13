# AutoDorker Software Bill of Materials (SBOM)

- **Generated (UTC)**: `2026-11-13T04:47:30Z`
- **Project**: `AutoDorker v1.0.0` (CyberNest Holdings LLC - Labs Department)
- **Go Gateway (`cmd/gateway/`)**: Standard Library Only (zero third-party Go modules; `GOFIPS=1` / `GOFIPS140=v1.0.0`)

## Python Dependencies (`requirements.txt`)

| Package | Version |
| :--- | :--- |
| `python-docx` | `1.2.0` |
| `beautifulsoup4` | `4.15.0` |
| `lxml` | `6.1.3` |
| `pyyaml` | `6.0.3` |
| `esprima` | `4.0.1` |

## Rust Direct Dependencies (`crates/dork_spider/Cargo.toml`)

| Crate | Locked Version |
| :--- | :--- |
| `chrono` | `0.4.45` |
| `csv` | `1.4.0` |
| `rand` | `0.8.8` |
| `regex` | `1.13.1` |
| `rusqlite` | `0.32.1` |
| `scraper` | `0.21.0` |
| `serde` | `1.0.229` |
| `serde_json` | `1.0.154` |
| `sha2` | `0.10.9` |
| `ureq` | `2.12.1` |
| `url` | `2.5.8` |

## Vendored Assets & Rulebook SHA-256 Ledger

| Artifact | Version | SHA-256 |
| :--- | :--- | :--- |
| `htmx.min.js` | `2.0.4` | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` |
| `JetBrainsMono.woff2` | `2.304` | `a9cb1cd82332b23a47e3a1239d25d13c86d16c4220695e34b243effa999f45f2` |
| `synth-ledger.css` | `1.0.0` | `2981d1eb275ed4483838c0a2125511fb984cfdc8f7924bc26d51408194c33a31` |
| `autodorker-ui.js` | `1.0.0` | `26b46bca508a7aefa14352276fe116a52036475f804fb92f4ac0d244b025f443` |
| `DorkSet.csv` | `295-rules` | `bc236738984b8a2b474e12ff5ae4dd2e257aaaafc4ae8b2b7697d8b83d60c1e6` |
