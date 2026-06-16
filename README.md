# VirtualSpace AppSec

[![Website](https://img.shields.io/badge/Website-virtualspacesec.com-2b59ff)](https://virtualspacesec.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**VirtualSpace AppSec** is a downloadable secure code review tool for Windows that runs **entirely on the user's own machine**. It combines Static Application Security Testing (SAST) with on-device, AI-assisted analysis to help individual developers and small teams find vulnerabilities in source code they own or are authorized to review - before that code ships to production, all without uploading any source code.

> **All analysis runs on the user's machine.** Source code, scan results, and analysis output never leave the device. The only network call the product makes is a lightweight license check.

This repository is a small public companion for the product. It links back to the storefront and documentation, and ships two short Python files of intentionally weak code that illustrate the kinds of patterns the scanner flags.

---

## About the product

- **Defensive only.** Built to defend, not to attack. Ships no exploit code, no payloads, and has no remote-execution capability. It never reaches out to or modifies any external system.
- **Source code only.** Analyzes C/C++, Python, JavaScript, and .NET source projects. It does not analyze, disassemble, decompile, or reverse-engineer compiled binaries, EXE/DLL files, or firmware.
- **Runs on your machine.** SAST rules, heuristics, taint and data-flow analysis, and the bundled AI model all run on the user's own Windows machine. There is no cloud scanner and no upload of customer code.
- **Authorized use only.** The product is for reviewing code you own or have explicit, documented authorization to analyze. This authorization requirement is reaffirmed in the Terms of Service.
- **One-time purchase.** Term licenses (for example, 7-day or 30-day) expire and require a manual repurchase. Lifetime licenses have no recurring fee. No subscriptions, no auto-renewal.
- **For individual developers and small teams.** Direct-to-consumer; there are no enterprise, reseller, or procurement plans, and no team seats, partner program, or volume discounts.

The product is operated by **Verse**, a Netherlands-registered business (KVK 88114171, BTW NL004542200B50). Pricing, documentation, EU consumer-rights information, and the full privacy policy live on the storefront.

## What the scanner detects

VirtualSpace AppSec maps findings to CWE and to widely-used rule sets, including:

- OWASP Top 10 (2025)
- CWE/SANS Top 25 (2025)
- PCI DSS v4.0.1 (secure-coding detection categories)
- NIST SP 800-218 (Secure Software Development Framework)
- OWASP LLM Top 10 (2025)

Example detection categories include memory-safety issues (use-after-free, buffer overflows), injection patterns (SQL, command, and others), insecure deserialization, weak cryptography, hardcoded secrets, SSRF and path-traversal patterns, authentication-bypass patterns, and supply-chain dependency risks. Each finding carries severity, a CWE classification, the offending source line, and a remediation recommendation, with SARIF 2.1.0 export for use in the developer's own local CI workflow, pre-commit hook, or developer tooling.

> No automated security tool can detect every vulnerability - findings are advisory. VirtualSpace AppSec is not a QSA, not an ASV scan, and not a compliance certificate.

## Sample vulnerable patterns in this repository

The two Python files in this repository exist purely as small, self-contained SAST fixtures. Each function is annotated with the specific CWE it illustrates and the safe alternative inline. They are not exploit code; they are deliberately weak example inputs that exist so a scanner has concrete patterns to detect.

There is no `__main__`, no network access, and no filesystem side effect on import. The files do nothing on their own.

**`Vuln-example.py`** - five distinct application-level weaknesses:

| Function | CWE | Pattern |
|---|---|---|
| `load_session_from_disk` | CWE-502 | Deserialization of untrusted data via `pickle.load` |
| `read_user_template` | CWE-22 | Path traversal via unchecked `os.path.join` |
| `find_user_by_email` | CWE-89 | SQL injection via f-string into `execute` |
| `archive_user_directory` | CWE-78 | OS command injection via `subprocess` with `shell=True` |
| `authenticate_admin` | CWE-798 | Hard-coded credentials |
| `hash_password_for_storage` | CWE-327 / CWE-916 | Single-round MD5 for password storage |

**`checksum_util.py`** - weak-integrity and timing-leak patterns, paired with the correct primitive:

| Function | CWE | Pattern |
|---|---|---|
| `fingerprint_md5`, `fingerprint_sha1` | CWE-327 / CWE-328 | Broken hash used as a security primitive |
| `crc32_authenticate` | CWE-353 / CWE-345 | CRC32 (a checksum, not a MAC) used for authenticity |
| `insecure_token_equals` | CWE-208 | Timing-unsafe `==` on a secret token |
| `mac_sign`, `mac_verify` | (reference) | The HMAC-SHA-256 + `hmac.compare_digest` pattern the above should have used |

## Links

- **Product website:** https://virtualspacesec.com
- **Features:** https://virtualspacesec.com/pages/features
- **Documentation:** https://virtualspacesec.com/pages/docs
- **Showcase:** https://virtualspacesec.com/pages/showcase
- **Support (only official channel):** support@virtualspacesec.com

## License

MIT - see [LICENSE](LICENSE).
