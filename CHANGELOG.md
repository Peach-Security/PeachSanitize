# Changelog

All notable changes to PeachSanitize are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-06-07

### Added

- `Invoke-JsonSanitize` — main exported function with `-Path`, pipeline, `-DryRun`, and `-OutFile` support
- Detection for: email addresses, high-entropy strings (API keys/tokens), JWT and Bearer tokens, IPv4 addresses, URLs with embedded credentials, US phone numbers, SSNs, Luhn-validated credit card numbers, internal hostnames/FQDNs, and key-name heuristics
- Shannon entropy calculation for API key detection (threshold: H > 3.5, length ≥ 20)
- Luhn checksum validation for credit card detection
- Realistic fake replacement values: matching character class and length for API keys, 555-prefix phones, 000-00-xxxx SSNs, 192.168.x.x IPs, fake-domain emails
- Recursive JSON tree walker — handles arbitrary nesting depth and root-level arrays
- `-DryRun` mode outputs a `Format-Table` preview of all replacements without modifying the payload
- `-OutFile` writes sanitized JSON to disk with proper error handling for access-denied and IO failures
- Large file warning (> 1 MB) — proceeds after warning
- Pester 5 test suite covering all detection types, replacement strategies, and end-to-end scenarios
- PSScriptAnalyzer-clean — zero warnings on all `.ps1` files
- Requires PowerShell 5.1+; tested on PowerShell 7 (Windows)
