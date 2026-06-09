# PeachSanitize

![PSScriptAnalyzer](https://img.shields.io/badge/PSScriptAnalyzer-0%20findings-brightgreen)
![Pester](https://img.shields.io/badge/Pester-76%2F76%20passing-brightgreen)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

A PowerShell module that strips sensitive data from JSON payloads before you paste them into AI tools like ChatGPT or Claude.

Runs entirely locally. No network calls. No cloud upload. One command.

```powershell
Install-Module PeachSanitize
'{"apiKey":"sk-a3f8c1e9d4b720e6f5a1","email":"alice@corp.com"}' | Invoke-JsonSanitize
```

---

## Install

```powershell
Install-Module PeachSanitize
Import-Module PeachSanitize
```

Requires PowerShell 5.1 or later (Windows PowerShell or PowerShell 7+). No external dependencies.

---

## Usage

**Sanitize a file and print to stdout:**

```powershell
Invoke-JsonSanitize -Path ./response.json
```

**Sanitize a string from the pipeline:**

```powershell
$json | Invoke-JsonSanitize
```

**Preview exactly what would be replaced — without changing anything:**

```powershell
Invoke-JsonSanitize -Path ./response.json -DryRun
```

```
KeyPath              DetectedType       OriginalValue                    ProposedReplacement
-------              ------------       -------------                    -------------------
apiKey               KeyNameMatch       sk-a3f8c1e9d4b720e6f5a19e7c      [REDACTED-KEYNAME-Xk9mP2qR...]
contact.email        Email              alice@corp.com                   morgan44@fakecorp.io
server.ip            IpAddress          10.40.2.55                       192.168.211.88
```

**Write sanitized output to a file:**

```powershell
Invoke-JsonSanitize -Path ./payload.json -OutFile ./payload.sanitized.json
```

**Pipe straight to clipboard (PowerShell 7):**

```powershell
Get-Content ./payload.json -Raw | Invoke-JsonSanitize | Set-Clipboard
```

---

## How it works

Detection runs in three layers, in priority order. The first layer that matches wins.

### Layer 1 — Key-name heuristic

Before looking at the value, the module checks whether the JSON key name contains any of these words (case-insensitive):

```
password  secret  token  key  apikey  api_key  auth  credential  private
```

If the key matches, the value is replaced regardless of what it looks like. This catches the most common MSP scenario — config dumps and API responses where the field name already tells you everything you need to know.

```json
{ "password": "N/A" }         → replaced  (key matched)
{ "clientSecret": "abc" }     → replaced  (key matched)
{ "status": "active" }        → unchanged (key is neutral)
```

### Layer 2 — Regex patterns

If the key is neutral, the value is run against a series of patterns:

| Type | How it's detected |
|---|---|
| JWT / Bearer token | Starts with `Bearer ` or `ey` (standard JWT header prefix) |
| Email address | Standard RFC-ish email format |
| URL with credentials | `scheme://user:pass@host` |
| IPv4 address | Four numeric octets |
| US phone number | `(xxx) xxx-xxxx`, `xxx-xxx-xxxx`, `+1xxxxxxxxxx` |
| Social Security Number | `xxx-xx-xxxx` |
| Credit card | 13–19 digits that pass a **Luhn checksum** |
| Hostname / FQDN | Multi-label domain like `server.corp.local` |

### Layer 3 — Shannon entropy (API key detection)

If nothing matched regex, the module calculates the Shannon entropy of the string — a measure of how random the characters are. A string that scores above **3.5** and is at least **20 characters long** is flagged as a probable API key or secret.

This catches credentials that don't match any known format: raw AWS secret keys, random UUIDs used as tokens, custom vendor keys, etc.

```
"sk-a3f8c1e9d4b720e6f5a19e7c"  → entropy 3.8  → flagged
"aaaaaaaaabbbbbbbbbbcccccccc"  → entropy 1.6  → not flagged
```

### Null, boolean, and numeric passthrough

Values that are `null`, `true`, `false`, or numbers are always passed through unchanged — there is nothing to sanitize in a boolean or a null.

---

## What gets detected

| Type | Example value |
|---|---|
| Email address | `alice@example.com` |
| API key / secret | `sk-abc123def456ghi789jkl0` |
| JWT token | `eyJhbGciOiJIUzI1NiJ9.payload.sig` |
| Bearer token | `Bearer eyJ...` |
| IPv4 address | `10.40.2.55` |
| URL with embedded credentials | `postgres://user:pass@host/db` |
| US phone number | `(212) 555-1234` |
| Social Security Number | `123-45-6789` |
| Credit card number | `4111111111111111` |
| Hostname / FQDN | `fileserver01.corp.contoso.local` |
| Any value whose key contains a sensitive word | `"clientSecret": "any-value"` |

---

## How replacements work

Replacements are designed to look plausible so the sanitized JSON still makes sense to an AI:

| Original | Replacement strategy | Example output |
|---|---|---|
| Email | Random name from a fake-name list + fake domain | `morgan44@fakecorp.io` |
| API key | Same length, same character class (hex/base64/alphanumeric) | `a7d2f9c1e4b830...` |
| JWT / Bearer | Fixed placeholder preserving rough length | `[REDACTED-TOKEN-a3f8c1e9]` |
| IP address | Random address in `192.168.x.x` | `192.168.44.201` |
| Phone | `(555) 000-xxxx` | `(555) 000-3847` |
| SSN | `000-00-xxxx` | `000-00-7312` |
| Credit card | Test card prefix + random suffix | `4111111111111849` |
| Credential URL | Credentials replaced, scheme and host preserved | `postgres://fakeuser:fakepass@host/db` |
| Hostname | Fixed placeholder with random suffix | `internal-host-q7r2xk.local` |
| Key-name match | REDACTED placeholder with 32-char random suffix | `[REDACTED-KEYNAME-Xk9mP2qR...]` |

Replacements are generated using `[System.Random]` seeded from a new GUID on each call — no two runs produce the same output.

---

## Edge cases

| Scenario | Behavior |
|---|---|
| Invalid JSON | Throws: `Input is not valid JSON. Verify with ConvertFrom-Json before running.` |
| File not found | Throws with the file path included in the message |
| File over 1 MB | Proceeds with a warning |
| Deeply nested JSON (5+ levels) | Sanitized recursively, no depth limit |
| Arrays at root level | Supported — each element is sanitized |
| Null values | Passed through unchanged |
| Boolean values | Passed through unchanged |
| Key matches sensitive pattern, value looks benign | Replaced anyway — key-name match takes priority |
| `-OutFile` path is read-only or inaccessible | Throws with the path in the error message |

---

## Why this exists

MSP and MSSP technicians paste JSON into AI tools every day — API responses, config files, ticket data, automation payloads. Those payloads routinely contain API keys, tokens, email addresses, and internal hostnames that should never leave the client environment.

The manual alternative — find-and-replace in a text editor — is slow, inconsistent, and easy to miss. This tool makes the safe path the fast path.

---

## The bigger picture

PeachSanitize is the manual, local version of what [Peach Security](https://peachsecurity.io) does automatically at the browser layer across all your clients — real-time DLP for every AI tool, enforced at the point of entry, without asking technicians to change their workflow.

If you want that protection running continuously instead of one command at a time, [peachsecurity.io](https://peachsecurity.io) is where to look.

---

---

## Running tests locally

Tests use [Pester 5](https://pester.dev). Install it once:

```powershell
Install-Module Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck -Scope CurrentUser
```

Run the full suite:

```powershell
Invoke-Pester ./Tests -Output Detailed
```

---

## Contributing

This tool is part of [Free Tools Friday](https://github.com/Peach-Security/FreeToolsFriday) — a weekly release of free MSP security tooling from Peach Security.

Bug reports and pull requests are welcome.

## License

MIT — see [LICENSE](LICENSE).
