# `email_security_check`

## Overview

`email_security_check` inspects a domain's SPF, DMARC, and DKIM DNS records and
returns a normalized anti-spoofing assessment with a score, rating, and
remediation recommendations. It does not require an API key.

## Purpose and common use cases

Use this tool to review the basic email-authentication posture of a domain:
whether SPF is published and how its terminal policy behaves, whether DMARC is
present and enforcing, whether a DMARC aggregate-reporting address is
configured, and whether a DKIM record can be found for one of the selectors the
tool probes.

This is useful during defensive reconnaissance, mail-domain hardening, and
pre-deployment checks for domains that send email.

## Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `domain` | string | Yes | A fully qualified domain name to inspect. Invalid domain names are rejected. |

The function lowercases and trims the input, then passes it through the shared
domain normalizer and validator before any DNS checks are made.

## Optional parameters

None.

## Example MCP request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "email_security_check",
    "arguments": {
      "domain": "example.com"
    }
  }
}
```

## Example successful response

The values below are illustrative. DKIM selector discovery is best-effort and
the exact selector list varies with the current year and the target domain's MX
provider.

```json
{
  "success": true,
  "domain": "example.com",
  "spf": {
    "found": true,
    "record": "v=spf1 include:_spf.example.net -all",
    "policy": "fail"
  },
  "dmarc": {
    "found": true,
    "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    "policy": "reject"
  },
  "dkim": {
    "found": true,
    "selectors_checked": [
      "default",
      "selector1",
      "2026"
    ],
    "found_selectors": [
      "selector1"
    ]
  },
  "security_score": "100%",
  "rating": "Excellent",
  "recommendations": []
}
```

## Response field descriptions

On a completed assessment, the response contains `success: true` and these
top-level fields:

| Field | Type | Description |
|---|---|---|
| `success` | boolean | `true` when validation succeeded and the assessment completed. Individual DNS checks can still be missing or unresolved. |
| `domain` | string | The normalized domain that was assessed. |
| `spf` | object | SPF presence, first matching SPF record, interpreted terminal policy, and no internal score field (the score is folded into `security_score`). |
| `dmarc` | object | DMARC presence, first matching DMARC record, interpreted `p=` policy, and no internal score field. |
| `dkim` | object | Whether at least one probed selector produced a DKIM-like TXT record, every selector checked, and the selectors that matched. |
| `security_score` | string | Combined score formatted as a percentage string, for example `"80%"`. |
| `rating` | string | `Excellent`, `Good`, `Fair`, or `Critical`. |
| `recommendations` | array of strings | Remediation messages produced by missing or weaker SPF/DMARC/DKIM findings. |

### SPF object

| Field | Type | Description |
|---|---|---|
| `found` | boolean | Whether a TXT record beginning with `v=spf1` was found. |
| `record` | string or null | The first matching SPF record. |
| `policy` | string or null | `fail` for `-all`, `softfail` for `~all`, `neutral` for `?all`, `pass` for `+all`, `unknown` when none of those mechanisms is present, or `null` when no SPF record was found. |

SPF contributes up to 30 points. A hard fail (`-all`) receives 30, softfail
receives 20, and neutral/pass receive 10. The implementation currently leaves
the default 30-point score in place for a found record whose terminal mechanism
is classified as `unknown`.

### DMARC object

| Field | Type | Description |
|---|---|---|
| `found` | boolean | Whether a TXT record beginning with `v=dmarc1` was found at `_dmarc.<domain>`. |
| `record` | string or null | The first matching DMARC record. |
| `policy` | string or null | The lowercased `p=` value, defaulting to `none` when the tag is absent, or `null` when DMARC is missing. |

DMARC contributes up to 35 points: `reject` gets 35, `quarantine` gets 25,
and other policies start at 10. Five points are deducted when the record does
not contain an `rua=` aggregate-reporting address.

### DKIM object

| Field | Type | Description |
|---|---|---|
| `found` | boolean | `true` when at least one probed selector returns a TXT record containing `v=dkim1` or `p=`. |
| `selectors_checked` | array of strings | The combined baseline and dynamically discovered selector candidates. |
| `found_selectors` | array of strings | Selector names whose TXT records matched the DKIM test. |

A successful DKIM probe contributes 35 points; no matching selector contributes
zero.

### Overall score and rating

The three component scores are added and returned as `security_score`.

| Score | Rating |
|---|---|
| 90–100 | `Excellent` |
| 70–89 | `Good` |
| 40–69 | `Fair` |
| 0–39 | `Critical` |

## Errors and timeouts

| Situation | Behavior |
|---|---|
| Domain validation fails | Returns `{"success": false, "error": "Invalid domain format"}`. |
| Initial TXT lookup raises `NXDOMAIN` or `NoAnswer` | Treated as an absent record rather than a tool-level failure. |
| Initial TXT lookup raises a resolver timeout or other DNS exception | Retries using `1.1.1.1` and `8.8.8.8`. |
| Fallback TXT lookup also fails | The check is treated as unresolved. SPF/DMARC add a timeout-style recommendation and zero points for that component. |
| An unexpected exception escapes the component checks | Returns `{"success": false, "error": "<exception message>"}`. |

TXT resolvers use a 2-second per-attempt timeout and a 4-second lifetime.
MX-based DKIM selector discovery uses a 3-second resolver lifetime and fails
open: if MX discovery fails, the baseline and time-derived selector candidates
are still checked.

## Notes and limitations

- DKIM detection is **best-effort**, not exhaustive. DKIM selectors cannot be
  discovered generically from DNS, so the tool probes a fixed baseline plus
  candidates derived from recent years and recognizable MX providers.
- Dynamic DKIM candidates include the current year and the previous three
  years, plus several month/date patterns. The exact `selectors_checked`
  output therefore changes over time.
- The selector collection is de-duplicated with a set before being converted
  back to a list, so selector ordering should not be treated as stable.
- MX discovery recognizes Google Workspace, Proofpoint, and Microsoft 365
  patterns and adds provider-oriented selector guesses.
- SPF and DMARC use only the first matching record returned by the TXT lookup.
- A `success: true` response means the assessment ran; it does not mean the
  domain is secure. Missing or weak controls are represented in the component
  objects, score, rating, and recommendations.
- The tool performs DNS lookups and therefore requires network access.
- The score is a project-specific heuristic, not a standards-compliance
  certificate or guarantee against spoofing.

## API key requirements

None required.

## Related tools

`dns_enumeration` provides the wider DNS view used during reconnaissance,
`whois_lookup` adds registration context, and `full_recon` combines this
email-security assessment with other core reconnaissance signals. See the
[tools index](README.md) for the current documentation inventory.
