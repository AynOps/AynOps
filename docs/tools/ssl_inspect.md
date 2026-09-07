# `ssl_inspect`

## Overview

`ssl_inspect` opens a TLS connection to a domain, reads the peer certificate and
negotiated cipher, and returns a structured analysis covering certificate
validity, certificate issuer, Subject Alternative Names, TLS protocol version,
cipher strength, and an overall security rating. No API key is required.

## Purpose and common use cases

Use this tool to verify whether a domain's TLS configuration is healthy before
a deployment, during a security audit, or as part of a broader reconnaissance
run. Common tasks include checking certificate expiry, confirming TLS 1.3
support, detecting self-signed or wildcard certificates, and identifying weak
ciphers or deprecated protocol versions.

## Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `domain` | string | Yes | — | A fully qualified domain name to inspect. IP addresses, `localhost`, bare labels, and malformed domain names are rejected. |
| `port` | integer | No | `443` | The TCP port to connect to. Use a non-default value for services such as SMTPS (465) or IMAPS (993). |

Domain validation applies the same rules as `whois_lookup`: at least one dot,
labels of at most 63 characters, total length of at most 253 characters, a
final label of at least two ASCII letters, and no leading or trailing hyphens
on any label.

## Optional parameters

`port` defaults to `443` when omitted. The tool performs a direct TLS handshake
(`wrap_socket`), so the target port must speak TLS immediately on connect.
Common non-default values include `465` (SMTPS) and `993` (IMAPS). Ports that
require a plaintext negotiation step before upgrading to TLS (such as `587`
STARTTLS) are not supported and will fail at the handshake.

## Example MCP request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "ssl_inspect",
    "arguments": {
      "domain": "example.com"
    }
  }
}
```

With a non-default port:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "ssl_inspect",
    "arguments": {
      "domain": "mail.example.com",
      "port": 465
    }
  }
}
```

## Example successful response

The values below are illustrative.

```json
{
  "success": true,
  "domain": "example.com",
  "port": 443,
  "tls_version": "TLSv1.3",
  "cipher": {
    "name": "TLS_AES_256_GCM_SHA384",
    "protocol": "TLSv1.3",
    "bits": 256
  },
  "certificate": {
    "subject": {
      "commonName": "example.com"
    },
    "issuer": {
      "commonName": "R11",
      "organizationName": "Let's Encrypt",
      "countryName": "US"
    },
    "serial_number": "03A1B2C3D4E5F6",
    "not_before": "2025-01-01T00:00:00+00:00",
    "not_after": "2025-04-01T00:00:00+00:00",
    "days_until_expiry": 115,
    "expired": false,
    "expiring_soon": false,
    "subject_alt_names": [
      "example.com",
      "www.example.com"
    ],
    "version": 3
  },
  "wildcard_certificate": false,
  "self_signed": false,
  "public_key_type": "ECDSA",
  "san_count": 2,
  "validity_period_days": 90,
  "certificate_status": "Healthy",
  "tls_security": "Strong",
  "cipher_security": "Strong",
  "weak_tls_version": false,
  "weak_cipher": false,
  "security_rating": "Excellent",
  "certificate_extensions": {
    "ocsp_url": "http://r11.o.lencr.org",
    "ca_issuer_url": "http://r11.i.lencr.org/",
    "crl_distribution_points": []
  }
}
```

## Response field descriptions

### Top-level fields

| Field | Type | Description |
|---|---|---|
| `success` | boolean | `true` for a completed inspection. |
| `domain` | string | The normalized domain that was inspected. |
| `port` | integer | The TCP port that was used. |
| `tls_version` | string | Negotiated TLS protocol version, e.g. `"TLSv1.3"`. |
| `wildcard_certificate` | boolean | `true` if the Common Name or any SAN starts with `*.`. |
| `self_signed` | boolean | `true` if the Subject and Issuer RDN sequences are identical. |
| `public_key_type` | string or null | Key algorithm: `"RSA"`, `"ECDSA"`, `"DSA"`, `"Ed25519"`, `"Ed448"`, or the raw class name. `null` when the `cryptography` library is not installed. |
| `san_count` | integer | Number of `DNS` entries in the Subject Alternative Names extension. |
| `validity_period_days` | integer | Total validity window in days (`not_after` − `not_before`). |
| `certificate_status` | string | `"Healthy"`, `"Expiring Soon"` (≤ 30 days remaining), or `"Expired"`. |
| `tls_security` | string | `"Strong"` (TLS 1.3), `"Good"` (TLS 1.2), `"Weak"` (TLS 1.1 or older), or `"Unknown"`. Because the connection context enforces a minimum of TLS 1.2, `"Weak"` cannot appear in a successful response — a server that only supports TLS 1.1 or older will produce a connection error instead. |
| `cipher_security` | string | `"Strong"` (≥ 256-bit key and no weak pattern), `"Good"` (≥ 128-bit), `"Weak"` (known weak pattern or < 128-bit), or `"Unknown"`. |
| `weak_tls_version` | boolean | `true` when the negotiated TLS version is TLS 1.1 or older (deprecated by RFC 8996 / PCI-DSS). For the same reason as `tls_security`, this will always be `false` in a successful response. |
| `weak_cipher` | boolean | `true` when the cipher name contains a known weak indicator (RC4, 3DES, NULL, EXPORT, EXP, MD5, RC2, ADH, AECDH) or the key size is below 128 bits. |
| `security_rating` | string | Overall rating: `"Excellent"`, `"Good"`, `"Fair"`, or `"Poor"`. See [Security rating](#security-rating) for the scoring logic. |

### `cipher` object

| Field | Type | Description |
|---|---|---|
| `name` | string | OpenSSL cipher suite name, e.g. `"TLS_AES_256_GCM_SHA384"`. |
| `protocol` | string | Protocol string returned by the SSL layer. |
| `bits` | integer | Effective key length in bits. |

### `certificate` object

| Field | Type | Description |
|---|---|---|
| `subject` | object | Flat key/value map of the certificate Subject RDN (e.g. `commonName`, `organizationName`). |
| `issuer` | object | Flat key/value map of the certificate Issuer RDN. |
| `serial_number` | string or null | Certificate serial number as a hex string. |
| `not_before` | string | ISO 8601 UTC timestamp for the start of the validity window. |
| `not_after` | string | ISO 8601 UTC timestamp for the end of the validity window. |
| `days_until_expiry` | integer | Days remaining until expiry. Negative values mean the certificate has already expired. |
| `expired` | boolean | `true` when `days_until_expiry` is negative. |
| `expiring_soon` | boolean | `true` when `days_until_expiry` is between 0 and 30 inclusive. |
| `subject_alt_names` | list of strings | All `DNS` SAN entries from the certificate. |
| `version` | integer or null | X.509 version number (typically `3`). |

### `certificate_extensions` object

| Field | Type | Description |
|---|---|---|
| `ocsp_url` | string or null | First OCSP responder URL from the Authority Information Access extension. |
| `ca_issuer_url` | string or null | First CA Issuers URL from the Authority Information Access extension. |
| `crl_distribution_points` | list of strings | CRL Distribution Points URLs, or an empty list when absent. |

## Security rating

The overall `security_rating` is derived from four components (maximum score: 10):

| Component | Criteria | Points |
|---|---|---|
| TLS version | TLS 1.3 | 3 |
| TLS version | TLS 1.2 | 2 |
| TLS version | TLS 1.1 or older | 0 |
| Cipher strength | Strong (≥ 256-bit, no weak pattern) | 3 |
| Cipher strength | Good (≥ 128-bit, no weak pattern) | 2 |
| Cipher strength | Weak or Unknown | 0 |
| Certificate expiry | Healthy (> 30 days remaining) | 2 |
| Certificate expiry | Expiring Soon (0–30 days) | 1 |
| Certificate expiry | Expired | 0 |
| Validity period | ≤ 398 days (CA/B Forum maximum) | 2 |
| Validity period | ≤ 825 days (pre-2020 CA/B Forum maximum) | 1 |
| Validity period | > 825 days | 0 |

Score-to-rating mapping:

| Score | Rating |
|---|---|
| 9–10 | `"Excellent"` |
| 7–8 | `"Good"` |
| 4–6 | `"Fair"` |
| 0–3 | `"Poor"` |

**Hard fail:** an expired certificate, a weak TLS version (< TLS 1.2), or a
weak cipher always caps the rating at `"Poor"` regardless of the numeric score.

## Errors and timeouts

Failure responses contain `success: false` and an `error` string:

| Situation | `error` value |
|---|---|
| Input fails normalization or validation | `"Invalid domain format"` |
| Certificate verification failure (e.g. untrusted CA, hostname mismatch) | `"SSL verification failed: <detail>"` |
| TCP connection timeout (10-second limit) | `"Connection timed out"` |
| Any other exception | The underlying exception message |

The connection is attempted with a 10-second socket timeout. The TLS context
enforces a minimum version of TLS 1.2, so connections to servers that only
support TLS 1.1 or older will fail at the handshake level.

## Notes and limitations

- Before validation, the domain is normalized: surrounding whitespace is
  stripped, the value is lowercased, and trailing dots are removed.
- The tool connects to the live server; it needs outbound network access on the
  target port.
- `public_key_type` is `null` when the `cryptography` package is not
  installed. The package is pulled in transitively by the MCP stack, so it
  should normally be present.
- The connection context enforces TLS 1.2 as the minimum version. Servers that
  do not support TLS 1.2 will produce a connection error, not a `weak_tls`
  result.
- Subject and Issuer fields reflect whatever attributes the CA chose to
  include; uncommon RDN attributes may appear under their OID string rather
  than a human-readable key.
- `self_signed` detection compares raw RDN tuples. A certificate issued by an
  intermediate CA with the same distinguished name as the leaf would be
  incorrectly flagged; this is extremely rare in practice.

## API key requirements

None required.

## Related tools

`whois_lookup` provides registration metadata for the same domain.
`dns_enumeration` resolves the DNS records that the certificate SANs may
reference. `cert_transparency` queries CT logs for historical certificates
issued to the domain. `full_recon` combines `ssl_inspect` with the other core
tools into a single report. See the [tools index](README.md) for the current
registration inventory and documentation status.
