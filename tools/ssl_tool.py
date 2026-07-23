import ssl
import socket
from datetime import datetime, timezone
from utils.helpers import is_valid_domain, normalize_domain

try:
    # cryptography is present via the MCP stack (fastmcp -> authlib ->
    # cryptography) but is not a direct requirement; degrade gracefully.
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False

# --- Security analysis thresholds (issue #100) ------------------------------
# Heuristics chosen for the analysis below; tune to taste.
EXPIRING_SOON_DAYS = 30             # cert is "Expiring Soon" within this window
MAX_PREFERRED_VALIDITY_DAYS = 398   # CA/B Forum maximum lifetime for public TLS certs
MAX_ACCEPTABLE_VALIDITY_DAYS = 825  # pre-2020 CA/B Forum maximum
MIN_CIPHER_BITS = 128               # below this a cipher is considered weak

# Well-known weak cipher indicators, per RFC 7457, NIST SP 800-131A and
# BSI TR-02102-2: RC4, 3DES/single-DES, NULL, EXPORT-grade, MD5 MACs, RC2
# and anonymous (unauthenticated) key exchange.
WEAK_CIPHER_PATTERNS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "EXP",
                        "MD5", "RC2", "ADH", "AECDH")

_TLS_VERSION_RANK = {
    "SSLv2": 0, "SSLv3": 1, "TLSv1": 2, "TLSv1.1": 3, "TLSv1.2": 4, "TLSv1.3": 5,
}


def _tls_version_rank(tls_version):
    return _TLS_VERSION_RANK.get(str(tls_version), -1)


def _is_weak_tls(tls_version):
    """TLS < 1.2 is weak (TLS 1.0/1.1 are deprecated by RFC 8996 / PCI-DSS)."""
    rank = _tls_version_rank(tls_version)
    return 0 <= rank < 4


def _classify_tls(tls_version):
    """Strong = TLS 1.3, Good = TLS 1.2, Weak = anything older."""
    rank = _tls_version_rank(tls_version)
    if rank >= 5:
        return "Strong"
    if rank == 4:
        return "Good"
    if rank >= 0:
        return "Weak"
    return "Unknown"


def _is_weak_cipher(cipher_name, cipher_bits):
    upper = str(cipher_name).upper()
    if any(pattern in upper for pattern in WEAK_CIPHER_PATTERNS):
        return True
    try:
        return cipher_bits is not None and int(cipher_bits) < MIN_CIPHER_BITS
    except (TypeError, ValueError):
        return False


def _classify_cipher(cipher_name, cipher_bits):
    """Weak if on the weak list or <128 bit; Strong >=256 bit; Good >=128 bit."""
    if _is_weak_cipher(cipher_name, cipher_bits):
        return "Weak"
    try:
        bits = int(cipher_bits)
    except (TypeError, ValueError):
        return "Unknown"
    return "Strong" if bits >= 256 else "Good"


def _certificate_status(days_left):
    if days_left < 0:
        return "Expired"
    if days_left <= EXPIRING_SOON_DAYS:
        return "Expiring Soon"
    return "Healthy"


def _security_rating(tls_version, cipher_name, cipher_bits, days_left, validity_days):
    """
    Overall rating from TLS version, cipher strength, expiry and validity.

    Scoring (max 10):
      TLS 1.3 = 3, TLS 1.2 = 2, older = 0
      cipher Strong = 3, Good = 2, Weak/Unknown = 0
      expiry Healthy = 2, Expiring Soon = 1, Expired = 0
      validity <=398d = 2, <=825d = 1, longer = 0 (shorter validity = better hygiene)

    Mapping: 9-10 Excellent, 7-8 Good, 4-6 Fair, 0-3 Poor.
    Hard fail: an expired certificate, a weak TLS version (<1.2) or a weak
    cipher caps the rating at "Poor" regardless of the score.
    """
    cipher_strength = _classify_cipher(cipher_name, cipher_bits)

    if days_left < 0 or _is_weak_tls(tls_version) or cipher_strength == "Weak":
        return "Poor"

    rank = _tls_version_rank(tls_version)
    score = 0
    score += 3 if rank >= 5 else 2 if rank == 4 else 0
    score += {"Strong": 3, "Good": 2}.get(cipher_strength, 0)
    score += 2 if days_left > EXPIRING_SOON_DAYS else 1
    if validity_days <= MAX_PREFERRED_VALIDITY_DAYS:
        score += 2
    elif validity_days <= MAX_ACCEPTABLE_VALIDITY_DAYS:
        score += 1

    if score >= 9:
        return "Excellent"
    if score >= 7:
        return "Good"
    if score >= 4:
        return "Fair"
    return "Poor"


def _public_key_type(conn):
    """Best-effort public key type from the DER certificate; None if unavailable."""
    if not _HAS_CRYPTOGRAPHY:
        return None
    try:
        der = conn.getpeercert(binary_form=True)
        key = x509.load_der_x509_certificate(der).public_key()
    except Exception:
        return None
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ECDSA"
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    return type(key).__name__


def ssl_inspect(domain: str, port: int = 443) -> dict:
    """
    Inspect SSL/TLS certificate details for a domain.
    Returns cert validity, issuer, SANs, expiry, and cipher info, plus the
    derived security analysis from issue #100: certificate fingerprinting
    (wildcard/self-signed/public key type/SAN count/validity period),
    certificate_status, TLS & cipher strength with weak flags, certificate
    extensions, and an overall security_rating. All derived fields come from
    data the connection already provides; no extra network I/O.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    try:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Create raw socket, wrap it, and manage the lifecycle of the wrapper
        raw_sock = socket.create_connection((domain, port), timeout=10)
        with context.wrap_socket(raw_sock, server_hostname=domain) as conn:
            cert = conn.getpeercert()
            cipher = conn.cipher()
            tls_version = conn.version()
            public_key_type = _public_key_type(conn)

        # Parse dates and make them timezone-aware (UTC)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days

        # Subject Alternative Names
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        def rdn(rdns):
            return {k: v for rdn in rdns for k, v in rdn}

        raw_subject = cert.get("subject", ())
        raw_issuer = cert.get("issuer", ())
        subject = rdn(raw_subject)
        issuer = rdn(raw_issuer)

        # --- issue #100: certificate fingerprinting ---
        common_name = subject.get("commonName", "")
        wildcard = common_name.startswith("*.") or any(s.startswith("*.") for s in sans)
        self_signed = bool(raw_subject) and raw_subject == raw_issuer
        validity_days = (not_after - not_before).days

        # --- issue #100: TLS & cipher security analysis ---
        weak_tls = _is_weak_tls(tls_version)
        weak_cipher = _is_weak_cipher(cipher[0], cipher[2])

        # --- issue #100: certificate extensions (already decoded by getpeercert) ---
        ocsp = cert.get("OCSP", ())
        ca_issuers = cert.get("caIssuers", ())

        return {
            "success": True,
            "domain": domain,
            "port": port,
            "tls_version": tls_version,
            "cipher": {
                "name": cipher[0],
                "protocol": cipher[1],
                "bits": cipher[2]
            },
            "certificate": {
                "subject": subject,
                "issuer": issuer,
                "serial_number": cert.get("serialNumber"),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_until_expiry": days_left,
                "expired": days_left < 0,
                "expiring_soon": 0 <= days_left <= 30,
                "subject_alt_names": sans,
                "version": cert.get("version")
            },
            # Certificate fingerprinting
            "wildcard_certificate": wildcard,
            "self_signed": self_signed,
            "public_key_type": public_key_type,
            "san_count": len(sans),
            "validity_period_days": validity_days,
            # Certificate status
            "certificate_status": _certificate_status(days_left),
            # TLS & cipher security
            "tls_security": _classify_tls(tls_version),
            "cipher_security": _classify_cipher(cipher[0], cipher[2]),
            "weak_tls_version": weak_tls,
            "weak_cipher": weak_cipher,
            # Overall rating + extensions
            "security_rating": _security_rating(tls_version, cipher[0], cipher[2], days_left, validity_days),
            "certificate_extensions": {
                "ocsp_url": ocsp[0] if ocsp else None,
                "ca_issuer_url": ca_issuers[0] if ca_issuers else None,
                "crl_distribution_points": list(cert.get("crlDistributionPoints", ()))
            }
        }

    except ssl.SSLCertVerificationError as e:
        return {"success": False, "error": f"SSL verification failed: {str(e)}"}
    except socket.timeout:
        return {"success": False, "error": "Connection timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}
