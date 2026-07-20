import unittest
from tools.ssl_tool import ssl_inspect
from unittest.mock import MagicMock, patch
import ssl
import socket
from datetime import datetime, timedelta, timezone

try:
    from cryptography import x509 as cx509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

class TestSslInspect(unittest.TestCase):

    def _make_cert(self, days_valid=365, days_since_not_before=30, sans=None, extra=None):
        now = datetime.now(timezone.utc)
        not_before = (now - timedelta(days=days_since_not_before)).strftime("%b %d %H:%M:%S %Y GMT")
        not_after = (now + timedelta(days=days_valid)).strftime("%b %d %H:%M:%S %Y GMT")
        if sans is None:
            sans = (("DNS", "example.com"), ("DNS", "www.example.com"))
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "serialNumber": "DEADBEEF",
            "notBefore": not_before,
            "notAfter": not_after,
            "subjectAltName": sans,
            "version": 3,
        }
        if extra:
            cert.update(extra)
        return cert

    def _run_inspect(self, cert, cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
                     version="TLSv1.3", der_bytes=None):
        """Run ssl_inspect with the same mocking mechanism as the existing tests."""
        mock_ssl_sock = MagicMock()
        if der_bytes is not None:
            mock_ssl_sock.getpeercert.side_effect = (
                lambda binary_form=False: der_bytes if binary_form else cert
            )
        else:
            mock_ssl_sock.getpeercert.return_value = cert
        mock_ssl_sock.cipher.return_value = cipher
        mock_ssl_sock.version.return_value = version

        with patch("socket.create_connection") as mock_create_connection, \
             patch("tools.ssl_tool.ssl.create_default_context") as mock_ctx_cls:
            mock_create_connection.return_value = MagicMock()
            mock_ctx = MagicMock()
            # Direct context manager mocking for wrap_socket object
            mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
            mock_ctx_cls.return_value = mock_ctx
            return ssl_inspect("example.com")

    def test_invalid_domain(self):
        result = ssl_inspect("not-valid")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Invalid domain format")

    @patch("socket.create_connection")
    @patch("tools.ssl_tool.ssl.create_default_context")
    def test_ssl_success(self, mock_ctx_cls, mock_create_connection):
        cert = self._make_cert(days_valid=90)
        
        # mock raw socket
        mock_raw_socket = MagicMock()
        mock_create_connection.return_value = mock_raw_socket

        # mock the wrapped SSL context manager socket
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = cert
        mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_sock.version.return_value = "TLSv1.3"

        mock_ctx = MagicMock()
        # Direct context manager mocking for wrap_socket object
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_ctx_cls.return_value = mock_ctx

        result = ssl_inspect("example.com")

        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["tls_version"], "TLSv1.3")

    @patch("socket.create_connection")
    @patch("tools.ssl_tool.ssl.create_default_context")
    def test_ssl_expiry_flags(self, mock_ctx_cls, mock_create_connection):
        cert = self._make_cert(days_valid=10)
        
        mock_raw_socket = MagicMock()
        mock_create_connection.return_value = mock_raw_socket

        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = cert
        mock_ssl_sock.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
        mock_ssl_sock.version.return_value = "TLSv1.3"

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_ctx_cls.return_value = mock_ctx

        result = ssl_inspect("example.com")
        
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertTrue(result["certificate"]["expiring_soon"])
        self.assertFalse(result["certificate"]["expired"])

    @patch("socket.create_connection", side_effect=socket.timeout)
    @patch("tools.ssl_tool.ssl.create_default_context")
    def test_ssl_timeout(self, mock_ctx_cls, _):
        result = ssl_inspect("example.com")
        self.assertFalse(result["success"])
        self.assertIn("timed out", result["error"])

    @patch("socket.create_connection")
    @patch("tools.ssl_tool.ssl.create_default_context")
    def test_ssl_cert_verification_error(self, mock_ctx_cls, mock_create_connection):
        mock_raw_socket = MagicMock()
        mock_create_connection.return_value = mock_raw_socket

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("cert verify failed")
        mock_ctx_cls.return_value = mock_ctx

        result = ssl_inspect("example.com")
        self.assertFalse(result["success"])
        self.assertIn("SSL verification failed", result["error"])

    # --- issue #100: certificate fingerprinting ---

    def test_wildcard_certificate_and_san_count(self):
        cert = self._make_cert(sans=(
            ("DNS", "*.example.com"), ("DNS", "example.com"), ("DNS", "www.example.com"),
        ))
        result = self._run_inspect(cert)
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertTrue(result["wildcard_certificate"])
        self.assertFalse(result["self_signed"])
        self.assertEqual(result["san_count"], 3)

    def test_non_wildcard_certificate(self):
        result = self._run_inspect(self._make_cert())
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertFalse(result["wildcard_certificate"])
        self.assertEqual(result["san_count"], 2)

    def test_self_signed_certificate(self):
        cert = self._make_cert()
        cert["issuer"] = cert["subject"]  # issuer == subject => self-signed
        result = self._run_inspect(cert)
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertTrue(result["self_signed"])

    def test_validity_period_days(self):
        # not_before = now - 30d, not_after = now + 90d => validity ~= 120 days
        result = self._run_inspect(self._make_cert(days_valid=90))
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertLessEqual(abs(result["validity_period_days"] - 120), 1)

    # --- issue #100: certificate status ---

    def test_certificate_status_healthy(self):
        result = self._run_inspect(self._make_cert(days_valid=365))
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertEqual(result["certificate_status"], "Healthy")

    def test_certificate_status_expiring_soon(self):
        result = self._run_inspect(self._make_cert(days_valid=10))
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertEqual(result["certificate_status"], "Expiring Soon")

    def test_certificate_status_expired(self):
        result = self._run_inspect(self._make_cert(days_valid=-5))
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertEqual(result["certificate_status"], "Expired")
        self.assertTrue(result["certificate"]["expired"])
        # an expired certificate is a hard fail for the overall rating
        self.assertEqual(result["security_rating"], "Poor")

    # --- issue #100: TLS & cipher security analysis ---

    def test_strong_tls_and_cipher(self):
        result = self._run_inspect(
            self._make_cert(days_valid=365),
            cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            version="TLSv1.3",
        )
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertEqual(result["tls_security"], "Strong")
        self.assertEqual(result["cipher_security"], "Strong")
        self.assertFalse(result["weak_tls_version"])
        self.assertFalse(result["weak_cipher"])
        # mocked getpeercert returns a dict for binary_form=True, so the
        # public key type cannot be decoded and must degrade to None
        self.assertIsNone(result["public_key_type"])

    def test_weak_tls_and_weak_cipher(self):
        result = self._run_inspect(
            self._make_cert(days_valid=365),
            cipher=("RC4-MD5", "TLSv1", 128),
            version="TLSv1",
        )
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertEqual(result["tls_security"], "Weak")
        self.assertEqual(result["cipher_security"], "Weak")
        self.assertTrue(result["weak_tls_version"])
        self.assertTrue(result["weak_cipher"])
        self.assertEqual(result["security_rating"], "Poor")

    def test_weak_cipher_by_low_bits(self):
        result = self._run_inspect(
            self._make_cert(days_valid=365),
            cipher=("TLS_RSA_WITH_DES_CBC_SHA", "TLSv1.2", 56),
            version="TLSv1.2",
        )
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertTrue(result["weak_cipher"])
        self.assertEqual(result["cipher_security"], "Weak")
        self.assertEqual(result["security_rating"], "Poor")

    # --- issue #100: overall security rating ---

    def test_security_rating_excellent(self):
        # TLS 1.3 (3) + Strong cipher (3) + Healthy (2) + validity <=398d (2) = 10
        result = self._run_inspect(
            self._make_cert(days_valid=90),
            cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            version="TLSv1.3",
        )
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertEqual(result["security_rating"], "Excellent")

    def test_security_rating_good_boundary(self):
        # TLS 1.2 (2) + Good cipher (2) + Healthy (2) + validity <=398d (2) = 8 -> Good
        result = self._run_inspect(
            self._make_cert(days_valid=90),
            cipher=("TLS_AES_128_GCM_SHA256", "TLSv1.2", 128),
            version="TLSv1.2",
        )
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertEqual(result["tls_security"], "Good")
        self.assertEqual(result["cipher_security"], "Good")
        self.assertEqual(result["security_rating"], "Good")

    def test_security_rating_fair(self):
        # TLS 1.2 (2) + Good cipher (2) + Expiring Soon (1) + validity >825d (0) = 5 -> Fair
        cert = self._make_cert(days_valid=30, days_since_not_before=800)
        result = self._run_inspect(
            cert,
            cipher=("TLS_AES_128_GCM_SHA256", "TLSv1.2", 128),
            version="TLSv1.2",
        )
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertEqual(result["certificate_status"], "Expiring Soon")
        self.assertEqual(result["security_rating"], "Fair")

    # --- issue #100: public key type ---

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography package not installed")
    def test_public_key_type_ecdsa_and_rsa(self):
        now = datetime.now(timezone.utc)
        name = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "example.com")])

        def make_der(key):
            builder = (cx509.CertificateBuilder()
                       .subject_name(name)
                       .issuer_name(name)
                       .public_key(key.public_key())
                       .serial_number(1)
                       .not_valid_before(now - timedelta(days=1))
                       .not_valid_after(now + timedelta(days=30)))
            return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

        cert = self._make_cert(days_valid=365)

        ec_der = make_der(ec.generate_private_key(ec.SECP256R1()))
        result = self._run_inspect(cert, der_bytes=ec_der)
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertEqual(result["public_key_type"], "ECDSA")

        rsa_der = make_der(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        result = self._run_inspect(cert, der_bytes=rsa_der)
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        self.assertEqual(result["public_key_type"], "RSA")

    # --- issue #100: certificate extensions ---

    def test_certificate_extensions(self):
        cert = self._make_cert(extra={
            "OCSP": ("http://ocsp.example.com",),
            "caIssuers": ("http://ca.example.com/issuer.crt",),
            "crlDistributionPoints": ("http://crl.example.com/a.crl", "http://crl.example.com/b.crl"),
        })
        result = self._run_inspect(cert)
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        ext = result["certificate_extensions"]
        self.assertEqual(ext["ocsp_url"], "http://ocsp.example.com")
        self.assertEqual(ext["ca_issuer_url"], "http://ca.example.com/issuer.crt")
        self.assertEqual(ext["crl_distribution_points"],
                         ["http://crl.example.com/a.crl", "http://crl.example.com/b.crl"])

    def test_certificate_extensions_absent(self):
        result = self._run_inspect(self._make_cert())
        self.assertTrue(result["success"], f"Expected success but got error: {result.get('error')}")
        ext = result["certificate_extensions"]
        self.assertIsNone(ext["ocsp_url"])
        self.assertIsNone(ext["ca_issuer_url"])
        self.assertEqual(ext["crl_distribution_points"], [])

if __name__ == "__main__":
    unittest.main(verbosity=2)
