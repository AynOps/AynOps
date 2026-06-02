import unittest
from tools.ssl_tool import ssl_inspect
from unittest.mock import MagicMock, patch
import ssl
import socket
from datetime import datetime, timedelta, timezone

class TestSslInspect(unittest.TestCase):

    def _make_cert(self, days_valid=365):
        now = datetime.now(timezone.utc)
        not_before = (now - timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT")
        not_after = (now + timedelta(days=days_valid)).strftime("%b %d %H:%M:%S %Y GMT")
        return {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "serialNumber": "DEADBEEF",
            "notBefore": not_before,
            "notAfter": not_after,
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
            "version": 3,
        }

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

if __name__ == "__main__":
    unittest.main(verbosity=2)