import unittest
from unittest.mock import Mock, MagicMock, patch, call
from tools.portscan_tool import port_scan

class TestPortScan(unittest.TestCase):

    def _make_scanner_mock(self, host="93.184.216.34", open_ports=None, os_matches=None, elapsed="1.23", nmap_xml=None):
        open_ports = open_ports or {80: {"state": "open", "name": "http", "product": "nginx", "version": "1.18"}}
        scanner = MagicMock()
        scanner.all_hosts.return_value = [host]
        scanner[host].hostname.return_value = "example.com"
        scanner[host].state.return_value = "up"
        scanner[host].all_protocols.return_value = ["tcp"]
        scanner[host]["tcp"].items.return_value = open_ports.items()
        scanner[host].get.side_effect = lambda key, default=None: {
            "osmatch": os_matches or []
        }.get(key, default)
        scanner.scanstats.return_value = {"elapsed": elapsed}
        scanner.get_nmap_last_output.return_value = nmap_xml
        return scanner

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_basic_scan_success(self, mock_cls):
        mock_cls.return_value = self._make_scanner_mock()
        result = port_scan("example.com", "basic")

        self.assertTrue(result["success"])
        self.assertEqual(result["target"], "example.com")
        self.assertEqual(result["scan_type"], "basic")
        self.assertEqual(result["hosts_found"], 1)
        self.assertIn("results", result)

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_scan_uses_nmap_and_application_timeouts(self, mock_cls):
        scanner = self._make_scanner_mock()
        mock_cls.return_value = scanner

        result = port_scan("example.com", "service")

        self.assertTrue(result["success"])
        scanner.scan.assert_called_once_with(
            hosts="example.com",
            arguments="-sV -F --host-timeout 120s",
            timeout=130,
        )

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_full_scan_uses_bounded_host_timeout(self, mock_cls):
        scanner = self._make_scanner_mock()
        mock_cls.return_value = scanner

        port_scan("example.com", "full")
        scanner.scan.assert_called_once_with(
            hosts="example.com",
            arguments="-p- --host-timeout 15m",
            timeout=950,
        )

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_vuln_scan_uses_script_timeout_and_bounded_host_timeout(self, mock_cls):
        scanner = self._make_scanner_mock()
        mock_cls.return_value = scanner

        port_scan("example.com", "vuln")
        scanner.scan.assert_called_once_with(
            hosts="example.com",
            arguments="--script vuln -F --host-timeout 15m --script-timeout 5m",
            timeout=950,
        )

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_scan_includes_port_details(self, mock_cls):
        mock_cls.return_value = self._make_scanner_mock()
        result = port_scan("example.com")

        port_entry = result["results"][0]["protocols"]["tcp"][0]
        self.assertEqual(port_entry["port"], 80)
        self.assertEqual(port_entry["service"], "http")
        self.assertEqual(port_entry["product"], "nginx")

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_os_scan_includes_os_matches(self, mock_cls):
        os_matches = [
            {"name": "Linux 4.19 - 5.15", "accuracy": "98", "line": "52790", "osclass": []},
            {"name": "Linux 4.15", "accuracy": "94", "line": "52791", "osclass": []},
        ]
        mock_cls.return_value = self._make_scanner_mock(os_matches=os_matches)
        result = port_scan("scanme.nmap.org", "os")

        self.assertTrue(result["success"])
        host_result = result["results"][0]
        self.assertIn("os_matches", host_result)
        self.assertEqual(
            host_result["os_matches"],
            [
                {"name": "Linux 4.19 - 5.15", "accuracy": "98"},
                {"name": "Linux 4.15", "accuracy": "94"},
            ],
        )

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_scan_omits_os_matches_when_absent(self, mock_cls):
        mock_cls.return_value = self._make_scanner_mock(os_matches=[])
        result = port_scan("example.com", "basic")

        self.assertNotIn("os_matches", result["results"][0])

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_scan_includes_duration(self, mock_cls):
        mock_cls.return_value = self._make_scanner_mock(elapsed="12.34")
        result = port_scan("example.com", "basic")

        self.assertEqual(result["duration_seconds"], 12.34)

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_duration_defaults_to_none_when_scanstats_unavailable(self, mock_cls):
        scanner = self._make_scanner_mock()
        scanner.scanstats.side_effect = AssertionError("Do a scan before trying to get result !")
        mock_cls.return_value = scanner

        result = port_scan("example.com", "basic")

        self.assertTrue(result["success"])
        self.assertIsNone(result["duration_seconds"])

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_host_timeout_status_from_xml(self, mock_cls):
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="93.184.216.34" addrtype="ipv4"/>
            <status state="up"/>
          </host>
        </nmaprun>"""
        mock_cls.return_value = self._make_scanner_mock(nmap_xml=xml)
        result = port_scan("93.184.216.34", "basic")

        self.assertTrue(result["success"])
        self.assertEqual(result["host_timeout_status"], {"93.184.216.34": False})

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_host_timeout_status_true_when_timedout(self, mock_cls):
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host timedout="true">
            <address addr="93.184.216.34" addrtype="ipv4"/>
            <status state="up"/>
          </host>
        </nmaprun>"""
        mock_cls.return_value = self._make_scanner_mock(nmap_xml=xml)
        result = port_scan("93.184.216.34", "basic")

        self.assertTrue(result["success"])
        self.assertEqual(result["host_timeout_status"], {"93.184.216.34": True})

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_host_timeout_status_none_when_xml_unavailable(self, mock_cls):
        mock_cls.return_value = self._make_scanner_mock(nmap_xml=None)
        result = port_scan("example.com", "basic")

        self.assertTrue(result["success"])
        self.assertIsNone(result["host_timeout_status"])

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_host_timeout_status_none_when_xml_is_garbage(self, mock_cls):
        mock_cls.return_value = self._make_scanner_mock(nmap_xml="not xml at all")
        result = port_scan("example.com", "basic")

        self.assertTrue(result["success"])
        self.assertIsNone(result["host_timeout_status"])

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_host_timeout_status_none_when_get_last_output_raises(self, mock_cls):
        scanner = self._make_scanner_mock()
        scanner.get_nmap_last_output.side_effect = RuntimeError("nmap crashed")
        mock_cls.return_value = scanner

        result = port_scan("example.com", "basic")

        self.assertTrue(result["success"])
        self.assertIsNone(result["host_timeout_status"])

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_host_timeout_status_supports_ipv6(self, mock_cls):
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host timedout="true">
            <address addr="2606:4700::6810:84e5" addrtype="ipv6"/>
            <status state="up"/>
          </host>
        </nmaprun>"""
        mock_cls.return_value = self._make_scanner_mock(
            host="2606:4700::6810:84e5", nmap_xml=xml
        )
        result = port_scan("2606:4700::6810:84e5", "basic")

        self.assertTrue(result["success"])
        self.assertEqual(
            result["host_timeout_status"], {"2606:4700::6810:84e5": True}
        )

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_host_timeout_status_supports_multiple_hosts(self, mock_cls):
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host timedout="true">
            <address addr="93.184.216.34" addrtype="ipv4"/>
            <status state="up"/>
          </host>
          <host>
            <address addr="93.184.216.35" addrtype="ipv4"/>
            <status state="up"/>
          </host>
        </nmaprun>"""
        mock_cls.return_value = self._make_scanner_mock(
            host="93.184.216.34", nmap_xml=xml
        )
        result = port_scan("93.184.216.34", "basic")

        self.assertTrue(result["success"])
        self.assertEqual(
            result["host_timeout_status"],
            {"93.184.216.34": True, "93.184.216.35": False},
        )

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_osmatch_filters_incomplete_entries(self, mock_cls):
        os_matches = [
            {"name": "Linux 4.19 - 5.15", "accuracy": "98"},
            {"name": "Linux 4.15", "line": "52791"},
            {"line": "52792"},
            {},
        ]
        mock_cls.return_value = self._make_scanner_mock(os_matches=os_matches)
        result = port_scan("example.com", "os")

        self.assertEqual(
            result["results"][0]["os_matches"],
            [{"name": "Linux 4.19 - 5.15", "accuracy": "98"}],
        )

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_scan_no_hosts_found(self, mock_cls):
        scanner = MagicMock()
        scanner.all_hosts.return_value = []
        scanner.scanstats.return_value = {"elapsed": "0.50"}
        scanner.get_nmap_last_output.return_value = None
        mock_cls.return_value = scanner

        result = port_scan("192.0.2.1")
        self.assertTrue(result["success"])
        self.assertEqual(result["hosts_found"], 0)
        self.assertEqual(result["results"], [])

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_nmap_not_installed_error(self, mock_cls):
        import nmap
        mock_cls.return_value.scan.side_effect = nmap.PortScannerError("nmap not found")
        result = port_scan("example.com")

        self.assertFalse(result["success"])
        self.assertIn("Nmap not found", result["error"])

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_scan_timeout_returns_structured_error(self, mock_cls):
        import nmap
        timeout_exc = getattr(nmap, "PortScannerTimeout", TimeoutError)
        mock_cls.return_value.scan.side_effect = timeout_exc("timed out")

        result = port_scan("example.com")

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Port scan timed out")

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_invalid_scan_type_returns_error(self, mock_cls):
        result = port_scan("example.com", scan_type="invalid_type")

        self.assertFalse(result["success"])
        self.assertIn("Invalid scan_type", result["error"])
        self.assertEqual(
            result["valid_scan_types"],
            ["basic", "service", "os", "full", "vuln"],
        )
        mock_cls.assert_not_called()

if __name__ == "__main__":
    unittest.main(verbosity=2)
