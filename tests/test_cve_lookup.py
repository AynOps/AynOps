from unittest.mock import Mock, patch
import unittest
import requests
from packaging.version import Version
from tools.cve_tool import cve_lookup, _cve_affects_version


def _make_raw_cve(cve_id, cpe_matches, configurations=None, software="someproduct"):
    """Build a raw NVD vulnerability item with the given cpeMatch entries.

    If ``configurations`` is None (default), a single configuration/node is
    created wrapping ``cpe_matches``. Pass an explicit ``configurations`` value
    to override the structure entirely.

    Each cpeMatch entry receives a default ``criteria`` field matching
    ``software`` (CPE 2.3 vendor=product=software) when not supplied, so the
    criteria-validation step in ``_cve_affects_version`` passes by default.
    Tests that need a non-matching criteria can pass it explicitly.
    """
    enriched_matches = []
    for match in cpe_matches:
        m = dict(match)
        if "criteria" not in m:
            m["criteria"] = f"cpe:2.3:a:{software}:{software}:*:*:*:*:*:*:*:*"
        enriched_matches.append(m)

    cve = {
        "id": cve_id,
        "published": "2021-01-01T00:00:00.000",
        "lastModified": "2021-01-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
        "metrics": {
            "cvssMetricV31": [
                {"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}
            ]
        },
    }
    if configurations is not None:
        cve["configurations"] = configurations
    else:
        cve["configurations"] = [{"nodes": [{"cpeMatch": enriched_matches}]}]
    return {"cve": cve}


class TestCveLookup(unittest.TestCase):

    @patch("tools.cve_tool.requests.get")
    def test_cve_lookup_returns_nvd_results(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                _make_raw_cve(
                    "CVE-2021-41773",
                    [{
                        "vulnerable": True,
                        "versionStartIncluding": "2.4.49",
                        "versionEndIncluding": "2.4.50",
                    }],
                    software="apache",
                ),
            ],
        }
        mock_get.return_value = response

        result = cve_lookup("apache", "2.4.49")

        self.assertTrue(result["success"])
        self.assertEqual(result["software"], "apache")
        self.assertEqual(result["version"], "2.4.49")
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-2021-41773")
        self.assertEqual(result["cves"][0]["severity"], "HIGH")
        self.assertEqual(result["cves"][0]["score"], 7.5)
        self.assertTrue(result["version_filtering_applied"])
        mock_get.assert_called_once()

    @patch("tools.cve_tool.requests.get")
    def test_cve_lookup_empty_results(self, mock_get):
        response = Mock()
        response.json.return_value = {"totalResults": 0, "vulnerabilities": []}
        mock_get.return_value = response

        result = cve_lookup("unknownsoftware", "9.9.9")
        self.assertTrue(result["success"])
        self.assertEqual(result["total_results"], 0)
        self.assertEqual(result["cves"], [])
        # Stage 1 returned no results -> Stage 2 fires -> version filtering applied
        self.assertTrue(result["version_filtering_applied"])
        self.assertEqual(mock_get.call_count, 2)

    def test_cve_lookup_empty_software_rejected(self):
        result = cve_lookup("", "1.0")
        self.assertFalse(result["success"])
        self.assertIn("required", result["error"])

    def test_cve_lookup_empty_version_rejected(self):
        result = cve_lookup("apache", "")
        self.assertFalse(result["success"])

    def test_cve_lookup_whitespace_only_rejected(self):
        result = cve_lookup("   ", "   ")
        self.assertFalse(result["success"])

    @patch("tools.cve_tool.requests.get")
    def test_cve_lookup_multiple_cves(self, mock_get):
        cve_a = _make_raw_cve(
            "CVE-2021-00001",
            [{"vulnerable": True, "versionStartIncluding": "1.0.0", "versionEndIncluding": "2.0.0"}],
            software="nginx",
        )
        cve_b = _make_raw_cve(
            "CVE-2021-00002",
            [{"vulnerable": True, "versionStartIncluding": "1.0.0", "versionEndIncluding": "2.0.0"}],
            software="nginx",
        )
        response = Mock()
        response.json.return_value = {
            "totalResults": 2,
            "vulnerabilities": [cve_a, cve_b],
        }
        mock_get.return_value = response

        result = cve_lookup("nginx", "1.18")
        self.assertEqual(len(result["cves"]), 2)
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-2021-00001")

    @patch("tools.cve_tool.requests.get", side_effect=Exception("NVD unreachable"))
    def test_cve_lookup_exception_caught(self, _):
        result = cve_lookup("apache", "2.4")
        self.assertFalse(result["success"])
        self.assertIn("NVD unreachable", result["error"])

    # ------------------------------------------------------------------
    # Stage 1 / 2 multi-stage behavior with version filtering on both stages
    # ------------------------------------------------------------------

    @patch("tools.cve_tool.requests.get")
    def test_stage1_returns_filtered_results(self, mock_get):
        """Stage 1 results are now version-filtered before being returned."""
        response = Mock()
        response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                _make_raw_cve(
                    "CVE-2021-41773",
                    [{
                        "vulnerable": True,
                        "versionStartIncluding": "2.4.49",
                        "versionEndIncluding": "2.4.50",
                    }],
                    software="apache",
                ),
            ],
        }
        mock_get.return_value = response

        result = cve_lookup("apache", "2.4.49")

        self.assertTrue(result["success"])
        self.assertTrue(result["version_filtering_applied"])
        self.assertEqual(mock_get.call_count, 1)
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-2021-41773")

    @patch("tools.cve_tool.requests.get")
    def test_stage1_filters_out_non_matching_version(self, mock_get):
        """Stage 1 CVE whose version range excludes the target is filtered out,
        and the tool falls back to Stage 2."""
        stage1_response = Mock()
        stage1_response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                _make_raw_cve(
                    "CVE-2021-41773",
                    # Target 2.4.49 is below this range -> filtered out.
                    [{"vulnerable": True, "versionStartIncluding": "2.4.51", "versionEndIncluding": "2.4.52"}],
                    software="apache",
                ),
            ],
        }
        stage2_response = Mock()
        stage2_response.json.return_value = {"totalResults": 0, "vulnerabilities": []}
        mock_get.side_effect = [stage1_response, stage2_response]

        result = cve_lookup("apache", "2.4.49")

        self.assertTrue(result["success"])
        self.assertEqual(result["total_results"], 0)
        self.assertEqual(mock_get.call_count, 2)

    @patch("tools.cve_tool.requests.get")
    def test_stage2_falls_back_and_filters(self, mock_get):
        empty_response = Mock()
        empty_response.json.return_value = {"totalResults": 0, "vulnerabilities": []}

        cve_matching_1 = _make_raw_cve(
            "CVE-2020-0001",
            [{"vulnerable": True, "versionStartIncluding": "1.0.0", "versionEndIncluding": "2.0.0"}],
        )
        cve_matching_2 = _make_raw_cve(
            "CVE-2020-0002",
            [{"vulnerable": True, "versionStartIncluding": "1.5.0", "versionEndExcluding": "3.0.0"}],
        )
        cve_non_matching = _make_raw_cve(
            "CVE-2020-0003",
            [{"vulnerable": True, "versionStartIncluding": "5.0.0", "versionEndIncluding": "6.0.0"}],
        )
        data_response = Mock()
        data_response.json.return_value = {
            "totalResults": 3,
            "vulnerabilities": [cve_matching_1, cve_matching_2, cve_non_matching],
        }

        mock_get.side_effect = [empty_response, data_response]

        result = cve_lookup("someproduct", "1.5.0")

        self.assertTrue(result["success"])
        self.assertTrue(result["version_filtering_applied"])
        self.assertEqual(mock_get.call_count, 2)
        self.assertEqual(len(result["cves"]), 2)
        cve_ids = {c["cve_id"] for c in result["cves"]}
        self.assertEqual(cve_ids, {"CVE-2020-0001", "CVE-2020-0002"})

    @patch("tools.cve_tool.requests.get")
    def test_stage2_filters_out_non_matching_version(self, mock_get):
        empty_response = Mock()
        empty_response.json.return_value = {"totalResults": 0, "vulnerabilities": []}

        cve_1 = _make_raw_cve(
            "CVE-2020-0001",
            [{"vulnerable": True, "versionStartIncluding": "5.0.0", "versionEndIncluding": "6.0.0"}],
        )
        cve_2 = _make_raw_cve(
            "CVE-2020-0002",
            [{"vulnerable": True, "versionEndExcluding": "1.0.0"}],
        )
        data_response = Mock()
        data_response.json.return_value = {
            "totalResults": 2,
            "vulnerabilities": [cve_1, cve_2],
        }

        mock_get.side_effect = [empty_response, data_response]

        result = cve_lookup("someproduct", "2.5.0")

        self.assertTrue(result["success"])
        self.assertTrue(result["version_filtering_applied"])
        self.assertEqual(len(result["cves"]), 0)
        self.assertEqual(result["total_results"], 0)

    @patch("tools.cve_tool.requests.get")
    def test_cve_with_no_configurations_excluded_by_filter(self, mock_get):
        empty_response = Mock()
        empty_response.json.return_value = {"totalResults": 0, "vulnerabilities": []}

        cve_no_config = {
            "cve": {
                "id": "CVE-2020-0001",
                "published": "2021-01-01T00:00:00.000",
                "lastModified": "2021-01-01T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "metrics": {
                    "cvssMetricV31": [
                        {"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}
                    ]
                },
                # NOTE: no "configurations" key on purpose.
            }
        }
        data_response = Mock()
        data_response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [cve_no_config],
        }

        mock_get.side_effect = [empty_response, data_response]

        result = cve_lookup("someproduct", "1.0.0")

        self.assertTrue(result["success"])
        self.assertTrue(result["version_filtering_applied"])
        self.assertEqual(len(result["cves"]), 0)

    @patch("tools.cve_tool.requests.get")
    def test_invalid_version_returns_error_without_api_call(self, mock_get):
        """An unparseable target version now returns an explicit error before
        any NVD call is made, instead of fail-open returning all CVEs."""
        result = cve_lookup("someproduct", "abc")

        self.assertFalse(result["success"])
        self.assertIn("Invalid version format", result["error"])
        self.assertIn("abc", result["error"])
        mock_get.assert_not_called()

    # ------------------------------------------------------------------
    # Version-range filtering unit tests (target _cve_affects_version)
    # ------------------------------------------------------------------

    @staticmethod
    def _cve_with_single_match(match_kwargs, software="someproduct"):
        return {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [{
                                "vulnerable": True,
                                "criteria": f"cpe:2.3:a:{software}:{software}:*:*:*:*:*:*:*:*",
                                **match_kwargs,
                            }]
                        }
                    ]
                }
            ]
        }

    def test_version_start_including(self):
        cve = self._cve_with_single_match({"versionStartIncluding": "1.0.0"})
        self.assertTrue(_cve_affects_version(cve, Version("1.5.0"), "someproduct"))
        self.assertTrue(_cve_affects_version(cve, Version("1.0.0"), "someproduct"))  # boundary inclusive
        self.assertFalse(_cve_affects_version(cve, Version("0.9.9"), "someproduct"))

    def test_version_end_excluding(self):
        cve = self._cve_with_single_match({"versionEndExcluding": "2.0.0"})
        self.assertTrue(_cve_affects_version(cve, Version("1.9.9"), "someproduct"))
        self.assertFalse(_cve_affects_version(cve, Version("2.0.0"), "someproduct"))  # excluded boundary

    def test_non_vulnerable_cpe_match_ignored(self):
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:a:someproduct:someproduct:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "1.0.0",
                                    "versionEndIncluding": "2.0.0",
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        # Non-vulnerable matches are ignored, so 1.5.0 is not affected.
        self.assertFalse(_cve_affects_version(cve, Version("1.5.0"), "someproduct"))

    def test_version_start_excluding(self):
        cve = self._cve_with_single_match({"versionStartExcluding": "1.0.0"})
        self.assertTrue(_cve_affects_version(cve, Version("1.0.1"), "someproduct"))
        self.assertFalse(_cve_affects_version(cve, Version("1.0.0"), "someproduct"))  # excluded boundary

    def test_version_end_including(self):
        cve = self._cve_with_single_match({"versionEndIncluding": "2.0.0"})
        self.assertTrue(_cve_affects_version(cve, Version("2.0.0"), "someproduct"))  # included boundary
        self.assertFalse(_cve_affects_version(cve, Version("2.0.1"), "someproduct"))

    def test_cpe_match_with_no_constraints_does_not_match(self):
        # A vulnerable cpeMatch with no version constraints is no longer
        # treated as affecting every version. We cannot reliably determine
        # impact, so the CVE is excluded.
        cve = self._cve_with_single_match({})
        self.assertFalse(_cve_affects_version(cve, Version("1.5.0"), "someproduct"))
        self.assertFalse(_cve_affects_version(cve, Version("99.0.0"), "someproduct"))

    def test_invalid_constraint_version_skips_match(self):
        # An unparseable constraint version (e.g. "*") causes the cpeMatch
        # to be skipped, so the CVE is reported as not affecting the target.
        cve = self._cve_with_single_match({
            "versionStartIncluding": "*",
            "versionEndIncluding": "2.0.0",
        })
        self.assertFalse(_cve_affects_version(cve, Version("1.5.0"), "someproduct"))

    # ------------------------------------------------------------------
    # CPE criteria validation
    # ------------------------------------------------------------------

    def test_cpe_criteria_matching_product(self):
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [{
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0.0",
                                "versionEndIncluding": "2.0.0",
                            }]
                        }
                    ]
                }
            ]
        }
        self.assertTrue(_cve_affects_version(cve, Version("1.5.0"), "nginx"))

    def test_cpe_criteria_matching_vendor_when_product_differs(self):
        # e.g. software="apache" matches CPE vendor="apache", product="http_server"
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [{
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                                "versionStartIncluding": "2.4.49",
                                "versionEndIncluding": "2.4.50",
                            }]
                        }
                    ]
                }
            ]
        }
        self.assertTrue(_cve_affects_version(cve, Version("2.4.49"), "apache"))

    def test_cpe_criteria_not_matching_software_excluded(self):
        # CVE returned by a broad nginx search but the cpeMatch refers to
        # Debian Linux, not nginx. Must be excluded.
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [{
                                "vulnerable": True,
                                "criteria": "cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0.0",
                                "versionEndIncluding": "2.0.0",
                            }]
                        }
                    ]
                }
            ]
        }
        self.assertFalse(_cve_affects_version(cve, Version("1.5.0"), "nginx"))

    def test_cpe_criteria_with_wildcard_vendor_matches_any_software(self):
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [{
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:*:someproduct:1.0.0:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0.0",
                                "versionEndIncluding": "2.0.0",
                            }]
                        }
                    ]
                }
            ]
        }
        self.assertTrue(_cve_affects_version(cve, Version("1.5.0"), "someproduct"))

    # ------------------------------------------------------------------
    # Nested children configuration nodes
    # ------------------------------------------------------------------

    def test_nested_children_nodes_are_traversed(self):
        # NVD uses nested children[] nodes for AND/OR compositions.
        # A vulnerable cpeMatch buried in a child node must still match.
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "AND",
                            "children": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [{
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "1.0.0",
                                        "versionEndIncluding": "2.0.0",
                                    }],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        self.assertTrue(_cve_affects_version(cve, Version("1.5.0"), "nginx"))

    def test_nested_children_with_non_matching_criteria_excluded(self):
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "AND",
                            "children": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [{
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "1.0.0",
                                        "versionEndIncluding": "2.0.0",
                                    }],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        self.assertFalse(_cve_affects_version(cve, Version("1.5.0"), "nginx"))

    # ------------------------------------------------------------------
    # Integration: nginx false-positive scenario from the review
    # ------------------------------------------------------------------

    @patch("tools.cve_tool.requests.get")
    def test_nginx_false_positive_scenario_filtered_out(self, mock_get):
        """Reproduces the maintainer's reported scenario: a broad nginx search
        returns CVE-2009-2629 whose only nginx cpeMatch has no version
        constraints (plus a Debian OS cpeMatch). Both must be filtered out."""
        empty_response = Mock()
        empty_response.json.return_value = {"totalResults": 0, "vulnerabilities": []}

        cve = {
            "cve": {
                "id": "CVE-2009-2629",
                "published": "2009-07-01T00:00:00.000",
                "lastModified": "2018-10-12T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "nginx vulnerability"}],
                "metrics": {
                    "cvssMetricV31": [
                        {"baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}
                    ]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        # nginx cpeMatch with no version constraints.
                                        "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                                    },
                                    {
                                        "vulnerable": True,
                                        # Debian OS cpeMatch, no version constraints.
                                        "criteria": "cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*",
                                    },
                                ]
                            }
                        ]
                    }
                ],
            }
        }
        data_response = Mock()
        data_response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [cve],
        }

        mock_get.side_effect = [empty_response, data_response]

        result = cve_lookup("nginx", "1.24.0")

        self.assertTrue(result["success"])
        self.assertEqual(result["total_results"], 0)
        self.assertEqual(result["cves"], [])
        self.assertTrue(result["version_filtering_applied"])

    # ------------------------------------------------------------------
    # Error-path tests
    # ------------------------------------------------------------------

    @patch("tools.cve_tool.requests.get")
    def test_stage1_http_error_does_not_fall_through_to_stage2(self, mock_get):
        # If Stage 1 raises an HTTP error, Stage 2 must NOT fire.
        mock_get.side_effect = requests.exceptions.HTTPError("404 Client Error")
        result = cve_lookup("apache", "2.4.49")
        self.assertFalse(result["success"])
        self.assertIn("NVD API request failed", result["error"])
        self.assertEqual(mock_get.call_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
