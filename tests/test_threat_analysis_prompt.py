"""Tests for the evidence-quality rules in the threat-analysis prompt.

The rules tell the model how to classify a signal the extractors handed it,
so they have to describe the same cutoff the extractors apply. A rule that
drifts from the code changes how findings are reported with nothing else in
the tree noticing.
"""
from tools.prompts.threat_analysis import THREAT_ANALYSIS_PROMPT


def _headers_evidence_rule():
    """The single evidence-quality bullet governing the headers scan."""
    rules = [
        line for line in THREAT_ANALYSIS_PROMPT.splitlines()
        if line.startswith("• IF the headers scan")
    ]
    assert len(rules) == 1, f"expected one headers evidence rule, found {len(rules)}"
    return rules[0]


def test_headers_evidence_rule_covers_every_case_the_extractor_suppresses():
    """headers_extractor writes no signal for a failed, blocked or non-2xx
    run, so the prompt must classify all three as insufficient data."""
    rule = _headers_evidence_rule()

    assert "failed" in rule
    assert "bot-detection/WAF challenge" in rule
    assert "4xx/5xx" in rule
    assert '"Insufficient data"' in rule
