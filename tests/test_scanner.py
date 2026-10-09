"""
test_scanner.py — Tests for risk_engine and vulnerability_scanner (offline/unit)
Hyron AI · FUSION 2026 · CSB-03
"""

import pytest

from backend.services.risk_engine import compute_risk, tier_label


class TestComputeRisk:
    """Test the heuristic risk formula: 100 × (CVSS/10) × (0.2 + 0.8 × exploit) × runtime_factor"""

    def test_kev_production_max(self):
        """KEV-listed, high CVSS, production dep → near-max risk."""
        risk = compute_risk(cvss=9.8, cve="CVE-2021-TEST", is_dev=False,
                            epss_map={}, kev={"CVE-2021-TEST"})
        assert risk == pytest.approx(98.0, abs=0.5)

    def test_dev_only_reduced(self):
        """Dev-only dependency gets 0.4x runtime factor."""
        risk_prod = compute_risk(10.0, "CVE-X", False, {}, {"CVE-X"})
        risk_dev  = compute_risk(10.0, "CVE-X", True,  {}, {"CVE-X"})
        assert risk_dev == pytest.approx(risk_prod * 0.4, abs=0.5)

    def test_no_exploit_signal_minimum(self):
        """No KEV, no EPSS → 0.2 floor applied."""
        risk = compute_risk(cvss=10.0, cve="CVE-UNKNOWN", is_dev=False,
                            epss_map={}, kev=set())
        assert risk == pytest.approx(20.0, abs=0.5)  # 100 × 1.0 × 0.2 × 1.0

    def test_epss_signal(self):
        """EPSS 0.10 contributes correctly."""
        risk = compute_risk(cvss=7.5, cve="CVE-2022-EPSS", is_dev=True,
                            epss_map={"CVE-2022-EPSS": 0.10}, kev=set())
        expected = round(100 * (7.5/10) * (0.2 + 0.8 * 0.10) * 0.4, 1)
        assert risk == pytest.approx(expected, abs=0.1)

    def test_none_cve_no_kev_hit(self):
        """None CVE → no KEV match, no EPSS → floor score."""
        risk = compute_risk(cvss=5.0, cve=None, is_dev=False,
                            epss_map={}, kev={"CVE-2021-TEST"})
        assert risk == pytest.approx(10.0, abs=0.5)  # 100 × 0.5 × 0.2 × 1.0

    def test_kev_supersedes_epss(self):
        """KEV (1.0) should override EPSS (0.05)."""
        risk_kev  = compute_risk(9.0, "CVE-KEV", False, {"CVE-KEV": 0.05}, {"CVE-KEV"})
        risk_epss = compute_risk(9.0, "CVE-KEV", False, {"CVE-KEV": 0.05}, set())
        assert risk_kev > risk_epss


class TestTierLabel:
    def test_no_target_escalate(self):
        assert tier_label(99.0, None, False) == "ESCALATE"

    def test_major_jump_escalate(self):
        assert tier_label(10.0, "2.0.0", True) == "ESCALATE"

    def test_low_risk_auto(self):
        assert tier_label(5.0, "1.0.1", False) == "AUTO"

    def test_high_risk_review(self):
        assert tier_label(85.0, "1.2.3", False) == "REVIEW"
