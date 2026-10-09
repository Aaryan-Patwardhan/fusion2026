"""
test_graph.py — Tests for patch_planner and dependency_graph utilities
Hyron AI · FUSION 2026 · CSB-03
"""

import pytest

from backend.services.patch_planner import pick_fix, build_patch_plan


class TestPickFix:
    def test_same_major_preferred(self):
        target, major = pick_fix("1.0.0", ["1.2.0", "2.0.0"])
        assert target == "1.2.0"
        assert major is False

    def test_major_jump_when_no_same(self):
        target, major = pick_fix("1.9.9", ["2.0.0", "3.0.0"])
        assert target == "2.0.0"
        assert major is True

    def test_no_fix_above_current(self):
        target, major = pick_fix("5.0.0", ["1.0.0", "4.9.9"])
        assert target is None
        assert major is False

    def test_empty_fixed_list(self):
        target, major = pick_fix("1.0.0", [])
        assert target is None
        assert major is False

    def test_prefers_smallest_above_current(self):
        target, major = pick_fix("1.0.0", ["1.0.1", "1.2.0", "1.99.0"])
        assert target == "1.0.1"
        assert major is False

    def test_invalid_current_version(self):
        target, major = pick_fix("not-a-version", ["1.0.0"])
        assert target is None

    def test_zero_x_minor_as_major_jump(self):
        """0.x minor bumps treated carefully."""
        target, major = pick_fix("0.1.0", ["0.2.0"])
        # Same major (0), so not flagged as major jump
        assert major is False
        assert target == "0.2.0"


class TestBuildPatchPlan:
    """Integration-style test for the patch plan builder."""

    FINDINGS = [
        {
            "project": "app-01",
            "package": "lodash@4.17.15",
            "vuln": "GHSA-xxxx-yyyy-zzzz",
            "cve": "CVE-2021-23337",
            "direct": True,
            "via": "lodash@4.17.15",
            "fixed": ["4.17.21"],
            "risk": 75.0,
        },
        {
            "project": "app-01",
            "package": "lodash@4.17.15",
            "vuln": "GHSA-aaaa-bbbb-cccc",
            "cve": "CVE-2020-8203",
            "direct": True,
            "via": "lodash@4.17.15",
            "fixed": ["4.17.19"],
            "risk": 40.0,
        },
        {
            "project": "app-02",
            "package": "minimist@1.2.0",
            "vuln": "GHSA-xvch-5gv4-984h",
            "cve": "CVE-2020-7598",
            "direct": False,
            "via": "mocha@7.0.0 > minimist@1.2.0",
            "fixed": [],
            "risk": 30.0,
        },
    ]

    def test_returns_list(self):
        plan = build_patch_plan(self.FINDINGS)
        assert isinstance(plan, list)

    def test_sorted_by_risk_removed(self):
        plan = build_patch_plan(self.FINDINGS)
        risks = [p["risk_removed"] for p in plan]
        assert risks == sorted(risks, reverse=True)

    def test_order_numbers_sequential(self):
        plan = build_patch_plan(self.FINDINGS)
        orders = [p["order"] for p in plan]
        assert orders == list(range(1, len(plan) + 1))

    def test_vulns_aggregated(self):
        plan = build_patch_plan(self.FINDINGS)
        lodash = next(p for p in plan if p["package"] == "lodash")
        assert len(lodash["vulns"]) == 2

    def test_no_fix_escalate(self):
        plan = build_patch_plan(self.FINDINGS)
        minimist = next(p for p in plan if p["package"] == "minimist")
        assert minimist["tier"] == "ESCALATE"
        assert minimist["target"] is None

    def test_fix_available_action(self):
        plan = build_patch_plan(self.FINDINGS)
        lodash = next(p for p in plan if p["package"] == "lodash")
        assert "4.17.21" in lodash["action"]

    def test_highest_fix_chosen(self):
        """When two vulns have different fixed versions, choose the highest."""
        plan = build_patch_plan(self.FINDINGS)
        lodash = next(p for p in plan if p["package"] == "lodash")
        assert lodash["target"] == "4.17.21"
