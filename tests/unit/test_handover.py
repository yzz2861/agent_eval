# -*- coding: utf-8 -*-

"""
Acceptance tests for the handover reconciliation layer, exercised
against a fictional inventory: the fictional vendor "acme" and its
fictional "routeros" device line are handed over from the parent
team "hq" to the subsidiary team "branch".
"""

from datetime import date
import unittest

from cpe.cpe import CPE
from cpe.handover import (
    Announcement,
    CPEScope,
    HandoverAgreement,
    InstallRecord,
    VersionChange,
    reconcile,
)

HQ = "hq"
BRANCH = "branch"

CUTOVER = date(2026, 3, 1)


def device_cpe(version):
    return CPE("cpe:2.3:h:acme:routeros:{0}:*:*:*:*:*:*:*".format(version))


def version_scope(pattern):
    return CPEScope([CPE(
        r'wfn:[part="h", vendor="acme", product="routeros", '
        r'version="{0}"]'.format(pattern))])


def all_routeros_scope():
    return CPEScope([CPE(
        'wfn:[part="h", vendor="acme", product="routeros"]')])


class FictionalInventory(object):
    """
    The fictional handover scenario:

    - AN-001 covers routeros 3.x, AN-002 covers 4.x, AN-003 5.x;
      all are originally owned by hq.
    - Agreement HO-2026-01 (cutover 2026-03-01) moves AN-001 and
      AN-003 for every routeros device installed up to the cutover.
    - hq believes it keeps the 4.x line, branch believes it holds
      the 3.x line plus the single 4.0 device; nobody lists 5.x.
    """

    def __init__(self):
        self.announcements = [
            Announcement("AN-001", version_scope(r"3\.*"), HQ),
            Announcement("AN-002", version_scope(r"4\.*"), HQ),
            Announcement("AN-003", version_scope(r"5\.*"), HQ),
        ]
        self.agreement = HandoverAgreement(
            "HO-2026-01", HQ, BRANCH, CUTOVER,
            all_routeros_scope(), ["AN-001", "AN-003"])
        self.retained_scopes = {
            HQ: version_scope(r"4\.*"),
            BRANCH: CPEScope([
                CPE(r'wfn:[part="h", vendor="acme", product="routeros", '
                    r'version="3\.*"]'),
                CPE(r'wfn:[part="h", vendor="acme", product="routeros", '
                    r'version="4\.0"]'),
            ]),
        }
        self.install_lists = {
            HQ: [
                InstallRecord("D-01", device_cpe("3.1"),
                              date(2026, 1, 10), HQ, "HQ-LIST#11"),
                InstallRecord("D-02", device_cpe("3.1"),
                              date(2026, 1, 12), HQ, "HQ-LIST#12"),
                InstallRecord("D-03", device_cpe("5.0"),
                              date(2026, 2, 1), HQ, "HQ-LIST#13"),
                InstallRecord("D-04", device_cpe("3.1"),
                              date(2026, 1, 20), HQ, "HQ-LIST#14"),
                InstallRecord("D-05", device_cpe("4.0"),
                              date(2026, 2, 10), HQ, "HQ-LIST#15"),
            ],
            # The subsidiary list is incomplete: it only holds the
            # devices it already inventoried itself.
            BRANCH: [
                InstallRecord("D-02", device_cpe("3.1"),
                              date(2026, 3, 5), BRANCH, "BR-LIST#02"),
                InstallRecord("D-06", device_cpe("3.2"),
                              date(2026, 5, 1), BRANCH, "BR-LIST#06"),
            ],
        }
        self.version_changes = [
            VersionChange("D-04", device_cpe("3.1"), device_cpe("4.2"),
                          date(2026, 4, 15), "CHG-77"),
        ]

    def reconcile(self):
        return reconcile(self.retained_scopes, self.install_lists,
                         self.announcements, [self.agreement],
                         self.version_changes)


class HandoverReconciliationTest(unittest.TestCase):

    def setUp(self):
        self.inventory = FictionalInventory()
        self.report = self.inventory.reconcile()

    def test_same_cpe_does_not_merge_devices(self):
        # D-02 appears in both installation lists with the same CPE;
        # the two sides' objects must stay distinct.
        keys = [key for key in self.report.device_entries
                if key[1] == "D-02"]
        self.assertEqual(sorted(keys), [(BRANCH, "D-02"), (HQ, "D-02")])
        entries = [self.report.device_entries[key] for key in keys]
        self.assertIsNot(entries[0], entries[1])
        self.assertEqual(str(entries[0].current_cpe),
                         str(entries[1].current_cpe))

    def test_transferred_assignment_follows_agreement(self):
        # D-01 runs 3.1, installed before the cutover: AN-001 moved
        # to the subsidiary by HO-2026-01.
        assignments = self.report.assignments_for(
            device_id="D-01", announcement_id="AN-001")
        self.assertEqual(len(assignments), 1)
        assignment = assignments[0]
        self.assertTrue(assignment.transferred)
        self.assertEqual(assignment.responsible_team, BRANCH)
        self.assertIn("agreement:HO-2026-01 cutover=2026-03-01",
                      assignment.evidence)
        self.assertIn("install:HQ-LIST#11", assignment.evidence)

    def test_installation_after_cutover_stays_with_original_team(self):
        # D-06 was installed after the signed cutover date, so the
        # agreement does not move AN-001 for it.
        assignments = self.report.assignments_for(
            device_id="D-06", announcement_id="AN-001")
        self.assertEqual(len(assignments), 1)
        self.assertFalse(assignments[0].transferred)
        self.assertEqual(assignments[0].responsible_team, HQ)

    def test_gap_when_both_teams_assume_the_other(self):
        # D-03 runs 5.0: the contract moved AN-003 to branch, but
        # branch's retained scope only lists 3.x/4.0 and hq dropped
        # everything but 4.x.  Both assume the other is responsible.
        self.assertEqual(len(self.report.gaps), 1)
        gap = self.report.gaps[0]
        self.assertEqual(gap.device_id, "D-03")
        self.assertEqual(gap.announcement_id, "AN-003")
        self.assertEqual(gap.claiming_teams, [])
        self.assertEqual(gap.assignment.responsible_team, BRANCH)

    def test_overlap_when_both_teams_claim(self):
        # D-05 runs 4.0, listed in both retained scopes.
        self.assertEqual(len(self.report.overlaps), 1)
        overlap = self.report.overlaps[0]
        self.assertEqual(overlap.assignment.device.device_id, "D-05")
        self.assertEqual(sorted(overlap.claiming_teams), [BRANCH, HQ])

    def test_version_change_is_traceable_to_announcement(self):
        # D-04 moved 3.1 -> 4.2 after the cutover.  AN-002 (4.x) now
        # applies, but HO-2026-01 never transferred it, so the duty
        # stays with hq and the trace shows no agreement.
        traces = [t for t in self.report.version_traces
                  if t.device.device_id == "D-04"]
        self.assertEqual(len(traces), 1)
        trace = traces[0]
        self.assertEqual(trace.announcement.announcement_id, "AN-002")
        self.assertTrue(trace.newly_covered)
        self.assertIsNone(trace.transferred_by)
        self.assertEqual(trace.responsible_team, HQ)
        self.assertIn("change:CHG-77", trace.evidence)
        self.assertIn("announcement:AN-002", trace.evidence)

        assignment = self.report.assignments_for(
            device_id="D-04", announcement_id="AN-002")[0]
        self.assertFalse(assignment.transferred)
        self.assertEqual(assignment.responsible_team, HQ)

    def test_incomplete_install_lists_still_reconcile(self):
        # branch only inventoried D-02 and D-06 itself, yet D-01 is
        # still reconciled from the parent list alone.
        self.assertEqual(
            self.report.assignments_for(device_id="D-01")[0]
            .device.source_team, HQ)

    def test_summary(self):
        self.assertEqual(self.report.summary()["gaps"], 1)
        self.assertEqual(self.report.summary()["overlaps"], 1)
        self.assertEqual(self.report.summary()["devices"], 7)


if __name__ == "__main__":
    unittest.main()
