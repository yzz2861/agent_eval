#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Handover reconciliation layer on top of CPE name matching.

This module reconciles remediation responsibility when a fleet of
devices is handed over from one team (e.g. a parent company) to
another (e.g. a subsidiary).  It answers three questions:

- Who is contractually responsible for remediating a given
  announcement on a given device, given the announced scope, the
  installation records and the cutover date both parties signed?
- Which announcement actually covers a device after a version
  change, and which handover agreement (if any) transferred it,
  so the decision can be traced back along the evidence?
- Which device/announcement pairs fell through the cracks, i.e.
  both teams assume the other one is responsible?

Device objects coming from the two parties' installation lists are
keyed by (source team, device id) and are never merged just because
they carry the same CPE name.
"""

from .cpe2_3_wfn import CPE2_3_WFN
from .cpeset2_3 import CPESet2_3


class CPEScope(object):
    """
    An ordered list of CPE 2.3 WFN patterns matched against concrete
    device CPE names through the CPE name matching algorithm.
    """

    def __init__(self, patterns=None):
        self._patterns = []
        for pattern in patterns or []:
            self.add(pattern)

    def add(self, pattern):
        """
        Adds a pattern to the scope.

        :param pattern: CPE Name of version 2.3 (any binding) usable
            as a matching pattern, e.g. with wildcards or ANY values
        :type pattern: CPE2_3
        :returns: None
        """

        self._patterns.append(CPE2_3_WFN(pattern.as_wfn()))

    def matches(self, cpe):
        """
        Returns True if the concrete CPE Name is covered by any
        pattern of the scope.

        :param CPE2_3 cpe: concrete CPE Name of a device
        :rtype: boolean
        """

        target = CPESet2_3()
        target.append(cpe)
        for pattern in self._patterns:
            if target.name_match(pattern):
                return True
        return False

    def __len__(self):
        return len(self._patterns)


class InstallRecord(object):
    """
    One entry of a party's installation list.  Lists may be
    incomplete; every record carries an evidence reference (e.g. a
    list or ticket number) so decisions can be traced back.
    """

    def __init__(self, device_id, cpe, installed_on, source_team, ref):
        self.device_id = device_id
        self.cpe = cpe
        self.installed_on = installed_on
        self.source_team = source_team
        self.ref = ref

    def __repr__(self):
        return "InstallRecord({0!r}, {1}, {2}, ref={3!r})".format(
            self.device_id, self.cpe, self.installed_on, self.ref)


class Announcement(object):
    """
    A remediation announcement with its actual announced scope and
    the team that originally owns the remediation duty.
    """

    def __init__(self, announcement_id, scope, owner_team,
                 issued_on=None, ref=None):
        self.announcement_id = announcement_id
        self.scope = scope
        self.owner_team = owner_team
        self.issued_on = issued_on
        self.ref = ref or announcement_id

    def covers(self, cpe):
        """
        Returns True if the concrete CPE Name is inside the actual
        announced scope.
        """

        return self.scope.matches(cpe)


class HandoverAgreement(object):
    """
    A handover agreement signed by both parties.  Only the
    announcements explicitly listed here move their remediation duty
    from ``from_team`` to ``to_team``, and only for devices inside
    the agreement scope that were installed on or before the signed
    cutover date.
    """

    def __init__(self, agreement_id, from_team, to_team, cutover_date,
                 scope, announcement_ids, ref=None):
        self.agreement_id = agreement_id
        self.from_team = from_team
        self.to_team = to_team
        self.cutover_date = cutover_date
        self.scope = scope
        self.announcement_ids = frozenset(announcement_ids)
        self.ref = ref or agreement_id


class VersionChange(object):
    """
    A recorded version change of a device, with an evidence
    reference so the change can be traced.
    """

    def __init__(self, device_id, from_cpe, to_cpe, changed_on, ref):
        self.device_id = device_id
        self.from_cpe = from_cpe
        self.to_cpe = to_cpe
        self.changed_on = changed_on
        self.ref = ref


class DeviceEntry(object):
    """
    A device as seen by one party.  The identity is the pair
    (source team, device id); two entries holding the same CPE name
    stay distinct objects.
    """

    def __init__(self, key, device_id, source_team):
        self.key = key
        self.device_id = device_id
        self.source_team = source_team
        self.install_records = []
        self.version_changes = []

    @property
    def current_cpe(self):
        """
        The CPE Name of the device according to the most recent
        evidence (latest installation record or version change).
        """

        events = [(record.installed_on, record.cpe)
                  for record in self.install_records]
        events.extend((change.changed_on, change.to_cpe)
                      for change in self.version_changes)
        if not events:
            return None
        events.sort(key=lambda event: event[0])
        return events[-1][1]

    @property
    def first_installed_on(self):
        dates = [record.installed_on for record in self.install_records]
        return min(dates) if dates else None

    def evidence_refs(self):
        refs = ["install:{0}".format(record.ref)
                for record in self.install_records]
        refs.extend("change:{0}".format(change.ref)
                    for change in self.version_changes)
        return refs


class Assignment(object):
    """
    The reconciled responsibility for one (device, announcement)
    pair, with the evidence the decision is based on.
    """

    def __init__(self, device, announcement, responsible_team,
                 transferred, agreement, evidence):
        self.device = device
        self.announcement = announcement
        self.responsible_team = responsible_team
        self.transferred = transferred
        self.agreement = agreement
        self.evidence = list(evidence)

    def __repr__(self):
        return ("Assignment(device={0!r}, announcement={1!r}, "
                "responsible={2!r}, transferred={3})").format(
                    self.device.key, self.announcement.announcement_id,
                    self.responsible_team, self.transferred)


class GapFinding(object):
    """
    A (device, announcement) pair no team claims: both teams assume
    the other one is responsible, so the remediation is being missed.
    """

    def __init__(self, assignment, claiming_teams):
        self.assignment = assignment
        self.claiming_teams = list(claiming_teams)

    @property
    def device_id(self):
        return self.assignment.device.device_id

    @property
    def announcement_id(self):
        return self.assignment.announcement.announcement_id

    def __repr__(self):
        return "GapFinding(device={0!r}, announcement={1!r})".format(
            self.device_id, self.announcement_id)


class OverlapFinding(object):
    """
    A (device, announcement) pair claimed by more than one team.
    """

    def __init__(self, assignment, claiming_teams):
        self.assignment = assignment
        self.claiming_teams = list(claiming_teams)


class VersionTrace(object):
    """
    Evidence chain for a version change: which announcements cover
    the device before and after the change, and which agreement (if
    any) transferred each of them.  ``transferred_by`` is None when
    no signed agreement covers the announcement for this device, so
    the duty stays with the original owner.
    """

    def __init__(self, device, change, announcement, newly_covered,
                 transferred_by, responsible_team, evidence):
        self.device = device
        self.change = change
        self.announcement = announcement
        self.newly_covered = newly_covered
        self.transferred_by = transferred_by
        self.responsible_team = responsible_team
        self.evidence = list(evidence)


class ReconciliationReport(object):
    """
    Result of a handover reconciliation.
    """

    def __init__(self):
        self.device_entries = {}
        self.assignments = []
        self.gaps = []
        self.overlaps = []
        self.version_traces = []

    def assignments_for(self, device_id=None, announcement_id=None):
        result = self.assignments
        if device_id is not None:
            result = [a for a in result
                      if a.device.device_id == device_id]
        if announcement_id is not None:
            result = [a for a in result
                      if a.announcement.announcement_id == announcement_id]
        return result

    def summary(self):
        return {
            "devices": len(self.device_entries),
            "assignments": len(self.assignments),
            "gaps": len(self.gaps),
            "overlaps": len(self.overlaps),
            "version_traces": len(self.version_traces),
        }


def _build_device_entries(install_lists, version_changes):
    """
    Builds the device ledger keyed by (source team, device id).
    Entries from different lists are never merged, even when they
    carry the same CPE name.
    """

    entries = {}
    for source_team, records in install_lists.items():
        for record in records:
            key = (source_team, record.device_id)
            entry = entries.get(key)
            if entry is None:
                entry = DeviceEntry(key, record.device_id, source_team)
                entries[key] = entry
            entry.install_records.append(record)

    for change in version_changes:
        # A version change is attached to every ledger entry of the
        # device; the lists are incomplete, so a change may be the
        # only evidence for a device on one side.
        matched = False
        for key, entry in entries.items():
            if entry.device_id == change.device_id:
                entry.version_changes.append(change)
                matched = True
        if not matched:
            key = (None, change.device_id)
            entry = DeviceEntry(key, change.device_id, None)
            entry.version_changes.append(change)
            entries[key] = entry

    return entries


def _find_transfer(agreements, announcement, entry):
    """
    Returns the agreement that transfers the announcement's duty for
    this device, or None.  A transfer requires all of:

    - the announcement is listed in the agreement,
    - the device's current CPE is inside the agreement scope,
    - the device was installed on or before the signed cutover date.
    """

    installed_on = entry.first_installed_on
    if installed_on is None:
        return None
    cpe = entry.current_cpe
    for agreement in agreements:
        if announcement.announcement_id not in agreement.announcement_ids:
            continue
        if installed_on > agreement.cutover_date:
            continue
        if not agreement.scope.matches(cpe):
            continue
        return agreement
    return None


def reconcile(retained_scopes, install_lists, announcements,
              agreements, version_changes=None):
    """
    Reconciles remediation responsibility across a handover.

    :param dict retained_scopes: team name -> CPEScope each team
        still claims as its own
    :param dict install_lists: team name -> list of InstallRecord
        (possibly incomplete)
    :param list announcements: Announcement objects with their
        actual announced scope
    :param list agreements: HandoverAgreement objects signed by
        both parties
    :param list version_changes: VersionChange objects (optional)
    :returns: ReconciliationReport
    """

    version_changes = version_changes or []
    report = ReconciliationReport()
    entries = _build_device_entries(install_lists, version_changes)
    report.device_entries = entries

    for key in sorted(entries, key=lambda k: (str(k[0]), k[1])):
        entry = entries[key]
        cpe = entry.current_cpe
        if cpe is None:
            continue

        claiming_teams = [team for team, scope in retained_scopes.items()
                          if scope.matches(cpe)]

        for announcement in announcements:
            if not announcement.covers(cpe):
                continue

            agreement = _find_transfer(agreements, announcement, entry)
            if agreement is not None:
                responsible = agreement.to_team
                evidence = entry.evidence_refs() + [
                    "announcement:{0}".format(announcement.ref),
                    "agreement:{0} cutover={1}".format(
                        agreement.ref, agreement.cutover_date),
                ]
                transferred = True
            else:
                responsible = announcement.owner_team
                evidence = entry.evidence_refs() + [
                    "announcement:{0}".format(announcement.ref),
                ]
                transferred = False

            assignment = Assignment(entry, announcement, responsible,
                                    transferred, agreement, evidence)
            report.assignments.append(assignment)

            if not claiming_teams:
                report.gaps.append(GapFinding(assignment, claiming_teams))
            elif len(claiming_teams) > 1:
                report.overlaps.append(
                    OverlapFinding(assignment, claiming_teams))

    for change in version_changes:
        for key, entry in entries.items():
            if change not in entry.version_changes:
                continue
            for announcement in announcements:
                if not announcement.covers(change.to_cpe):
                    continue
                newly_covered = not announcement.covers(change.from_cpe)
                agreement = _find_transfer(agreements, announcement, entry)
                responsible = (agreement.to_team if agreement is not None
                               else announcement.owner_team)
                evidence = ["change:{0}".format(change.ref),
                            "announcement:{0}".format(announcement.ref)]
                if agreement is not None:
                    evidence.append(
                        "agreement:{0} cutover={1}".format(
                            agreement.ref, agreement.cutover_date))
                report.version_traces.append(VersionTrace(
                    entry, change, announcement, newly_covered,
                    agreement, responsible, evidence))

    return report
