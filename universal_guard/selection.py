"""Slice selection, evidence binding and coverage evaluation."""

from .models import (
    BoundEvidence,
    CoverageReport,
    DeploymentScope,
    ProtectionPolicy,
    Reason,
    ReasonCode,
    ReportChange,
    SliceAssessment,
    SliceDigest,
    SliceStatus,
    Terminal,
    TerminalAssessment,
    TerminalStatus,
    VerificationEvidence,
)
from .parsing import parse_artifact

SUBTYPE_MASK = 0x0FFFFFFF

# More specific subtypes must win over the generic ALL (0) slice.
_SUBTYPE_RANK = {0: 0, 1: 1, 2: 2, 3: 1, 4: 2, 8: 2}
ANY = "ANY"


def _masked(subtype):
    return subtype & SUBTYPE_MASK


def _rank(subtype):
    masked = _masked(subtype)
    return _SUBTYPE_RANK.get(masked, masked)


def subtype_compatible(slice_subtype, terminal_subtype):
    slice_st = _masked(slice_subtype)
    terminal_st = _masked(terminal_subtype)
    if slice_st == 0:
        return True
    return terminal_st >= slice_st



def select_slice(artifact, terminal):
    candidates = []
    rejections = []
    for slc in artifact.slices:
        if slc.cpu_type != terminal.cpu_type:
            rejections.append(
                Reason(
                    ReasonCode.CPU_TYPE_MISMATCH.value,
                    "slice %d cputype 0x%x cannot serve cputype 0x%x"
                    % (slc.index, slc.cpu_type, terminal.cpu_type),
                )
            )
            continue
        if not subtype_compatible(slc.cpu_subtype, terminal.cpu_subtype):
            rejections.append(
                Reason(
                    ReasonCode.CPU_SUBTYPE_INCOMPATIBLE.value,
                    "slice %d subtype %d exceeds terminal subtype %d"
                    % (
                        slc.index,
                        _masked(slc.cpu_subtype),
                        terminal.masked_subtype,
                    ),
                )
            )
            continue
        if slc.platform is None or slc.platform.platform != terminal.platform:
            rejections.append(
                Reason(
                    ReasonCode.PLATFORM_MISMATCH.value,
                    "slice %d platform does not match terminal platform %d"
                    % (slc.index, terminal.platform),
                )
            )
            continue
        if terminal.os_version < slc.platform.min_os:
            rejections.append(
                Reason(
                    ReasonCode.OS_VERSION_BELOW_MINIMUM.value,
                    "slice %d needs %s %s but terminal runs %s"
                    % (
                        slc.index,
                        slc.platform.platform_name,
                        slc.platform.min_os,
                        terminal.os_version,
                    ),
                )
            )
            continue
        candidates.append(slc)

    if not candidates:
        reasons = [
            Reason(
                ReasonCode.NO_SELECTABLE_SLICE.value,
                "no slice can be loaded by this terminal",
            )
        ] + rejections
        return None, reasons

    candidates.sort(key=lambda slc: (-_rank(slc.cpu_subtype), slc.index))
    return candidates[0], []



def _evidence_key(raw):
    return (
        ANY if raw.get("cpu_type") is None else raw["cpu_type"],
        ANY if raw.get("cpu_subtype") is None
        else _masked(raw["cpu_subtype"]),
        ANY if raw.get("platform") is None else raw["platform"],
    )


def _key_matches(key, slc):
    cpu_type, subtype, platform = key
    if cpu_type != ANY and cpu_type != slc.cpu_type:
        return False
    if subtype != ANY and subtype != _masked(slc.cpu_subtype):
        return False
    if platform != ANY and platform != (
        slc.platform.platform if slc.platform else None
    ):
        return False
    return True


def bind_evidence(slices, verifications):
    bound = {}
    unmatched = []
    for raw in verifications:
        evidence = VerificationEvidence.from_mapping(raw)
        claimed = SliceDigest(
            algorithm=evidence.digest_algorithm,
            value=evidence.digest_value,
        )
        targets = [
            slc for slc in slices if _key_matches(_evidence_key(raw), slc)
        ]
        if not targets:
            unmatched.append(
                Reason(
                    ReasonCode.EVIDENCE_ARCH_NOT_PRESENT.value,
                    "no slice matches evidence key %r" % (_evidence_key(raw),),
                )
            )
            continue
        any_match = False
        for slc in targets:
            observed = slc.digests.get(evidence.digest_algorithm)
            digest_ok = observed is not None and observed == claimed.value
            cdhash_ok = None
            if evidence.expected_cdhash is not None:
                cdhash_ok = (
                    slc.code_signature is not None
                    and slc.code_signature.cdhash
                    == evidence.expected_cdhash
                )
            bound[slc.index] = BoundEvidence(
                evidence=evidence,
                digest=claimed,
                digest_matches=digest_ok,
                cdhash_matches=cdhash_ok,
            )
            any_match = any_match or digest_ok
        if not any_match:
            unmatched.append(
                Reason(
                    ReasonCode.EVIDENCE_DIGEST_MISMATCH.value,
                    "evidence digest matches no current slice for key %r"
                    % (_evidence_key(raw),),
                )
            )
    return bound, unmatched



def _missing_attributes(slc, policy):
    missing = []
    attributes = slc.protection_attributes
    for name, required in policy.required_attributes.items():
        if required and not attributes.get(name):
            missing.append(name)
    return missing


def _evidence_sound(binding):
    return (
        binding is not None
        and binding.digest_matches
        and binding.cdhash_matches is not False
        and binding.evidence.verified
    )


def assess_slice(slc, bound, policy):
    reasons = []
    binding = bound.get(slc.index)

    if binding is None:
        reasons.append(
            Reason(
                ReasonCode.NO_EVIDENCE_FOR_SLICE.value,
                "caller supplied no verification result bound to this slice",
            )
        )
    else:
        if not binding.digest_matches:
            reasons.append(
                Reason(
                    ReasonCode.EVIDENCE_DIGEST_MISMATCH.value,
                    "bound evidence digest does not match the current slice",
                )
            )
        if binding.cdhash_matches is False:
            reasons.append(
                Reason(
                    ReasonCode.CDHASH_MISMATCH.value,
                    "CodeDirectory cdhash does not match the evidence claim",
                )
            )
        if binding.digest_matches and not binding.evidence.verified:
            reasons.append(
                Reason(
                    ReasonCode.SIGNATURE_VERIFICATION_FAILED.value,
                    "caller reports verification failure: %s"
                    % (binding.evidence.verifier_detail,),
                )
            )

    signature = slc.code_signature
    if signature is None or not signature.present:
        reasons.append(
            Reason(
                ReasonCode.NO_CODE_SIGNATURE.value,
                "slice has no LC_CODE_SIGNATURE command",
            )
        )
    elif not signature.has_code_directory:
        reasons.append(
            Reason(
                ReasonCode.NO_CODE_DIRECTORY.value,
                "signature blob lacks a CodeDirectory",
            )
        )
    elif (
        signature.encryption_info is not None
        and signature.encryption_info.get("cryptid", 0)
    ):
        reasons.append(
            Reason(
                ReasonCode.FAIRPLAY_ENCRYPTION_PRESENT.value,
                "slice is FairPlay encrypted (cryptid=%d)"
                % signature.encryption_info["cryptid"],
            )
        )

    missing = _missing_attributes(slc, policy)
    for name in missing:
        reasons.append(
            Reason(
                ReasonCode.PROTECTION_ATTRIBUTE_MISSING.value,
                "required protection attribute %r is absent" % name,
            )
        )

    evidence_codes = {
        ReasonCode.NO_EVIDENCE_FOR_SLICE.value,
        ReasonCode.EVIDENCE_DIGEST_MISMATCH.value,
        ReasonCode.CDHASH_MISMATCH.value,
        ReasonCode.SIGNATURE_VERIFICATION_FAILED.value,
        ReasonCode.NO_CODE_SIGNATURE.value,
        ReasonCode.NO_CODE_DIRECTORY.value,
    }
    has_evidence_failure = any(
        reason.code in evidence_codes for reason in reasons
    )
    if not has_evidence_failure and not missing:
        status = SliceStatus.COVERED
    elif _evidence_sound(binding):
        status = SliceStatus.AT_RISK
    else:
        status = SliceStatus.MISSING_EVIDENCE

    return SliceAssessment(
        slice_index=slc.index,
        status=status,
        reasons=reasons,
        evidence=binding,
        missing_attributes=missing,
    )



def _within_scope(slc, terminal, scope):
    if scope is None:
        return True
    if scope.platforms and slc.platform.platform not in scope.platforms:
        return False
    if scope.min_os is not None and terminal.os_version < scope.min_os:
        return False
    if scope.max_os is not None and terminal.os_version > scope.max_os:
        return False
    if scope.cpu_types and slc.cpu_type not in scope.cpu_types:
        return False
    return True


def assess_terminal(terminal, artifact, bound, policy, scopes):
    slc, reasons = select_slice(artifact, terminal)
    if slc is None:
        return TerminalAssessment(
            terminal_id=terminal.terminal_id,
            status=TerminalStatus.MISSING_EVIDENCE,
            slice_index=None,
            reasons=reasons,
        )

    scope = scopes.get(slc.index)
    if not _within_scope(slc, terminal, scope):
        return TerminalAssessment(
            terminal_id=terminal.terminal_id,
            status=TerminalStatus.MISSING_EVIDENCE,
            slice_index=slc.index,
            reasons=[
                Reason(
                    ReasonCode.DEPLOYMENT_SCOPE_EXCLUDED.value,
                    "slice %d is not allowed to serve this terminal"
                    % slc.index,
                )
            ],
        )

    slice_assessment = assess_slice(slc, bound, policy)
    status = {
        SliceStatus.COVERED: TerminalStatus.COVERED,
        SliceStatus.AT_RISK: TerminalStatus.AT_RISK,
        SliceStatus.MISSING_EVIDENCE: TerminalStatus.MISSING_EVIDENCE,
    }[slice_assessment.status]
    return TerminalAssessment(
        terminal_id=terminal.terminal_id,
        status=status,
        slice_index=slc.index,
        reasons=slice_assessment.reasons,
        slice_assessment=slice_assessment,
    )


def evaluate(
    source,
    terminals,
    verifications=None,
    policy=None,
    deployment_scopes=None,
):
    artifact = (
        source if hasattr(source, "slices") else parse_artifact(source)
    )
    policy = policy or ProtectionPolicy()
    verifications = verifications or []
    deployment_scopes = deployment_scopes or {}
    scopes = {}
    for index, scope in deployment_scopes.items():
        scopes[index] = (
            DeploymentScope.from_mapping(scope)
            if isinstance(scope, dict)
            else scope
        )

    bound, unmatched = bind_evidence(artifact.slices, verifications)
    slice_reports = {
        slc.index: assess_slice(slc, bound, policy)
        for slc in artifact.slices
    }
    terminal_reports = [
        assess_terminal(terminal, artifact, bound, policy, scopes)
        for terminal in terminals
    ]
    return CoverageReport(
        artifact=artifact,
        terminals=terminal_reports,
        slices=slice_reports,
        unmatched_evidence=unmatched,
        policy=policy,
    )


def diff_reports(before, after):
    before_map = {
        item.terminal_id: item for item in before.terminals
    }
    after_map = {
        item.terminal_id: item for item in after.terminals
    }
    changes = []
    for terminal_id in sorted(set(before_map) | set(after_map)):
        old = before_map.get(terminal_id)
        new = after_map.get(terminal_id)
        old_codes = [reason.code for reason in old.reasons] if old else []
        new_codes = [reason.code for reason in new.reasons] if new else []
        if (
            old is None
            or new is None
            or old.status != new.status
            or old.slice_index != new.slice_index
            or old_codes != new_codes
        ):
            changes.append(
                ReportChange(
                    terminal_id=terminal_id, before=old, after=new
                )
            )
    return changes


def explain_change(before, after):
    lines = []
    for change in diff_reports(before, after):
        if change.before is None:
            lines.append(
                "%s: added as %s"
                % (change.terminal_id, change.after.status.value)
            )
        elif change.after is None:
            lines.append(
                "%s: removed (was %s)"
                % (change.terminal_id, change.before.status.value)
            )
        else:
            lines.append(
                "%s: %s -> %s (slice %s -> %s)"
                % (
                    change.terminal_id,
                    change.before.status.value,
                    change.after.status.value,
                    change.before.slice_index,
                    change.after.slice_index,
                )
            )
    return lines
