"""
Read-only preview of merged Mach-O dependency rewrites.

The packaging team used to apply administrator-approved rewrites one at a
time.  This module lets them review a *merged* plan before macholib performs
any actual writes: for every file, every slice and every relevant load
command it derives what the merged plan would do, which approved rule is
responsible, and which items are no longer covered by an individual approval
and therefore need to be approved again.

Nothing in this module ever opens a file for writing.  Existing callers that
do not opt into the preview are unaffected: the merged plan is expressed as
an ordinary ``changefunc`` (see :func:`merge_changefuncs`) that can be handed
to :meth:`macholib.MachO.MachO.rewriteLoadCommands` exactly like before.
"""

from __future__ import print_function

import sys
from collections import OrderedDict

from macholib.MachO import MachO, lc_str_value

if sys.version_info[0] == 2:
    text_type = unicode  # noqa: F821
else:
    text_type = str

__all__ = [
    "RewriteRule",
    "merge_changefuncs",
    "preview_package",
    "PreviewReport",
    "FilePreview",
    "SlicePreview",
    "CommandPreview",
]

_CPU_TYPE_NAMES = {
    0x1000007: "x86_64",
    0x100000C: "arm64",
    0x0C: "arm",
    0x07: "i386",
}


class RewriteRule(object):
    """
    One administrator-approved dependency rewrite.

    ``changefunc`` follows the exact protocol macholib uses when rewriting:
    it is called with a path (the on-disk filename for the install name
    command, or the current value of a relocatable load command) and returns
    the replacement value, or None to leave the command untouched.
    """

    def __init__(self, name, changefunc, approved=True):
        self.name = name
        self.changefunc = changefunc
        self.approved = approved

    def __repr__(self):
        return "<RewriteRule %r approved=%r>" % (self.name, self.approved)


def _apply_rules(rules, value):
    """
    Apply *rules* in order to *value*.  Returns ``(new_value, contributors)``
    where *contributors* lists the names of the rules that fired.
    """
    current = value
    contributors = []
    for rule in rules:
        new_value = rule.changefunc(current)
        if new_value is not None:
            current = new_value
            contributors.append(rule.name)
    return current, contributors


def merge_changefuncs(rules):
    """
    Chain the changefuncs of *rules* into a single changefunc suitable for
    :meth:`macholib.MachO.MachO.rewriteLoadCommands`.

    Each rule sees the output of the previous rules, so a command that no
    rule touches individually may still be reinterpreted once another rule
    rewrote its input.  Returns None when no rule fires, exactly like an
    ordinary macholib changefunc.
    """

    def changefunc(path):
        new_value, contributors = _apply_rules(rules, path)
        if contributors:
            return new_value
        return None

    return changefunc


class CommandPreview(object):
    """
    Preview of a single load command in a single slice.

    Attributes:
      - index:        index of the load command in the slice
      - kind:         "install_name" or the relocatable command name
      - original:     current value stored in the file
      - solo:         rule name -> value if only that rule were applied
      - merged:       value produced by the merged plan
      - contributors: rules that fired (in order) in the merged plan
      - attribution_before/after: install-name identity this command will
        bind to before/after the merged plan (relocatable commands only)
      - reasons:      why this command needs to be approved again
    """

    def __init__(self, index, kind, original):
        self.index = index
        self.kind = kind
        self.original = original
        self.solo = OrderedDict()
        self.merged = original
        self.contributors = []
        self.attribution_before = None
        self.attribution_after = None
        self.reasons = []

    @property
    def changed(self):
        return self.merged != self.original

    @property
    def attribution_changed(self):
        return self.attribution_before != self.attribution_after

    @property
    def needs_approval(self):
        return bool(self.reasons)

    @property
    def status(self):
        if self.needs_approval:
            return "needs-approval"
        if self.changed or self.attribution_changed:
            return "approved"
        return "unchanged"

    def __repr__(self):
        return "<CommandPreview #%d %s %r -> %r (%s)>" % (
            self.index,
            self.kind,
            self.original,
            self.merged,
            self.status,
        )


class SlicePreview(object):
    """Preview of one slice (Mach-O header) of a file."""

    def __init__(self, index, header):
        self.index = index
        self.header = header
        self.commands = []
        self.id_command = None

    @property
    def arch(self):
        cputype = self.header.header.cputype
        return _CPU_TYPE_NAMES.get(cputype, "cpu=%d" % (cputype,))

    @property
    def install_name(self):
        if self.id_command is None:
            return None
        return self.id_command.original

    @property
    def merged_install_name(self):
        if self.id_command is None:
            return None
        return self.id_command.merged

    @property
    def needs_approval(self):
        return [cmd for cmd in self.commands if cmd.needs_approval]


class FilePreview(object):
    """Preview of all slices of one Mach-O file."""

    def __init__(self, filename):
        self.filename = filename
        self.slices = []

    @property
    def needs_approval(self):
        return [cmd for slice_ in self.slices for cmd in slice_.needs_approval]


class PreviewReport(object):
    """
    Result of :func:`preview_package`.  Purely informational: generating the
    report never modifies the files it describes.
    """

    def __init__(self, rules):
        self.rules = list(rules)
        self.files = []

    def needs_approval(self):
        """
        List of ``(file_preview, slice_preview, command_preview)`` tuples
        for every command whose merged outcome is not covered by the
        individual approvals.
        """
        result = []
        for file_preview in self.files:
            for slice_preview in file_preview.slices:
                for cmd in slice_preview.commands:
                    if cmd.needs_approval:
                        result.append((file_preview, slice_preview, cmd))
        return result

    def render(self):
        lines = []
        lines.append(
            "Preview of merged rewrite plan (%d rule%s): %s"
            % (
                len(self.rules),
                "s" if len(self.rules) != 1 else "",
                ", ".join(rule.name for rule in self.rules),
            )
        )
        lines.append("Read-only preview: no files were modified.")
        for file_preview in self.files:
            lines.append("")
            lines.append(file_preview.filename)
            for slice_preview in file_preview.slices:
                lines.append(
                    "  slice %d (%s, %s)"
                    % (
                        slice_preview.index,
                        slice_preview.arch,
                        slice_preview.header.filetype,
                    )
                )
                if not slice_preview.commands:
                    lines.append("    (no rewritable load commands)")
                for cmd in slice_preview.commands:
                    lines.append(
                        "    [%s] cmd #%d %s: %s -> %s"
                        % (cmd.status, cmd.index, cmd.kind, cmd.original, cmd.merged)
                    )
                    if cmd.contributors:
                        lines.append(
                            "      rewritten by: %s" % (", ".join(cmd.contributors),)
                        )
                    if cmd.attribution_before is not None:
                        lines.append(
                            "      binds to: %s -> %s"
                            % (cmd.attribution_before, cmd.attribution_after)
                        )
                    for reason in cmd.reasons:
                        lines.append("      RE-APPROVE: %s" % (reason,))
        pending = self.needs_approval()
        lines.append("")
        if pending:
            lines.append(
                "Summary: %d command(s) need re-approval before the merged"
                " plan may be applied:" % (len(pending),)
            )
            for file_preview, slice_preview, cmd in pending:
                lines.append(
                    "  - %s slice %d cmd #%d (%s)"
                    % (
                        file_preview.filename,
                        slice_preview.index,
                        cmd.index,
                        cmd.kind,
                    )
                )
        else:
            lines.append(
                "Summary: merged plan is fully covered by the individual"
                " approvals."
            )
        return "\n".join(lines)


def _command_string(lc, cmd, data):
    return lc_str_value(cmd.name, (lc, cmd, data)).decode(
        sys.getfilesystemencoding()
    )


def preview_package(filenames, rules, resolve=None):
    """
    Derive a read-only preview of applying the merged *rules* to *filenames*.

    For every file, every slice and every install-name/relocatable load
    command the report derives the merged outcome, the outcome each rule
    would have had on its own, and the dependency attribution (the
    install-name identity each load command binds to) before and after the
    merge.  Commands whose merged outcome is not covered by any individual
    approval are flagged as needing re-approval.

    ``resolve`` may be a callable ``(loader_filename, path) -> filename``
    that maps load-command paths to package members (e.g. bundle-relative
    paths); paths it cannot map fall back to matching the install names and
    on-disk locations of the files in the package.

    This function only reads files; it never writes.
    """
    rules = list(rules)
    report = PreviewReport(rules)

    # Pass 1: per-file, per-slice derivation of the merged command values.
    for filename in filenames:
        macho = MachO(filename)
        file_preview = FilePreview(filename)
        for header_index, header in enumerate(macho.headers):
            slice_preview = SlicePreview(header_index, header)

            if header.id_cmd is not None:
                lc, cmd, data = header.commands[header.id_cmd]
                original_id = _command_string(lc, cmd, data)
                # macholib derives the new install name from the on-disk
                # filename, not from the current install name.
                merged_id, contributors = _apply_rules(rules, filename)
                if not contributors:
                    merged_id = original_id
                command = CommandPreview(header.id_cmd, "install_name", original_id)
                command.merged = merged_id
                command.contributors = contributors
                for rule in rules:
                    solo = rule.changefunc(filename)
                    command.solo[rule.name] = solo if solo is not None else original_id
                slice_preview.commands.append(command)
                slice_preview.id_command = command

            for index, name, value in header.walkRelocatables():
                merged, contributors = _apply_rules(rules, value)
                command = CommandPreview(index, name, value)
                command.merged = merged
                command.contributors = contributors
                for rule in rules:
                    solo = rule.changefunc(value)
                    command.solo[rule.name] = solo if solo is not None else value
                slice_preview.commands.append(command)

            file_preview.slices.append(slice_preview)
        report.files.append(file_preview)

    # Pass 2: dependency attribution.  A load command binds to the install
    # name of the package member it resolves to; unresolvable paths keep
    # their own string as identity (which is what dyld would record).
    id_before = {}
    id_after = {}
    by_path = {}
    for file_preview in report.files:
        by_path[file_preview.filename] = file_preview.filename
        for slice_preview in file_preview.slices:
            if slice_preview.id_command is not None:
                id_before.setdefault(
                    slice_preview.install_name, file_preview.filename
                )
                id_after.setdefault(
                    slice_preview.merged_install_name, file_preview.filename
                )

    def lookup(loader, path, after):
        if resolve is not None:
            target = resolve(loader, path)
            if target is not None:
                return target
        if after:
            target = id_after.get(path)
        else:
            target = id_before.get(path)
        if target is not None:
            return target
        return by_path.get(path)

    merged_ids = {}
    for file_preview in report.files:
        for slice_preview in file_preview.slices:
            if slice_preview.id_command is not None:
                merged_ids.setdefault(
                    file_preview.filename,
                    (
                        slice_preview.install_name,
                        slice_preview.merged_install_name,
                        slice_preview.id_command.contributors,
                    ),
                )

    def attribution(loader, path, after):
        target = lookup(loader, path, after)
        if target is None or target not in merged_ids:
            return path, None
        before, after_id, _contributors = merged_ids[target]
        return (after_id if after else before), target

    for file_preview in report.files:
        for slice_preview in file_preview.slices:
            for command in slice_preview.commands:
                if command.kind == "install_name":
                    continue
                before, target_before = attribution(
                    file_preview.filename, command.original, after=False
                )
                after, target_after = attribution(
                    file_preview.filename, command.merged, after=True
                )
                command.attribution_before = before
                command.attribution_after = after
                if before == after:
                    continue
                if target_before is None and target_after is None:
                    # Neither side resolves to a package member, so the
                    # identity change is the string rewrite itself, which
                    # is judged by the string-level checks below.
                    continue
                target = target_after or target_before
                causers = merged_ids[target][2]
                command.reasons.append(
                    "dependency attribution changes from %r to %r because"
                    " rule(s) %s rewrote the install name of %s"
                    % (
                        before,
                        after,
                        ", ".join(repr(name) for name in causers) or "??",
                        target,
                    )
                )

    # Pass 3: compare the merged outcome with the individually approved
    # outcomes for every command.
    for file_preview in report.files:
        for slice_preview in file_preview.slices:
            for command in slice_preview.commands:
                solo_values = set(command.solo.values())
                if command.merged != command.original:
                    if command.merged not in solo_values:
                        command.reasons.append(
                            "merged value %r was not produced by any"
                            " individually approved rule" % (command.merged,)
                        )
                    else:
                        overridden = [
                            name
                            for name, value in command.solo.items()
                            if value != command.original and value != command.merged
                        ]
                        if overridden:
                            command.reasons.append(
                                "approved outcome of rule(s) %s is overridden"
                                " by the merged plan"
                                % (", ".join(repr(name) for name in overridden),)
                            )
                elif any(value != command.original for value in solo_values):
                    lost = [
                        name
                        for name, value in command.solo.items()
                        if value != command.original
                    ]
                    command.reasons.append(
                        "approved effect of rule(s) %s no longer happens in"
                        " the merged plan"
                        % (", ".join(repr(name) for name in lost),)
                    )

    return report
