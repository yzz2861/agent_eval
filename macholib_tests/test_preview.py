"""
Tests for macholib.preview: read-only preview of merged dependency rewrites.

The synthetic package built here demonstrates the packaging team's scenario:
two administrator-approved rewrites that are each safe on their own, where
the merged plan still contains an item that needs to be approved again.
"""

import os
import shutil
import struct
import sys
import tempfile
import unittest

from macholib import mach_o
from macholib.MachO import MachO
from macholib.preview import RewriteRule, merge_changefuncs, preview_package

CPU_TYPE_X86_64 = 0x1000007
CPU_TYPE_ARM64 = 0x100000C
SLICE_SIZE = 4096

VENDOR_PATH = "/vendor/libfoo.dylib"
BUNDLE_PATH = "@executable_path/../Frameworks/libfoo.dylib"
RPATH_PATH = "@rpath/libfoo.dylib"


def _pad8(data):
    return data + b"\x00" * (8 - len(data) % 8)


def lc_segment_64():
    # Dummy __TEXT segment so that the header has a sane low_offset,
    # which keeps MachOHeader.write() usable on the synthetic files.
    return struct.pack(
        ">II16sQQQQIIII",
        mach_o.LC_SEGMENT_64,
        72,
        b"__TEXT",
        0,
        0x1000,
        SLICE_SIZE,
        0x10,
        7,
        5,
        0,
        0,
    )


def lc_dylib(cmd, name):
    payload = _pad8(name.encode("utf-8"))
    cmdsize = 24 + len(payload)
    return struct.pack(">IIIIII", cmd, cmdsize, 24, 0, 0, 0) + payload


def thin_macho(cputype, filetype, load_commands):
    sizeofcmds = sum(len(command) for command in load_commands)
    header = struct.pack(
        ">IIIIIIII",
        mach_o.MH_MAGIC_64,
        cputype,
        0,
        filetype,
        len(load_commands),
        sizeofcmds,
        0,
        0,
    )
    blob = header + b"".join(load_commands)
    assert len(blob) <= SLICE_SIZE
    return blob + b"\x00" * (SLICE_SIZE - len(blob))


def fat_macho(slices):
    header = struct.pack(">II", mach_o.FAT_MAGIC, len(slices))
    archs = b""
    offset = SLICE_SIZE
    for cputype, blob in slices:
        archs += struct.pack(">IIIII", cputype, 0, offset, len(blob), 12)
        offset += len(blob)
    padding = b"\x00" * (SLICE_SIZE - (8 + 20 * len(slices)))
    return header + archs + padding + b"".join(blob for _, blob in slices)


def make_package(directory):
    """
    Create a synthetic package:

      - ``main``: executable loading libfoo through its vendor install name
      - ``libfoo.dylib``: universal (x86_64 + arm64) dylib whose install
        name is the vendor path
    """
    main = os.path.join(directory, "main")
    libfoo = os.path.join(directory, "libfoo.dylib")
    with open(main, "wb") as fp:
        fp.write(
            thin_macho(
                CPU_TYPE_ARM64,
                mach_o.MH_EXECUTE,
                [lc_segment_64(), lc_dylib(mach_o.LC_LOAD_DYLIB, VENDOR_PATH)],
            )
        )
    slices = [
        (
            cputype,
            thin_macho(
                cputype,
                mach_o.MH_DYLIB,
                [lc_segment_64(), lc_dylib(mach_o.LC_ID_DYLIB, VENDOR_PATH)],
            ),
        )
        for cputype in (CPU_TYPE_X86_64, CPU_TYPE_ARM64)
    ]
    with open(libfoo, "wb") as fp:
        fp.write(fat_macho(slices))
    return main, libfoo


def make_rules(libfoo_filename):
    """
    The two administrator-approved rewrites:

      - bundle-libfoo: the main executable loads libfoo from inside the
        bundle instead of from the vendor location
      - modernize-libfoo-id: libfoo's install name becomes @rpath-based
    """

    def bundle_libfoo(path):
        if path == VENDOR_PATH:
            return BUNDLE_PATH
        return None

    def modernize_libfoo_id(path):
        if path == libfoo_filename:
            return RPATH_PATH
        return None

    return (
        RewriteRule("bundle-libfoo", bundle_libfoo),
        RewriteRule("modernize-libfoo-id", modernize_libfoo_id),
    )


def make_resolver(libfoo_filename):
    def resolve(loader, path):
        if path == BUNDLE_PATH:
            return libfoo_filename
        return None

    return resolve


def load_command_values(filename):
    """Read back the install names and relocatable commands of every slice."""
    result = []
    for header in MachO(filename).headers:
        entry = {"install_name": None, "relocatables": []}
        if header.id_cmd is not None:
            lc, cmd, data = header.commands[header.id_cmd]
            offset = cmd.name - 24
            entry["install_name"] = data[
                offset : data.find(b"\x00", offset)
            ].decode(sys.getfilesystemencoding())
        for _index, _name, value in header.walkRelocatables():
            entry["relocatables"].append(value)
        result.append(entry)
    return result


class PreviewTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.directory)
        self.main, self.libfoo = make_package(self.directory)
        self.rule_bundle, self.rule_modernize = make_rules(self.libfoo)
        self.resolve = make_resolver(self.libfoo)
        self.files = [self.main, self.libfoo]

    def file_preview(self, report, filename):
        for file_preview in report.files:
            if file_preview.filename == filename:
                return file_preview
        self.fail("no preview for %r" % (filename,))

    def test_each_rule_is_safe_on_its_own(self):
        report = preview_package(self.files, [self.rule_bundle], self.resolve)
        self.assertEqual(report.needs_approval(), [])
        main_preview = self.file_preview(report, self.main)
        command = main_preview.slices[0].commands[0]
        self.assertEqual(command.merged, BUNDLE_PATH)
        self.assertEqual(command.status, "approved")
        libfoo_preview = self.file_preview(report, self.libfoo)
        for slice_preview in libfoo_preview.slices:
            self.assertEqual(slice_preview.merged_install_name, VENDOR_PATH)

        report = preview_package(self.files, [self.rule_modernize], self.resolve)
        self.assertEqual(report.needs_approval(), [])
        libfoo_preview = self.file_preview(report, self.libfoo)
        self.assertEqual(len(libfoo_preview.slices), 2)
        self.assertEqual(
            [slice_.arch for slice_ in libfoo_preview.slices], ["x86_64", "arm64"]
        )
        for slice_preview in libfoo_preview.slices:
            self.assertEqual(slice_preview.merged_install_name, RPATH_PATH)
        main_preview = self.file_preview(report, self.main)
        command = main_preview.slices[0].commands[0]
        self.assertEqual(command.merged, VENDOR_PATH)
        self.assertEqual(command.status, "unchanged")

    def test_merged_plan_flags_item_for_reapproval(self):
        report = preview_package(
            self.files, [self.rule_bundle, self.rule_modernize], self.resolve
        )
        pending = report.needs_approval()
        self.assertEqual(len(pending), 1)
        file_preview, slice_preview, command = pending[0]
        self.assertEqual(file_preview.filename, self.main)
        self.assertEqual(command.kind, "load_dylib")
        # The string rewrite itself is exactly what "bundle-libfoo" was
        # approved for ...
        self.assertEqual(command.merged, BUNDLE_PATH)
        self.assertEqual(command.contributors, ["bundle-libfoo"])
        # ... but "modernize-libfoo-id" changed the install name of the
        # dylib this command binds to, so the merged interpretation of the
        # approved rewrite is no longer the approved one.
        self.assertEqual(command.attribution_before, VENDOR_PATH)
        self.assertEqual(command.attribution_after, RPATH_PATH)
        self.assertIn("modernize-libfoo-id", command.reasons[0])

        # Both slices of the universal dylib get their new install name
        # exactly as approved, per slice.
        libfoo_preview = self.file_preview(report, self.libfoo)
        self.assertEqual(len(libfoo_preview.slices), 2)
        for slice_preview in libfoo_preview.slices:
            self.assertEqual(slice_preview.install_name, VENDOR_PATH)
            self.assertEqual(slice_preview.merged_install_name, RPATH_PATH)
            self.assertEqual(slice_preview.id_command.status, "approved")

        rendered = report.render()
        self.assertIn("needs-approval", rendered)
        self.assertIn("RE-APPROVE", rendered)
        self.assertIn(self.main, rendered)

    def test_merged_plan_is_read_only(self):
        before = {}
        for filename in self.files:
            with open(filename, "rb") as fp:
                before[filename] = fp.read()
        preview_package(
            self.files, [self.rule_bundle, self.rule_modernize], self.resolve
        )
        for filename in self.files:
            with open(filename, "rb") as fp:
                self.assertEqual(fp.read(), before[filename])

    def test_preview_matches_actual_writes(self):
        # Apply the merged plan through the existing macholib write path
        # (what existing callers do, unchanged) and verify the preview
        # predicted it exactly.
        report = preview_package(
            self.files, [self.rule_bundle, self.rule_modernize], self.resolve
        )
        changefunc = merge_changefuncs([self.rule_bundle, self.rule_modernize])
        for filename in self.files:
            macho = MachO(filename)
            if macho.rewriteLoadCommands(changefunc):
                with open(filename, "rb+") as fp:
                    for _header in macho.headers:
                        fp.seek(0)
                        macho.write(fp)

        main_values = load_command_values(self.main)
        self.assertEqual(main_values[0]["relocatables"], [BUNDLE_PATH])
        libfoo_values = load_command_values(self.libfoo)
        self.assertEqual(len(libfoo_values), 2)
        for slice_values in libfoo_values:
            self.assertEqual(slice_values["install_name"], RPATH_PATH)

        main_preview = self.file_preview(report, self.main)
        self.assertEqual(
            main_preview.slices[0].commands[0].merged,
            main_values[0]["relocatables"][0],
        )
        libfoo_preview = self.file_preview(report, self.libfoo)
        for index, slice_preview in enumerate(libfoo_preview.slices):
            self.assertEqual(
                slice_preview.merged_install_name,
                libfoo_values[index]["install_name"],
            )

    def test_chained_rules_can_produce_unapproved_values(self):
        # A command that rule "second" leaves unchanged on its own is
        # reinterpreted once rule "first" rewrote its input: the merged
        # value was never approved and must be flagged.  Rule order
        # decides whether the merged plan is clean.
        old_path = "/old/libfoo.dylib"
        new_path = "/new/libfoo.dylib"
        first = RewriteRule(
            "first", lambda path: new_path if path == old_path else None
        )
        second = RewriteRule(
            "second", lambda path: RPATH_PATH if path == new_path else None
        )
        lonely = os.path.join(self.directory, "lonely")
        with open(lonely, "wb") as fp:
            fp.write(
                thin_macho(
                    CPU_TYPE_ARM64,
                    mach_o.MH_EXECUTE,
                    [lc_segment_64(), lc_dylib(mach_o.LC_LOAD_DYLIB, old_path)],
                )
            )

        report = preview_package([lonely], [first, second])
        pending = report.needs_approval()
        self.assertEqual(len(pending), 1)
        command = pending[0][2]
        self.assertEqual(command.merged, RPATH_PATH)
        self.assertEqual(command.solo["first"], new_path)
        self.assertEqual(command.solo["second"], old_path)
        self.assertIn("not produced by any", command.reasons[0])

        report = preview_package([lonely], [second, first])
        self.assertEqual(report.needs_approval(), [])
        command = report.files[0].slices[0].commands[0]
        self.assertEqual(command.merged, new_path)
        self.assertEqual(command.status, "approved")

    def test_merge_changefuncs_follows_changefunc_protocol(self):
        changefunc = merge_changefuncs([self.rule_bundle, self.rule_modernize])
        self.assertIsNone(changefunc("/unrelated/lib.dylib"))
        self.assertEqual(changefunc(VENDOR_PATH), BUNDLE_PATH)
        self.assertEqual(changefunc(self.libfoo), RPATH_PATH)
        self.assertIsNone(merge_changefuncs([])(VENDOR_PATH))


if __name__ == "__main__":
    unittest.main()
