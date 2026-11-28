#-------------------------------------------------------------------------------
# elftools tests
#
# Tests for the read-only DWARF type dependency / forensic query module.
# The graph-level cases build synthetic type nodes (no compiler required);
# the end-to-end cases run against the checked-in ELF fixtures.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import os
import unittest

from elftools.dwarf.type_deps import (
    DIEKey,
    ExcerptKey,
    RetentionPolicy,
    TypeDependencyIndex,
    TypeRef,
    UnresolvedRef,
)
from elftools.elf.elffile import ELFFile


UNITTEST_DIR = os.path.join('test', 'testfiles_for_unittests')


def make_index() -> TypeDependencyIndex:
    """ Build a two-artifact type graph.

        Artifact A defines ``Node`` and ``int``; artifact B defines the same
        two named types plus its own ``char``. ``Node`` holds a pointer to its
        own type (a legal recursive reference) and a value of ``int``.

        Layout (offsets are section-relative, one DIE per excerpt):
            A: Node@0x10 -> int@0x30, Node@0x10 (recursive pointer)
            B: Node@0x20 -> int@0x40, Node@0x20 (recursive pointer); char@0x60
    """
    index = TypeDependencyIndex()

    a_node = DIEKey('artifact_a', '.debug_info', 0x10)
    a_int = DIEKey('artifact_a', '.debug_info', 0x30)
    b_node = DIEKey('artifact_b', '.debug_info', 0x20)
    b_int = DIEKey('artifact_b', '.debug_info', 0x40)

    index._add_synthetic_node(
        'artifact_a', '.debug_info', 0x30,
        'DW_TAG_base_type', 'int', size=7, global_offset=0x1000)
    index._add_synthetic_node(
        'artifact_a', '.debug_info', 0x10,
        'DW_TAG_structure_type', 'Node',
        references=(
            TypeRef('DW_AT_type', 'DW_FORM_ref4', a_int),
            TypeRef('DW_AT_type', 'DW_FORM_ref4', a_node),
        ),
        size=12, global_offset=0x1000)

    index._add_synthetic_node(
        'artifact_b', '.debug_info', 0x40,
        'DW_TAG_base_type', 'int', size=7, global_offset=0x2000)
    index._add_synthetic_node(
        'artifact_b', '.debug_info', 0x60,
        'DW_TAG_base_type', 'char', size=7, global_offset=0x2000)
    index._add_synthetic_node(
        'artifact_b', '.debug_info', 0x20,
        'DW_TAG_structure_type', 'Node',
        references=(
            TypeRef('DW_AT_type', 'DW_FORM_ref4', b_int),
            TypeRef('DW_AT_type', 'DW_FORM_ref4', b_node),
        ),
        size=12, global_offset=0x2000)
    return index


class TestTypeDependencyGraph(unittest.TestCase):
    def test_candidate_sources_are_discovered_by_name(self):
        index = make_index()
        candidates = {node.key.artifact
                      for node in index.find_by_name('Node')}
        self.assertEqual(candidates, {'artifact_a', 'artifact_b'})

    def test_closure_preserves_recursive_reference_without_duplicates(self):
        index = make_index()
        result = index.query(DIEKey('artifact_a', '.debug_info', 0x10))
        keys = [node.key for node in result.nodes]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(
            {key.offset for key in keys}, {0x10, 0x30})

        node = index.get_node(DIEKey('artifact_a', '.debug_info', 0x10))
        targets = {ref.target for ref in node.references}
        # The self pointer edge is retained even though it is a back edge.
        self.assertIn(DIEKey('artifact_a', '.debug_info', 0x10), targets)

    def test_mutual_recursion_is_solved_without_double_counting(self):
        index = TypeDependencyIndex()
        type_a = DIEKey('one', '.debug_info', 0x10)
        type_b = DIEKey('one', '.debug_info', 0x20)
        index._add_synthetic_node(
            'one', '.debug_info', 0x10, 'DW_TAG_structure_type', 'A',
            references=(
                TypeRef('DW_AT_type', 'DW_FORM_ref4', type_b),),
            size=5, global_offset=0x100 - 0x10)
        index._add_synthetic_node(
            'one', '.debug_info', 0x20, 'DW_TAG_structure_type', 'B',
            references=(
                TypeRef('DW_AT_type', 'DW_FORM_ref4', type_a),),
            size=5, global_offset=0x200 - 0x20)

        result = index.query('A')
        self.assertTrue(result.complete)
        self.assertEqual(len(result.nodes), 2)
        # Each type needs its own excerpt; the A -> B -> A back edge must not
        # add a third excerpt or loop forever.
        self.assertEqual(len(result.excerpts), 2)

    def test_minimum_set_picks_cheapest_of_two_candidate_sources(self):
        index = make_index()

        # Default policy: both artifacts allowed, every excerpt costs one.
        # Either source of Node needs its own int, so the minimum is two
        # excerpts and the deterministic tie break selects artifact_a.
        result = index.query('Node')
        self.assertTrue(result.complete)
        self.assertEqual(len(result.excerpts), 2)
        self.assertEqual(
            {excerpt.artifact for excerpt in result.excerpts},
            {'artifact_a'})

        # Make the B excerpts individually cheaper; the solver must switch to
        # the B candidate while still covering B's int.
        cheap = RetentionPolicy(excerpt_cost={
            ExcerptKey('artifact_b', '.debug_info', 0x2020, 0x202c): 0,
            ExcerptKey('artifact_b', '.debug_info', 0x2040, 0x2047): 0,
        })
        cheap_result = index.query('Node', cheap)
        self.assertEqual(
            {excerpt.artifact for excerpt in cheap_result.excerpts},
            {'artifact_b'})
        self.assertEqual(cheap_result.excerpt_keys, frozenset((
            ExcerptKey('artifact_b', '.debug_info', 0x2020, 0x202c),
            ExcerptKey('artifact_b', '.debug_info', 0x2040, 0x2047),
        )))

    def test_retention_license_restricts_artifacts_and_sections(self):
        index = make_index()
        only_b = RetentionPolicy(allowed_artifacts=frozenset({'artifact_b'}))
        result = index.query('Node', only_b)
        self.assertTrue(result.complete)
        self.assertEqual(
            {excerpt.artifact for excerpt in result.excerpts},
            {'artifact_b'})

        no_types = RetentionPolicy(
            allowed_sections=frozenset(('.debug_abbrev',)))
        blocked = index.query('Node', no_types)
        self.assertFalse(blocked.complete)
        self.assertEqual(blocked.excerpts, ())
        self.assertTrue(blocked.missing)
        self.assertTrue(all(
            requirement.attribute == '<type-source>'
            for requirement in blocked.missing))

    def test_when_no_artifact_is_permitted_root_requires_supplement(self):
        index = make_index()
        policy = RetentionPolicy(
            allowed_artifacts=frozenset({'some_other_artifact'}))
        result = index.query('Node', policy)
        self.assertFalse(result.complete)
        self.assertEqual(result.excerpts, ())
        # One requirement per logical type that lost every candidate source.
        self.assertGreaterEqual(len(result.missing), 1)
        for requirement in result.missing:
            self.assertEqual(requirement.attribute, '<type-source>')
            self.assertIn(requirement.artifact,
                          {'artifact_a', 'artifact_b'})

    def test_two_candidate_types_share_dependency_choice(self):
        # When B is forced, both Node and its int must come from B even though
        # A also defines an int with the same name.
        index = make_index()
        only_b = RetentionPolicy(allowed_artifacts=frozenset({'artifact_b'}))
        result = index.query('Node', only_b)
        offsets = {excerpt.section_offset for excerpt in result.excerpts}
        self.assertEqual(offsets, {0x20, 0x40})

    def test_unresolved_reference_lists_minimum_supplement(self):
        index = TypeDependencyIndex()
        root = DIEKey('partial', '.debug_info', 0x10)
        index._add_synthetic_node(
            'partial', '.debug_info', 0x10,
            'DW_TAG_typedef', 'HalfResolved',
            unresolved=(UnresolvedRef(
                source=root,
                attribute='DW_AT_type',
                form='DW_FORM_GNU_ref_alt',
                raw_value=0x11,
                reason='DW_FORM_GNU_ref_alt to dwo',
            ),),
            global_offset=0x500)

        result = index.query(root)
        self.assertFalse(result.complete)
        self.assertEqual(len(result.missing), 1)
        requirement = result.missing[0]
        self.assertEqual(requirement.artifact, 'partial')
        self.assertEqual(requirement.requested_form, 'DW_FORM_GNU_ref_alt')
        self.assertEqual(requirement.requested_raw_value, 0x11)
        self.assertIn('supplementary', requirement.hint)

    def test_dependency_shared_excerpt_is_counted_once(self):
        index = TypeDependencyIndex()
        # Both int and Count are carried by the exact same physical excerpt
        # (absolute file range 0x1000..0x1007), even though their DIE offsets
        # differ. global_offset is chosen per node so the computed excerpt key
        # is identical.
        shared_excerpt = ExcerptKey('one', '.debug_info', 0x1000, 0x1007)
        shared_int = DIEKey('one', '.debug_info', 0x30)
        index._add_synthetic_node(
            'one', '.debug_info', 0x30, 'DW_TAG_base_type', 'int',
            size=7, global_offset=shared_excerpt.start - 0x30)
        index._add_synthetic_node(
            'one', '.debug_info', 0x40, 'DW_TAG_typedef', 'Count',
            references=(TypeRef('DW_AT_type', 'DW_FORM_ref4', shared_int),),
            size=7, global_offset=shared_excerpt.start - 0x40)
        self.assertEqual(
            index.get_node(shared_int).excerpt.key,
            index.get_node(DIEKey('one', '.debug_info', 0x40)).excerpt.key)
        index._add_synthetic_node(
            'one', '.debug_info', 0x10, 'DW_TAG_structure_type', 'Pair',
            references=(
                TypeRef('DW_AT_type', 'DW_FORM_ref4', shared_int),
                TypeRef('DW_AT_type', 'DW_FORM_ref4',
                         DIEKey('one', '.debug_info', 0x40)),
            ),
            size=7, global_offset=0x2000 - 0x10)

        policy = RetentionPolicy(excerpt_cost={
            shared_excerpt: 5,
        })
        result = index.query('Pair', policy)
        # Pair's excerpt plus the single excerpt carrying both int and Count.
        self.assertEqual(len(result.excerpts), 2)
        total = sum(policy.cost(excerpt) for excerpt in result.excerpts)
        # Pair costs the default 1; the shared excerpt is charged once at 5.
        self.assertEqual(total, 6)


class TestTypeDependencyRealELF(unittest.TestCase):
    def test_query_on_sample_exe_reports_file_ranges(self):
        path = os.path.join(UNITTEST_DIR, 'sample_exe64.elf')
        with open(path, 'rb') as stream:
            elf = ELFFile(stream)
            dwarfinfo = elf.get_dwarf_info()
            index = TypeDependencyIndex()
            index.register_artifact('sample_exe64.elf', dwarfinfo)

            root = index.find_by_name('size_t')[0].key
            result = index.query(root)
            self.assertTrue(result.complete)
            self.assertEqual(result.missing, ())
            # size_t -> long unsigned int: two excerpts, both inside .debug_info
            self.assertEqual(len(result.excerpts), 2)
            for excerpt in result.excerpts:
                self.assertEqual(excerpt.section, '.debug_info')
                self.assertIsNotNone(excerpt.file_offset)
                self.assertEqual(
                    excerpt.file_end - excerpt.file_offset, excerpt.size)
                descriptor = dwarfinfo.debug_info_sec
                self.assertGreaterEqual(
                    excerpt.file_offset, descriptor.global_offset)

    def test_missing_supplementary_is_reported_not_raised(self):
        path = os.path.join(UNITTEST_DIR, 'test_gnudebugaltlink1.debug')
        with open(path, 'rb') as stream:
            elf = ELFFile(stream)
            # follow_links=False keeps the alt-link unresolved on purpose.
            dwarfinfo = elf.get_dwarf_info(follow_links=False)
            index = TypeDependencyIndex()
            index.register_artifact('gnu1', dwarfinfo)

            typedef = next(
                node for node in index._nodes.values()
                if node.tag == 'DW_TAG_typedef')
            result = index.query(typedef.key)
            self.assertFalse(result.complete)
            self.assertTrue(any(
                requirement.requested_form == 'DW_FORM_GNU_ref_alt'
                for requirement in result.missing))

    def test_query_is_read_only_on_stream(self):
        path = os.path.join(UNITTEST_DIR, 'sample_exe64.elf')
        with open(path, 'rb') as stream:
            elf = ELFFile(stream)
            dwarfinfo = elf.get_dwarf_info()
            index = TypeDependencyIndex()
            index.register_artifact('sample_exe64.elf', dwarfinfo)
            root = index.find_by_name('size_t')[0].key
            before = stream.tell()
            index.query(root)
            index.query(root)
            self.assertEqual(stream.tell(), before)

    def test_supplementary_artifact_is_indexed_and_resolved(self):
        # With link following enabled, the alt-link object is loaded and the
        # index follows it transitively, so cross-file DW_AT_type references
        # resolve instead of being reported as missing evidence.
        path = os.path.join(UNITTEST_DIR, 'test_gnudebugaltlink1.debug')
        with ELFFile.load_from_path(path) as elf:
            dwarfinfo = elf.get_dwarf_info()
            self.assertIsNotNone(dwarfinfo.supplementary_dwarfinfo)
            index = TypeDependencyIndex()
            index.register_artifact('gnu1', dwarfinfo)

            self.assertIn('gnu1:supplementary', index.artifacts)
            typedef = next(
                node for node in index._nodes.values()
                if node.tag == 'DW_TAG_typedef')
            result = index.query(typedef.key)
            self.assertTrue(result.complete)
            self.assertEqual(result.missing, ())
            used = {excerpt.artifact for excerpt in result.excerpts}
            self.assertIn('gnu1:supplementary', used)


if __name__ == '__main__':
    unittest.main()
