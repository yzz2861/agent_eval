#-------------------------------------------------------------------------------
# elftools: dwarf/type_deps.py
#
# Read-only forensic queries over DWARF type information.
#
# Given the debug information already parsed by pyelftools (optionally spread
# over several artifacts, such as a stripped executable, its .gnu_debuglink
# companion and a supplementary/alt-link object), this module answers:
#
#   * which type DIEs a given type depends on to be fully reconstructed;
#   * which "excerpts" (byte ranges of debug sections inside artifacts) carry
#     each of those DIEs;
#   * which excerpts must be kept, under a caller supplied retention license,
#     to keep the type reconstructible, choosing the cheapest option when
#     several artifacts define candidate sources for the same type;
#   * the minimum additional evidence that must be supplied when a reference
#     cannot be resolved from the registered artifacts.
#
# The module never writes to, and never mutates the position of, any stream.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, NamedTuple

from ..common.exceptions import DWARFError

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

    from .compileunit import CompileUnit
    from .die import DIE
    from .dwarfinfo import DebugSectionDescriptor, DWARFInfo
    from .typeunit import TypeUnit


# Attributes whose value is a reference to another DIE that contributes to the
# definition of a type. DW_AT_type is by far the most common; the rest appear on
# composite/pointer-to-member/entry-point types. Attributes such as
# DW_AT_abstract_origin are deliberately excluded: they describe code rather
# than the layout of a type.
STRUCTURAL_REFERENCE_ATTRS: frozenset[str] = frozenset((
    'DW_AT_type',
    'DW_AT_specification',
    'DW_AT_containing_type',
    'DW_AT_allocated',
    'DW_AT_associated',
    'DW_AT_data_member_location',
    'DW_AT_use_location',
    'DW_AT_extension',
    'DW_AT_import',
))

# Tags that are themselves type DIEs. DIEs carrying DW_AT_type but using other
# tags (variables, parameters, subprograms...) are entry points into the type
# graph rather than members of it.
TYPE_TAGS: frozenset[str] = frozenset((
    'DW_TAG_base_type',
    'DW_TAG_pointer_type',
    'DW_TAG_reference_type',
    'DW_TAG_rvalue_reference_type',
    'DW_TAG_const_type',
    'DW_TAG_volatile_type',
    'DW_TAG_restrict_type',
    'DW_TAG_atomic_type',
    'DW_TAG_packed_type',
    'DW_TAG_typedef',
    'DW_TAG_structure_type',
    'DW_TAG_class_type',
    'DW_TAG_union_type',
    'DW_TAG_enumeration_type',
    'DW_TAG_array_type',
    'DW_TAG_subroutine_type',
    'DW_TAG_ptr_to_member_type',
    'DW_TAG_string_type',
    'DW_TAG_set_type',
    'DW_TAG_subrange_type',
    'DW_TAG_unspecified_type',
    'DW_TAG_dynamic_type',
    'DW_TAG_coarray_type',
    'DW_TAG_interface_type',
))


class DIEKey(NamedTuple):
    """ Stable identity of a DIE across artifacts.

        Two DIEs in different artifacts may share an offset, so the artifact
        name is part of the key. Within one artifact, (section, offset) is
        unique.
    """
    artifact: str
    section: str
    offset: int


class ExcerptKey(NamedTuple):
    """ Identity of an excerpt: a byte range of a debug section in an
        artifact. Offsets are absolute in the artifact file.
    """
    artifact: str
    section: str
    start: int
    end: int


@dataclass(frozen=True)
class Excerpt:
    """ A contiguous piece of evidence that carries one or more DIEs.

        section_offset/size locate the DIE relative to its debug section;
        file_offset/file_end are absolute byte positions in the artifact, so
        an archive/cleanup tool can extract the bytes without understanding
        DWARF. global_offset is None when the section descriptor does not know
        its position in the container (custom DWARFInfo setups).
    """
    artifact: str
    section: str
    section_offset: int
    size: int
    global_offset: int | None

    @property
    def key(self) -> ExcerptKey:
        if self.global_offset is not None:
            start = self.global_offset + self.section_offset
        else:
            # No container mapping available; fall back to section-relative
            # coordinates, which remain stable within one registration.
            start = self.section_offset
        return ExcerptKey(self.artifact, self.section, start, start + self.size)

    @property
    def file_offset(self) -> int | None:
        if self.global_offset is None:
            return None
        return self.global_offset + self.section_offset

    @property
    def file_end(self) -> int | None:
        if self.global_offset is None:
            return None
        return self.global_offset + self.section_offset + self.size


@dataclass(frozen=True)
class TypeRef:
    """ A directed edge between two type DIEs. """
    attribute: str
    form: str
    target: DIEKey


@dataclass(frozen=True)
class UnresolvedRef:
    """ A structural reference that cannot be resolved from the registered
        artifacts (for example a DW_FORM_ref_sup8 with no supplementary file
        loaded, or a dwo reference that was not provided).
    """
    source: DIEKey
    attribute: str
    form: str
    raw_value: int
    reason: str


@dataclass(frozen=True)
class TypeNode:
    """ One type DIE and everything known about its immediate surroundings. """
    key: DIEKey
    tag: str
    name: str | None
    die_offset: int
    excerpt: Excerpt
    references: tuple[TypeRef, ...]
    unresolved: tuple[UnresolvedRef, ...]
    die: DIE | None = field(repr=False, compare=False)


@dataclass(frozen=True)
class MissingRequirement:
    """ Minimum evidence that has to be supplied to finish reconstruction.

        Each entry is one unresolved reference. requested_form/raw_value state
        exactly what the surviving DIE points at; hint names the kind of
        artifact that normally carries the target.
    """
    artifact: str
    section: str
    attribute: str
    requested_form: str
    requested_raw_value: int
    hint: str
    reason: str


@dataclass(frozen=True)
class RetentionPolicy:
    """ Caller supplied retention license.

        allowed_artifacts restricts which artifacts may be selected. An empty
        collection means "no restriction".
        allowed_sections restricts which debug sections may be selected; the
        default is the two sections that carry type DIEs. An empty collection
        means "no restriction".
    """
    allowed_artifacts: frozenset[str] = frozenset()
    allowed_sections: frozenset[str] = frozenset(
        ('.debug_info', '.debug_types'))
    excerpt_cost: dict[ExcerptKey, int] = field(default_factory=dict)

    def permits(self, excerpt: Excerpt) -> bool:
        if self.allowed_artifacts and excerpt.artifact not in self.allowed_artifacts:
            return False
        if self.allowed_sections and excerpt.section not in self.allowed_sections:
            return False
        return True

    def cost(self, excerpt: Excerpt) -> int:
        return self.excerpt_cost.get(excerpt.key, 1)


@dataclass(frozen=True)
class DependencyResult:
    """ Outcome of a query for one root type.

        nodes: every reachable type node, including the root, in discovery
               order. Recursive references are preserved: a node appears once
               even if several edges point at it.
        excerpts: the excerpts selected by the solver under the policy. This
                  is the minimum-cost set that covers every reachable type
                  whose candidates include a permitted excerpt.
        missing: minimum supplementary evidence for references that cannot be
                 resolved, and permitted types that have no permitted source.
        complete: True when every reachable type has a permitted source and
                  there are no unresolved references.
    """
    root: DIEKey
    nodes: tuple[TypeNode, ...]
    excerpts: tuple[Excerpt, ...]
    missing: tuple[MissingRequirement, ...]
    complete: bool

    @property
    def excerpt_keys(self) -> frozenset[ExcerptKey]:
        return frozenset(excerpt.key for excerpt in self.excerpts)


class TypeDependencyIndex:
    """ Read-only index of the type DIEs available in a set of artifacts.

        The index is built from already parsed DWARFInfo objects. Each
        DWARFInfo is paired with an arbitrary caller chosen artifact name.
        Absolute file offsets are taken from the DWARF section descriptors, so
        no ELFFile handle is required. All reads go through the existing
        pyelftools parsers; this class only walks DIEs and records offsets.

        Artifacts are registered explicitly, so the caller controls which
        files participate in a query - nothing is opened implicitly.
    """

    def __init__(self) -> None:
        # artifact name -> DWARFInfo
        self._dwarfinfos: dict[str, DWARFInfo | None] = {}
        # DIEKey -> TypeNode, for every DIE discovered while building
        self._nodes: dict[DIEKey, TypeNode] = {}
        # DIE object id() -> DIEKey, used to turn a resolved DIE back into a
        # key without re-deriving its section/offset
        self._die_keys: dict[int, DIEKey] = {}
        # (artifact, type name) -> DIEKey, for name based lookups
        self._names: dict[tuple[str, str], list[DIEKey]] = {}

    #------------------------------------------------------------------#
    # Construction
    #------------------------------------------------------------------#

    def register_artifact(
        self, artifact: str, dwarfinfo: DWARFInfo) -> None:
        """ Register one artifact and index every type DIE it contains.

            Registering the same artifact name again replaces its previous
            registration. Supplementary DWARFInfo objects reachable through
            ``supplementary_dwarfinfo`` are followed and indexed under derived
            names (``<artifact>:supplementary``) unless they were registered
            explicitly first.

            Absolute file positions for excerpts come from the DWARF section
            descriptors, so the DWARFInfo alone is sufficient.
        """
        if artifact in self._dwarfinfos:
            self._remove_artifact(artifact)
        self._dwarfinfos[artifact] = dwarfinfo
        self._index_dwarfinfo(artifact, dwarfinfo)

        # Follow supplementary/alt-link debug info transitively. The chain is
        # acyclic in practice; the visited set also protects against loops.
        visited = {id(dwarfinfo)}
        current = dwarfinfo
        depth = 0
        while current.supplementary_dwarfinfo is not None:
            sup = current.supplementary_dwarfinfo
            if id(sup) in visited:
                break
            visited.add(id(sup))
            depth += 1
            sup_artifact = f'{artifact}:supplementary' if depth == 1 else (
                f'{artifact}:supplementary{depth}')
            if sup_artifact not in self._dwarfinfos:
                self._dwarfinfos[sup_artifact] = sup
                self._index_dwarfinfo(sup_artifact, sup)
            current = sup

    def _remove_artifact(self, artifact: str) -> None:
        stale = [key for key in self._nodes if key.artifact == artifact]
        for key in stale:
            node = self._nodes.pop(key)
            self._die_keys.pop(id(node.die), None)
            if node.name is not None:
                grouped = self._names.get((artifact, node.name))
                if grouped is not None:
                    grouped = [candidate for candidate in grouped
                               if candidate != key]
                    if grouped:
                        self._names[(artifact, node.name)] = grouped
                    else:
                        del self._names[(artifact, node.name)]
        self._dwarfinfos.pop(artifact, None)

    def _index_dwarfinfo(
        self, artifact: str, dwarfinfo: DWARFInfo) -> None:
        for unit in self._iter_units(dwarfinfo):
            section, descriptor = self._unit_section(unit, dwarfinfo)
            global_offset = descriptor.global_offset if descriptor else None
            for die in unit.iter_DIEs():
                if die.is_null() or die.tag not in TYPE_TAGS:
                    continue
                key = DIEKey(artifact, section, die.offset)
                excerpt = Excerpt(
                    artifact=artifact,
                    section=section,
                    section_offset=die.offset,
                    size=die.size,
                    global_offset=global_offset,
                )
                name = _die_name(die)
                node = TypeNode(
                    key=key,
                    tag=die.tag,
                    name=name,
                    die_offset=die.offset,
                    excerpt=excerpt,
                    references=(),
                    unresolved=(),
                    die=die,
                )
                self._nodes[key] = node
                self._die_keys[id(die)] = key
                if name is not None:
                    self._names.setdefault((artifact, name), []).append(key)

    @staticmethod
    def _iter_units(dwarfinfo: DWARFInfo) -> Iterator[CompileUnit | TypeUnit]:
        yield from dwarfinfo.iter_CUs()
        if dwarfinfo.has_debug_types():
            yield from dwarfinfo.iter_TUs()

    @staticmethod
    def _unit_section(
        unit: CompileUnit | TypeUnit,
        dwarfinfo: DWARFInfo,
    ) -> tuple[str, DebugSectionDescriptor | None]:
        # TypeUnit instances only exist for .debug_types; CompileUnit instances
        # live in .debug_info. Checking the class avoids importing TypeUnit just
        # for an isinstance test.
        if type(unit).__name__ == 'TypeUnit':
            return '.debug_types', dwarfinfo.debug_types_sec
        return '.debug_info', dwarfinfo.debug_info_sec

    #------------------------------------------------------------------#
    # Lookups
    #------------------------------------------------------------------#

    @property
    def artifacts(self) -> tuple[str, ...]:
        return tuple(self._dwarfinfos)

    def get_node(self, key: DIEKey) -> TypeNode:
        try:
            return self._nodes[key]
        except KeyError as exc:
            raise KeyError(f'no type DIE indexed at {key!r}') from exc

    def find_by_name(
        self,
        name: str,
        artifact: str | None = None,
    ) -> tuple[TypeNode, ...]:
        """ Return every indexed type DIE with DW_AT_name equal to name.

            These are the candidate sources for the type. When artifact is
            given the search is restricted to it.
        """
        if artifact is not None:
            keys = self._names.get((artifact, name), ())
        else:
            keys = [
                key
                for (art, type_name), grouped in self._names.items()
                if type_name == name
                for key in grouped
            ]
        return tuple(self._nodes[key] for key in keys)

    def key_for_die(self, die: DIE) -> DIEKey:
        """ Return the index key of an already indexed DIE object. """
        try:
            return self._die_keys[id(die)]
        except KeyError as exc:
            raise DWARFError(
                'DIE is not part of any registered artifact') from exc

    def _add_synthetic_node(
        self,
        artifact: str,
        section: str,
        offset: int,
        tag: str,
        name: str | None,
        references: Iterable[TypeRef] = (),
        unresolved: Iterable[UnresolvedRef] = (),
        size: int = 1,
        global_offset: int | None = None,
    ) -> DIEKey:
        """ Insert a node without an underlying DIE/stream.

            Intended for callers that already hold a parsed type graph (and
            for tests). Edges are supplied eagerly, so no DIE is ever touched
            while resolving them. The node's ``die`` field is None.
        """
        key = DIEKey(artifact, section, offset)
        excerpt = Excerpt(
            artifact=artifact,
            section=section,
            section_offset=offset,
            size=size,
            global_offset=global_offset,
        )
        node = TypeNode(
            key=key,
            tag=tag,
            name=name,
            die_offset=offset,
            excerpt=excerpt,
            references=tuple(references),
            unresolved=tuple(unresolved),
            die=None,
        )
        self._nodes[key] = node
        self._dwarfinfos.setdefault(artifact, None)
        if name is not None:
            self._names.setdefault((artifact, name), []).append(key)
        return key

    #------------------------------------------------------------------#
    # Edge resolution and traversal
    #------------------------------------------------------------------#

    def _resolve_edges(self, node: TypeNode) -> None:
        """ Populate node.references/node.unresolved by following the
            structural reference attributes of its DIE.

            Recursive references are legal DWARF and are kept as ordinary
            edges; the traversal algorithm below is cycle safe.
        """
        if node.references or node.unresolved or node.die is None:
            return

        refs: list[TypeRef] = []
        unresolved: list[UnresolvedRef] = []
        die = node.die
        for attr_name in sorted(
                STRUCTURAL_REFERENCE_ATTRS & die.attributes.keys()):
            attr = die.attributes[attr_name]
            try:
                target_die = die.get_DIE_from_attribute(attr_name)
            except (DWARFError, NotImplementedError, KeyError) as exc:
                # KeyError covers offset lookups into units that were not
                # provided; NotImplementedError is raised by pyelftools for
                # dwo references and missing supplementary files.
                unresolved.append(UnresolvedRef(
                    source=node.key,
                    attribute=attr_name,
                    form=attr.form,
                    raw_value=_raw_int(attr.raw_value),
                    reason=str(exc),
                ))
                continue

            target_key = self._die_keys.get(id(target_die))
            if target_key is None or target_key not in self._nodes:
                # The reference resolves, but to a non-type DIE or to an
                # artifact that has not been registered. Either way the type
                # definition cannot be fully reconstructed from the index.
                unresolved.append(UnresolvedRef(
                    source=node.key,
                    attribute=attr_name,
                    form=attr.form,
                    raw_value=_raw_int(attr.raw_value),
                    reason=('target DIE is not a type DIE in any registered '
                            'artifact'),
                ))
                continue
            refs.append(TypeRef(
                attribute=attr_name,
                form=attr.form,
                target=target_key,
            ))

        # dataclasses are frozen; bypass via object.__setattr__ for this lazy
        # cache while keeping the public value immutable.
        object.__setattr__(node, 'references', tuple(refs))
        object.__setattr__(node, 'unresolved', tuple(unresolved))

    def closure(self, root: DIEKey) -> tuple[TypeNode, ...]:
        """ Return every type node reachable from root, in discovery order.

            Recursive references terminate naturally because visited nodes
            are not expanded twice.
        """
        if root not in self._nodes:
            raise KeyError(f'no type DIE indexed at {root!r}')

        ordered: list[TypeNode] = []
        visited: set[DIEKey] = set()
        stack: list[DIEKey] = [root]
        while stack:
            key = stack.pop()
            if key in visited:
                continue
            visited.add(key)
            node = self._nodes[key]
            self._resolve_edges(node)
            ordered.append(node)
            # Reverse so the first declared reference is visited first while
            # keeping the depth-first stack order intuitive.
            for ref in reversed(node.references):
                if ref.target not in visited:
                    stack.append(ref.target)
        return tuple(ordered)

    #------------------------------------------------------------------#
    # Public query
    #------------------------------------------------------------------#

    def query(
        self,
        root: DIEKey | str,
        policy: RetentionPolicy | None = None,
    ) -> DependencyResult:
        """ Run the forensic query for one root type.

            root may be a DIEKey or a type name. When a name matches several
            candidate sources (the same type defined in several artifacts),
            all of them participate as alternatives and the solver picks the
            cheapest permitted combination.

            The query is strictly read-only.
        """
        policy = policy or RetentionPolicy()
        root_keys = self._root_keys(root)

        # Build the reachable graph from every candidate root, then treat the
        # candidate roots as alternatives for the same logical type.
        reachable: dict[DIEKey, TypeNode] = {}
        discovery: list[DIEKey] = []
        for candidate in root_keys:
            for node in self.closure(candidate):
                if node.key not in reachable:
                    reachable[node.key] = node
                    discovery.append(node.key)

        # Group reachable nodes that are the same logical type: named types
        # share a group keyed by name; anonymous nodes are only alternatives of
        # themselves. The root candidates always form one group even if the
        # root name is None.
        groups = self._build_equivalence_groups(root_keys, reachable)
        selection, unpermitted = self._solve(groups, policy)

        missing = self._collect_missing(
            reachable, discovery, groups, unpermitted)
        chosen_excerpts: dict[ExcerptKey, Excerpt] = {}
        for key in selection:
            if key not in reachable:
                continue
            excerpt = reachable[key].excerpt
            chosen_excerpts.setdefault(excerpt.key, excerpt)
        excerpts = tuple(
            chosen_excerpts[key] for key in sorted(chosen_excerpts))
        complete = not missing
        return DependencyResult(
            root=root_keys[0],
            nodes=tuple(reachable[key] for key in discovery),
            excerpts=excerpts,
            missing=tuple(missing),
            complete=complete,
        )

    def _root_keys(self, root: DIEKey | str) -> list[DIEKey]:
        if isinstance(root, DIEKey):
            if root not in self._nodes:
                raise KeyError(f'no type DIE indexed at {root!r}')
            return [root]
        matches = self.find_by_name(root)
        if not matches:
            raise KeyError(f'no type DIE named {root!r} is indexed')
        return [node.key for node in matches]

    def _build_equivalence_groups(
        self,
        root_keys: Sequence[DIEKey],
        reachable: dict[DIEKey, TypeNode],
    ) -> list[frozenset[DIEKey]]:
        """ Group reachable keys that represent the same logical type.

            Two named nodes are equivalent when they carry the same DW_AT_name
            and tag; that is the situation produced when the same header type
            is compiled into several artifacts. Anonymous nodes stay alone,
            because nothing ties them to a counterpart in another artifact.
        """
        by_signature: dict[tuple[str, str], set[DIEKey]] = {}
        anonymous: list[frozenset[DIEKey]] = []
        root_group = set(root_keys)
        for key, node in reachable.items():
            if key in root_group:
                continue
            if node.name is None:
                anonymous.append(frozenset((key,)))
            else:
                signature = (node.name, node.tag)
                by_signature.setdefault(signature, set()).add(key)

        # Merge any named group that happens to include a root key into the
        # root alternative group, so the root is solved as one choice.
        root_name = reachable[root_keys[0]].name
        root_tag = reachable[root_keys[0]].tag
        if root_name is not None:
            root_group.update(
                by_signature.pop((root_name, root_tag), set()))

        groups = [frozenset(root_group)]
        groups.extend(frozenset(keys) for keys in by_signature.values())
        groups.extend(anonymous)
        return groups

    def _solve(
        self,
        groups: Sequence[frozenset[DIEKey]],
        policy: RetentionPolicy,
    ) -> tuple[set[DIEKey], set[frozenset[DIEKey]]]:
        """ Minimum-cost AND-OR selection over the type graph.

            Each group is an OR of candidate DIEs (pick one source); each DIE
            is an AND over the groups reached through its reference edges.
            Costs are tracked per excerpt, so one excerpt carrying several
            selected DIEs is charged exactly once. Recursive references are
            supported through the active group stack: a back edge closes a
            cycle that the outer choice already pays for. The recursion is
            path sensitive (the memo includes the active stack), which keeps
            the result exact in the presence of cycles.
        """
        group_of: dict[DIEKey, int] = {}
        for index, group in enumerate(groups):
            for key in group:
                group_of[key] = index

        # (group, active group stack, excerpts already paid) -> result. The
        # stack keeps recursive references sound, and the paid set ensures a
        # cached choice is not reused under a different excerpt sharing state.
        memo: dict[
            tuple[int, frozenset[int], frozenset[ExcerptKey]],
            tuple[int, set[DIEKey]],
        ] = {}
        unpermitted: set[frozenset[DIEKey]] = set()

        def evaluate(
            group_index: int,
            stack: frozenset[int],
            paid: frozenset[ExcerptKey],
        ) -> tuple[int, set[DIEKey]]:
            memo_key = (group_index, stack, paid)
            if memo_key in memo:
                return memo[memo_key]
            if group_index in stack:
                # Back edge of a recursive type: the outer choice for this
                # group is already on the path and already pays the excerpt.
                return 0, set()

            best_cost: int | None = None
            best_pick: set[DIEKey] = set()
            next_stack = stack | {group_index}
            for candidate in sorted(groups[group_index]):
                node = self._nodes[candidate]
                if not policy.permits(node.excerpt):
                    continue

                chosen: set[DIEKey] = {candidate}
                excerpt_key = node.excerpt.key
                already_paid = excerpt_key in paid
                cost = 0 if already_paid else policy.cost(node.excerpt)
                next_paid = paid if already_paid else paid | {excerpt_key}
                ok = True
                for ref in node.references:
                    target_group = group_of.get(ref.target)
                    if target_group is None:
                        # Unreachable in normal operation: every reference
                        # target is a reachable node and therefore belongs to
                        # an equivalence group. The guard keeps the solver
                        # from raising if a subclass overrides grouping.
                        ok = False
                        break
                    sub_cost, sub_pick = evaluate(
                        target_group, next_stack, next_paid)
                    cost += sub_cost
                    next_paid = next_paid | frozenset(
                        self._nodes[item].excerpt.key for item in sub_pick)
                    chosen |= sub_pick
                if not ok:
                    continue
                if best_cost is None or cost < best_cost:
                    best_cost = cost
                    best_pick = chosen

            if best_cost is None:
                unpermitted.add(groups[group_index])
                memo[memo_key] = (0, set())
                return memo[memo_key]

            memo[memo_key] = (best_cost, best_pick)
            return memo[memo_key]

        # Only the root group is a required type. The recursion reaches every
        # mandatory dependency, so unrelated reachable groups are not forced in.
        _, root_selection = evaluate(0, frozenset(), frozenset())
        return root_selection, unpermitted

    def _collect_missing(
        self,
        reachable: dict[DIEKey, TypeNode],
        discovery: Sequence[DIEKey],
        groups: Sequence[frozenset[DIEKey]],
        unpermitted: set[frozenset[DIEKey]],
    ) -> list[MissingRequirement]:
        """ Produce the minimum supplementary evidence list.

            One entry per unresolved structural reference, plus one entry per
            logical type whose every candidate source is forbidden by the
            retention license. Deduplicated so a requirement is stated once
            even if it is reachable through several paths.
        """
        seen: set[tuple] = set()
        requirements: list[MissingRequirement] = []

        def emit(requirement: MissingRequirement, dedup_key: tuple) -> None:
            if dedup_key in seen:
                return
            seen.add(dedup_key)
            requirements.append(requirement)

        for key in discovery:
            node = reachable[key]
            for unresolved in node.unresolved:
                emit(
                    MissingRequirement(
                        artifact=node.excerpt.artifact,
                        section=node.excerpt.section,
                        attribute=unresolved.attribute,
                        requested_form=unresolved.form,
                        requested_raw_value=unresolved.raw_value,
                        hint=_hint_for_form(unresolved.form),
                        reason=unresolved.reason,
                    ),
                    (node.excerpt.artifact, node.excerpt.section,
                     unresolved.attribute, unresolved.form,
                     unresolved.raw_value),
                )

        for group in groups:
            if group not in unpermitted:
                continue
            sample = reachable[next(iter(group))]
            for key in sorted(group):
                node = reachable[key]
                emit(
                    MissingRequirement(
                        artifact=node.excerpt.artifact,
                        section=node.excerpt.section,
                        attribute='<type-source>',
                        requested_form='',
                        requested_raw_value=node.die_offset,
                        hint=(
                            "permit one of the candidate excerpts, or supply "
                            "an artifact defining this type"),
                        reason=(
                            f'no permitted source for {sample.tag} '
                            f'{sample.name or "<anonymous>"}'),
                    ),
                    ('<type-source>',) + tuple(sorted(group)),
                )
        return requirements


#-----------------------------------------------------------------------#
# Helpers
#-----------------------------------------------------------------------#

def _die_name(die: DIE) -> str | None:
    attr = die.attributes.get('DW_AT_name')
    if attr is None:
        return None
    value = attr.value
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return str(value)


def _raw_int(raw_value: object) -> int:
    return raw_value if isinstance(raw_value, int) else -1


def _hint_for_form(form: str) -> str:
    if form in ('DW_FORM_ref_sup4', 'DW_FORM_ref_sup8',
                'DW_FORM_strp_sup', 'DW_FORM_GNU_ref_alt',
                'DW_FORM_GNU_strp_alt'):
        return ('supplementary/alt-link debug object referenced by '
                '.debug_sup or .gnu_debugaltlink')
    if form in ('DW_FORM_ref_addr',):
        return 'the .debug_info or .debug_types section holding the offset'
    return 'the compilation/type unit containing the referenced DIE'
