"""
An optional, opt-in mode which explains how a schema evaluated an instance.

The explainer observes a single pass over the normal validation traversal,
without re-running any validator callable.  It records which keywords ran
and whether they succeeded, which applicator branches were entered and
whether they succeeded, and where each evaluated property or array item was
evaluated from.

Nothing here is consulted by validation itself; it only observes the
traversal.  When no `Explainer` is attached, the rest of the package makes
no observable change.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

from attrs import define, field

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


# The explainer attached to an in-progress ``explain`` traversal.  Validator
# objects are created via attrs and their field aliases must not change, so
# the active explainer is carried here rather than as a validator field; it
# is scoped per validation (and per thread / asyncio task via ContextVar).
_CURRENT: ContextVar[Explainer | None] = ContextVar(
    "jsonschema_explainer",
    default=None,
)


def current() -> Explainer | None:
    """Return the explainer for the active traversal, if any."""
    return _CURRENT.get()


@contextmanager
def activate(explainer: Explainer) -> Iterator[None]:
    """Make ``explainer`` observe validation within the block."""
    token = _CURRENT.set(explainer)
    try:
        yield
    finally:
        _CURRENT.reset(token)


# Keywords whose subschemas are applicator *branches*.
_BRANCH_KEYWORDS = frozenset(
    {
        "allOf",
        "anyOf",
        "oneOf",
        "dependentSchemas",
    },
)
# Keywords whose subschema evaluations are reference jumps.
_REF_KEYWORDS = frozenset({"$ref", "$dynamicRef", "$recursiveRef"})
# Keywords which directly apply a subschema to a property.
_PROPERTY_KEYWORDS = frozenset(
    {
        "properties",
        "patternProperties",
        "additionalProperties",
        "unevaluatedProperties",
    },
)
# Keywords which directly apply a subschema to an array item.
_ITEM_KEYWORDS = frozenset(
    {
        "prefixItems",
        "items",
        "additionalItems",
    },
)
# Branches whose annotations are only kept when the branch succeeds.
_CONDITIONAL_KEYWORDS = frozenset({"anyOf", "oneOf"})


def escape(token: Any) -> str:
    """Escape a single JSON Pointer reference token."""
    return str(token).replace("~", "~0").replace("/", "~1")


def pointer(tokens: Iterable[Any]) -> str:
    """Build a JSON Pointer from an iterable of reference tokens."""
    return "".join("/" + escape(token) for token in tokens)


@define(frozen=True, slots=True)
class EvaluationSource:
    """
    A single property or array item which was evaluated.

    Attributes:

    instance_pointer:

        a JSON Pointer to the evaluated property value or item within the
        validated instance

    schema_pointer:

        a JSON Pointer (relative to the root schema, or to a referenced
        document's root) to the subschema location which caused the
        evaluation

    keyword:

        the keyword which applied the subschema doing the evaluation

    via:

        the chain of applicator branches or references traversed from the
        root schema before the evaluation, innermost last; each element is a
        ``(keyword, JSON Pointer)`` pair

    value:

        the evaluated value, only present when ``include_values=True``

    name:

        the final instance reference token in its native type (a property
        name or an integer array index)

    item:

        whether ``name`` is an array index rather than a property name

    """

    instance_pointer: str
    schema_pointer: str
    keyword: str
    via: tuple[tuple[str, str], ...] = ()
    value: Any = None
    name: Any = None
    item: bool = False

    def as_dict(self, *, include_values: bool = False) -> dict[str, Any]:
        result = {
            "instance_pointer": self.instance_pointer,
            "schema_pointer": self.schema_pointer,
            "keyword": self.keyword,
            "via": [
                {"keyword": keyword, "schema_pointer": target}
                for keyword, target in self.via
            ],
        }
        if include_values:
            result["value"] = self.value
        return result


@define(frozen=True, slots=True)
class KeywordEvaluation:
    """
    The outcome of evaluating one keyword at one schema location.

    Attributes:

    keyword:

        the keyword name

    instance_pointer:

        a JSON Pointer to the instance location at which the keyword ran

    schema_pointer:

        a JSON Pointer to the keyword within the schema

    valid:

        whether the keyword produced no error

    via:

        the chain of branches and references traversed before the keyword
        ran, innermost last

    """

    keyword: str
    instance_pointer: str
    schema_pointer: str
    valid: bool
    via: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "keyword": self.keyword,
            "instance_pointer": self.instance_pointer,
            "schema_pointer": self.schema_pointer,
            "valid": self.valid,
            "via": [
                {"keyword": keyword, "schema_pointer": target}
                for keyword, target in self.via
            ],
        }


@define(frozen=True, slots=True)
class BranchEvaluation:
    """
    The outcome of one applicator branch.

    Attributes:

    keyword:

        the containing applicator keyword (``allOf``, ``anyOf``, ``oneOf``,
        ``if``, ``then``, ``else``, ``$ref``, ``$dynamicRef``,
        ``$recursiveRef`` or ``dependentSchemas``)

    instance_pointer:

        a JSON Pointer to the instance location the branch was applied to

    applicator_pointer:

        a JSON Pointer to the containing keyword

    branch_pointer:

        a JSON Pointer to the branch subschema: an index, ``then``,
        ``else``, or the reference target when the pointer resets

    evaluated:

        whether the branch subschema was entered

    valid:

        whether the branch succeeded, or ``None`` when it was not entered

    ref:
        for references, the reference string which was followed

    """

    keyword: str
    instance_pointer: str
    applicator_pointer: str
    branch_pointer: str
    evaluated: bool
    valid: bool | None = None
    ref: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result = {
            "keyword": self.keyword,
            "instance_pointer": self.instance_pointer,
            "applicator_pointer": self.applicator_pointer,
            "branch_pointer": self.branch_pointer,
            "evaluated": self.evaluated,
            "valid": self.valid,
        }
        if self.ref is not None:
            result["ref"] = self.ref
        return result


@define(slots=True)
class _Frame:
    # The keyword under which this frame was descended, if any.
    entered_keyword: str | None
    # The reference token locating the descended subschema in the parent.
    schema_token: Any
    # The instance reference token locating the descended value.
    instance_token: Any
    # Instance pointer tokens from the root.
    instance_tokens: list[Any]
    # Schema pointer tokens within the current (possibly referenced)
    # document.
    schema_tokens: list[Any]
    # The applicator/reference chain traversed to reach this frame.
    via: list[tuple[str, str]]
    # Whether this frame is a probe whose results are never reported.
    ephemeral: bool = False
    # Whether this frame marks the start of a referenced document.
    reference: bool = False
    # For references, the followed reference string and referencing kw.
    ref: str | None = None
    ref_keyword: str | None = None
    # The instance this frame validates.
    instance: Any = None
    # Whether this frame is a conditional boundary holding annotations
    # until it knows whether it succeeded.
    conditional: bool = False
    errors: int = 0
    # Annotations recorded directly in this frame.
    annotations: list[EvaluationSource] = field(factory=list)
    # Annotations held at a conditional boundary until it succeeds.
    held: list[EvaluationSource] = field(factory=list)
    keyword_evaluations: list[KeywordEvaluation] = field(factory=list)
    branches: list[BranchEvaluation] = field(factory=list)

    @property
    def valid(self) -> bool:
        return self.errors == 0

    @property
    def instance_pointer(self) -> str:
        return pointer(self.instance_tokens)

    @property
    def schema_pointer(self) -> str:
        return pointer(self.schema_tokens)

    def all_annotations(self) -> list[EvaluationSource]:
        return self.annotations + self.held


class Explainer:
    """
    Observe a single validation traversal and collect an explanation.

    Arguments:

    include_values:

        whether evaluated values are included in the report; by default only
        pointers are recorded

    max_events:

        the maximum number of recorded events (keyword evaluations,
        branches and evaluation sources); once exceeded the report is marked
        truncated and recording stops

    max_depth:

        the maximum number of simultaneously recorded schema frames; deeper
        frames (e.g. reached via recursive references) are not recorded,
        which guarantees the report itself terminates

    """

    def __init__(
        self,
        *,
        include_values: bool = False,
        max_events: int = 10_000,
        max_depth: int = 1_000,
    ) -> None:
        self.include_values = include_values
        self.max_events = max_events
        self.max_depth = max_depth

        self._frames: list[_Frame] = []
        self._inhibit_depth = 0
        self._events = 0
        self.truncated = False
        # The reference the next descend should jump to: (keyword, string).
        self._pending_ref: tuple[str, str] | None = None
        # The keyword currently executing in the deepest frame.
        self._active_keyword: str | None = None
        self._keyword_evaluations: list[KeywordEvaluation] = []
        self._branches: list[BranchEvaluation] = []
        self._annotations: list[EvaluationSource] = []

    @property
    def active(self) -> bool:
        return self._inhibit_depth == 0

    def _charge(self, amount: int = 1) -> bool:
        if self.truncated:
            return False
        self._events += amount
        if self._events > self.max_events:
            self.truncated = True
            return False
        return True

    @contextmanager
    def inhibit(self) -> Iterator[None]:
        """
        Suppress observation within the block.

        Used for the re-running ``unevaluatedProperties`` /
        ``unevaluatedItems`` helpers, whose traversal duplicates the real
        one and must not pollute the report.
        """
        self._inhibit_depth += 1
        try:
            yield
        finally:
            self._inhibit_depth -= 1

    def _current(self) -> _Frame | None:
        return self._frames[-1] if self._frames else None

    def _nearest_boundary(self, index: int) -> _Frame | None:
        """
        Return the nearest enclosing conditional boundary.

        This is the boundary strictly before the frame at ``index``, or None
        when annotations reach the report directly.
        """
        for candidate in reversed(self._frames[:index]):
            if candidate.conditional:
                return candidate
        return None

    def _emit_branch_records(
        self,
        frame: _Frame,
        parent: _Frame | None,
    ) -> None:
        if frame.reference and frame.ref_keyword is not None:
            self._charge()
            applicator = (
                (parent.schema_pointer if parent is not None else "")
                + "/"
                + escape(frame.ref_keyword)
            )
            record = BranchEvaluation(
                keyword=frame.ref_keyword,
                instance_pointer=frame.instance_pointer,
                applicator_pointer=applicator,
                branch_pointer=frame.ref or "",
                evaluated=True,
                valid=frame.valid,
                ref=frame.ref,
            )
            if parent is None:
                self._branches.append(record)
            else:
                parent.branches.append(record)

        if frame.entered_keyword in _BRANCH_KEYWORDS and parent is not None:
            self._charge()
            parent.branches.append(
                BranchEvaluation(
                    keyword=frame.entered_keyword,
                    instance_pointer=frame.instance_pointer,
                    applicator_pointer=(
                        parent.schema_pointer
                        + "/"
                        + escape(frame.entered_keyword)
                    ),
                    branch_pointer=str(frame.schema_token)
                    if frame.schema_token is not None
                    else "",
                    evaluated=True,
                    valid=frame.valid,
                ),
            )

    def begin_iter_errors(
        self,
        *,
        schema: Any,
        instance: Any,
    ) -> _Frame | None:
        """
        Begin the root frame for an ``iter_errors`` traversal.

        A nested call (an ``is_valid`` probe during a real traversal) is an
        ephemeral frame whose observations are discarded.
        """
        if not self.active:
            return None
        ephemeral = bool(self._frames)
        return self._begin(
            entered_keyword=None,
            schema_token=None,
            instance_token=None,
            schema=schema,
            instance=instance,
            ephemeral=ephemeral,
        )

    def begin_descend(
        self,
        *,
        schema: Any,
        instance: Any,
        path: Any,
        schema_path: Any,
    ) -> _Frame | None:
        parent = self._current()
        keyword = self._active_keyword
        if not self.active:
            return None
        ephemeral = parent is not None and parent.ephemeral
        pending = self._pending_ref
        self._pending_ref = None

        frame = self._begin(
            entered_keyword=keyword,
            schema_token=schema_path,
            instance_token=path,
            schema=schema,
            instance=instance,
            ephemeral=ephemeral,
            pending_ref=pending,
        )
        self._record_direct_annotation(frame)
        return frame

    def _begin(
        self,
        *,
        entered_keyword: str | None,
        schema_token: Any,
        instance_token: Any,
        schema: Any,
        instance: Any,
        ephemeral: bool,
        pending_ref: tuple[str, str] | None = None,
    ) -> _Frame | None:
        parent = self._current()
        depth_cutoff = len(self._frames) >= self.max_depth
        # Frames past the depth cap are still pushed, so the frame stack
        # stays balanced if recursive references keep descending.  Such
        # frames are ephemeral and contribute nothing to the report.
        suppressed = ephemeral or not self.active
        if depth_cutoff:
            self.truncated = True
            suppressed = True

        pending_keyword, pending_string = pending_ref or (
            entered_keyword,
            None,
        )
        is_reference = pending_ref is not None

        if parent is None:
            instance_tokens: list[Any] = []
            schema_tokens: list[Any] = []
            via: list[tuple[str, str]] = []
        else:
            instance_tokens = list(parent.instance_tokens)
            if instance_token is not None:
                instance_tokens.append(instance_token)
            if is_reference:
                schema_tokens = []
                via = list(parent.via)
                via.append((pending_keyword, pending_string or ""))
            else:
                schema_tokens = list(parent.schema_tokens)
                via = list(parent.via)
                if (
                    entered_keyword is not None
                    and entered_keyword not in _REF_KEYWORDS
                ):
                    schema_tokens.append(entered_keyword)
                    if schema_token is not None:
                        schema_tokens.append(schema_token)
                if entered_keyword in _BRANCH_KEYWORDS or (
                    entered_keyword in {"then", "else"}
                ):
                    via.append(
                        (entered_keyword, pointer(schema_tokens)),
                    )

        frame = _Frame(
            entered_keyword=entered_keyword,
            schema_token=schema_token,
            instance_token=instance_token,
            instance_tokens=instance_tokens,
            schema_tokens=schema_tokens,
            via=via,
            ephemeral=suppressed,
            reference=is_reference,
            ref=pending_string,
            ref_keyword=pending_keyword if is_reference else None,
            instance=instance,
            conditional=(
                not suppressed and entered_keyword in _CONDITIONAL_KEYWORDS
            ),
        )
        self._frames.append(frame)
        return frame

    def _record_direct_annotation(self, frame: _Frame) -> None:
        keyword = frame.entered_keyword
        if frame.ephemeral or keyword is None or frame.instance_token is None:
            return
        if keyword not in _PROPERTY_KEYWORDS and keyword not in _ITEM_KEYWORDS:
            return
        if not self._charge():
            return
        frame.annotations.append(
            EvaluationSource(
                instance_pointer=frame.instance_pointer,
                schema_pointer=frame.schema_pointer,
                keyword=keyword,
                via=tuple(frame.via),
                value=frame.instance if self.include_values else None,
                name=frame.instance_token,
                item=isinstance(frame.instance_token, int),
            ),
        )

    def add_error(self, frame: _Frame | None) -> None:
        if frame is not None and not frame.ephemeral:
            frame.errors += 1

    def keyword(self, keyword: str) -> _KeywordContext | None:
        frame = self._current()
        if frame is None or frame.ephemeral or not self.active:
            return None
        return _KeywordContext(self, frame, keyword)

    def end_frame(self, frame: _Frame | None) -> None:
        if frame is None:
            return
        # If the interpreter unwound past an interrupted ``begin`` (e.g. a
        # recursion error in a pathological cyclic schema), locate and pop
        # the frame rather than raising a secondary error.
        try:
            index = next(
                i
                for i, candidate in enumerate(self._frames)
                if candidate is frame
            )
        except StopIteration:
            return
        boundary = self._nearest_boundary(index)
        del self._frames[index]
        if frame.ephemeral:
            return

        parent = self._current()
        self._emit_branch_records(frame, parent)

        if parent is None:
            self._keyword_evaluations.extend(frame.keyword_evaluations)
            self._branches.extend(frame.branches)
            self._annotations.extend(frame.all_annotations())
            return

        # Keyword and branch observations always propagate, even for failed
        # branches.
        parent.keyword_evaluations.extend(frame.keyword_evaluations)
        parent.branches.extend(frame.branches)

        if frame.conditional and not frame.valid:
            # Failed anyOf/oneOf branch: its held annotations are dropped.
            return

        annotations = frame.annotations + frame.held
        if boundary is None:
            self._annotations.extend(annotations)
        else:
            boundary.held.extend(annotations)

    def branch(
        self,
        *,
        keyword: str,
        evaluated: bool,
        valid: bool | None,
        index: int | None = None,
        label: str | None = None,
        ref: str | None = None,
    ) -> None:
        """
        Record an explicit branch outcome.

        Used for the ``if`` result, branches which were not entered
        (``then`` / ``else`` and ``anyOf`` short-circuit skips), and the
        ``oneOf`` second-pass probes which do not descend.
        """
        frame = self._current()
        if frame is None or frame.ephemeral or not self.active:
            return
        if not self._charge():
            return
        if label is not None:
            branch_pointer = label
        elif index is not None:
            branch_pointer = str(index)
        else:
            branch_pointer = ""
        frame.branches.append(
            BranchEvaluation(
                keyword=keyword,
                instance_pointer=frame.instance_pointer,
                applicator_pointer=(
                    frame.schema_pointer + "/" + escape(keyword)
                ),
                branch_pointer=branch_pointer,
                evaluated=evaluated,
                valid=valid,
                ref=ref,
            ),
        )

    def evaluated_property(self, keyword: str, name: Any) -> None:
        self._evaluated(keyword=keyword, token=name, item=False)

    def evaluated_item(
        self,
        keyword: str,
        index: int,
        value: Any,
    ) -> None:
        self._evaluated(
            keyword=keyword,
            token=index,
            item=True,
            value=value,
        )

    def _evaluated(
        self,
        *,
        keyword: str,
        token: Any,
        item: bool,
        value: Any = None,
    ) -> None:
        frame = self._current()
        if frame is None or frame.ephemeral or not self.active:
            return
        if not self._charge():
            return
        instance_tokens = [*frame.instance_tokens, token]
        schema_tokens = [*frame.schema_tokens, keyword]
        annotation = EvaluationSource(
            instance_pointer=pointer(instance_tokens),
            schema_pointer=pointer(schema_tokens),
            keyword=keyword,
            via=tuple(frame.via),
            value=value if self.include_values else None,
            name=token,
            item=item,
        )
        index = next(
            i for i, candidate in enumerate(self._frames) if candidate is frame
        )
        boundary = self._nearest_boundary(index)
        if boundary is None:
            self._annotations.append(annotation)
        else:
            boundary.held.append(annotation)

    def build(self, errors: Iterable[Any] = ()) -> Explanation:
        """Build the final explanation after the traversal completed."""
        error_list = list(errors)
        return Explanation(
            valid=not error_list,
            keyword_evaluations=list(self._keyword_evaluations),
            branches=list(self._branches),
            evaluated_properties=list(
                _dedupe(
                    annotation
                    for annotation in self._annotations
                    if not annotation.item
                ),
            ),
            evaluated_items=list(
                _dedupe(
                    annotation
                    for annotation in self._annotations
                    if annotation.item
                ),
            ),
            truncated=self.truncated,
            include_values=self.include_values,
            errors=error_list,
        )


@define(slots=True)
class _KeywordContext:
    explainer: Explainer
    frame: _Frame
    keyword: str
    errors: int = 0
    previous: str | None = None

    def __enter__(self) -> _KeywordContext:  # noqa: PYI034
        self.previous = self.explainer._active_keyword
        self.explainer._active_keyword = self.keyword
        return self

    def add_error(self) -> None:
        self.errors += 1

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if self.explainer.active and self.explainer._charge():
                self.frame.keyword_evaluations.append(
                    KeywordEvaluation(
                        keyword=self.keyword,
                        instance_pointer=self.frame.instance_pointer,
                        schema_pointer=(
                            self.frame.schema_pointer
                            + "/"
                            + escape(self.keyword)
                        ),
                        valid=self.errors == 0,
                        via=tuple(self.frame.via),
                    ),
                )
        finally:
            self.explainer._active_keyword = self.previous


def _dedupe(
    annotations: Iterable[EvaluationSource],
) -> Iterable[EvaluationSource]:
    seen: set[tuple[Any, ...]] = set()
    for annotation in annotations:
        key = (
            annotation.instance_pointer,
            annotation.schema_pointer,
            annotation.keyword,
            annotation.via,
            annotation.name,
            annotation.item,
        )
        if key in seen:
            continue
        seen.add(key)
        yield annotation


@define(frozen=True, slots=True)
class Explanation:
    """
    The result of validating one instance with explanation enabled.

    The instance was validated under one schema.

    Attributes:

    valid:

        whether the instance was valid

    keyword_evaluations:

        each keyword that ran, with its instance/schema JSON Pointers and
        whether it succeeded, in execution order

    branches:

        each applicator branch (``allOf``, ``anyOf``, ``oneOf``,
        ``if``/``then``/``else``, references and ``dependentSchemas``),
        whether it was entered and whether it succeeded

    evaluated_properties:

        each evaluated object property and the location which evaluated it,
        in execution order (deduplicated)

    evaluated_items:

        each evaluated array item and the location which evaluated it, in
        execution order (deduplicated)

    truncated:

        whether the configured event/depth caps were reached

    errors:

        the `jsonschema.exceptions.ValidationError` objects produced by the
        normal traversal, in the same order as ``iter_errors``

    """

    valid: bool
    keyword_evaluations: list[KeywordEvaluation] = field(factory=list)
    branches: list[BranchEvaluation] = field(factory=list)
    evaluated_properties: list[EvaluationSource] = field(factory=list)
    evaluated_items: list[EvaluationSource] = field(factory=list)
    truncated: bool = False
    include_values: bool = False
    errors: list[Any] = field(factory=list)

    def sources_for(self, instance_pointer: str) -> list[EvaluationSource]:
        """Return the evaluation sources at the given JSON Pointer."""
        return [
            source
            for source in (
                *self.evaluated_properties,
                *self.evaluated_items,
            )
            if source.instance_pointer == instance_pointer
        ]

    def to_summary(self) -> dict[str, Any]:
        """Serialize the explanation to plain JSON-compatible data."""
        return {
            "valid": self.valid,
            "truncated": self.truncated,
            "keyword_evaluations": [
                evaluation.as_dict() for evaluation in self.keyword_evaluations
            ],
            "branches": [branch.as_dict() for branch in self.branches],
            "evaluated_properties": [
                source.as_dict(include_values=self.include_values)
                for source in self.evaluated_properties
            ],
            "evaluated_items": [
                source.as_dict(include_values=self.include_values)
                for source in self.evaluated_items
            ],
        }
