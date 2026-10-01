"""
Diagnostic explanation data collected during a single validation run.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
import contextlib


DEFAULT_EXPLANATION_LIMIT = 10_000


def json_pointer(segments: Sequence[str | int]) -> str:
    pointer = ""
    for segment in segments:
        segment = str(segment)
        pointer += "/" + segment.replace("~", "~0").replace("/", "~1")
    return pointer


@dataclass(frozen=True)
class KeywordEvaluation:
    """The outcome of evaluating one keyword in one schema node."""

    instance: str
    schema: str
    keyword: str
    status: str
    error_count: int = 0
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class BranchEvaluation:
    """The outcome of one applicator branch or reference target."""

    instance: str
    schema: str
    keyword: str
    branch: str | int
    status: str
    error_count: int = 0
    resolved_schema: str | None = None


@dataclass(frozen=True)
class EvaluationSource:
    """One reason a property or array item was treated as evaluated."""

    keyword: str
    schema: str
    branch: str | int | None = None
    target: str | None = None


@dataclass(frozen=True)
class EvaluatedProperty:
    instance: str
    name: str
    sources: tuple[EvaluationSource, ...]


@dataclass(frozen=True)
class EvaluatedItem:
    instance: str
    index: int
    sources: tuple[EvaluationSource, ...]


@dataclass
class Explanation:
    valid: bool | None = None
    keywords: list[KeywordEvaluation] = field(default_factory=list)
    branches: list[BranchEvaluation] = field(default_factory=list)
    evaluated_properties: list[EvaluatedProperty] = field(default_factory=list)
    evaluated_items: list[EvaluatedItem] = field(default_factory=list)
    truncated: bool = False
    limit: int = DEFAULT_EXPLANATION_LIMIT

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "keywords": [
                {
                    "instance": each.instance,
                    "schema": each.schema,
                    "keyword": each.keyword,
                    "status": each.status,
                    "errorCount": each.error_count,
                    "errors": list(each.errors),
                }
                for each in self.keywords
            ],
            "branches": [
                {
                    "instance": each.instance,
                    "schema": each.schema,
                    "keyword": each.keyword,
                    "branch": each.branch,
                    "status": each.status,
                    "errorCount": each.error_count,
                    "resolvedSchema": each.resolved_schema,
                }
                for each in self.branches
            ],
            "evaluatedProperties": [
                {
                    "instance": each.instance,
                    "name": each.name,
                    "sources": [
                        {
                            "keyword": source.keyword,
                            "schema": source.schema,
                            "branch": source.branch,
                            "target": source.target,
                        }
                        for source in each.sources
                    ],
                }
                for each in self.evaluated_properties
            ],
            "evaluatedItems": [
                {
                    "instance": each.instance,
                    "index": each.index,
                    "sources": [
                        {
                            "keyword": source.keyword,
                            "schema": source.schema,
                            "branch": source.branch,
                            "target": source.target,
                        }
                        for source in each.sources
                    ],
                }
                for each in self.evaluated_items
            ],
            "truncated": self.truncated,
            "limit": self.limit,
        }


class RecursionStopped:
    pass


BRANCH_KEYWORDS = frozenset(
    {
        "allOf",
        "anyOf",
        "oneOf",
        "if",
        "$ref",
        "$dynamicRef",
        "$recursiveRef",
    },
)


class _Frame:
    def __init__(
        self,
        collector: ExplanationCollector,
        instance_path: tuple[str | int, ...],
        schema_path: tuple[str | int, ...],
        schema_uri: str | None,
        report_schema_path: tuple[str | int, ...],
        source: tuple[
            str,
            str | int | None,
            str | None,
            str | None,
        ] | None,
        commit_on_success: bool,
    ):
        self.collector = collector
        self.instance_path = instance_path
        self.schema_path = schema_path
        self.schema_uri = schema_uri
        self.report_schema_path = report_schema_path
        self.source = source
        self.commit_on_success = commit_on_success
        self.keyword: str | None = None
        self.branch: str | int | None = None
        self.errors: list[str] = []
        self.error_count = 0
        self.properties: dict[str, list[EvaluationSource]] = {}
        self.items: dict[int, list[EvaluationSource]] = {}

    @property
    def instance_pointer(self) -> str:
        return json_pointer(self.instance_path)

    @property
    def schema_pointer(self) -> str:
        if self.schema_uri is not None:
            return self.schema_uri
        return json_pointer(self.schema_path)

    def source_record(self) -> EvaluationSource:
        if self.source is not None:
            keyword, branch, target, source_schema = self.source
        else:
            keyword = self.keyword or "schema"
            branch = target = source_schema = None
        return EvaluationSource(
            keyword=keyword,
            schema=source_schema or self.schema_pointer,
            branch=branch,
            target=target,
        )

    def annotate_property(self, name: str) -> None:
        self.properties.setdefault(str(name), []).append(self.source_record())

    def annotate_item(self, index: int) -> None:
        self.items.setdefault(index, []).append(self.source_record())

    def inherit(self, child: _Frame, success: bool) -> None:
        self.error_count += child.error_count
        if child.commit_on_success and not success:
            return
        source = (
            child.source_record()
            if child.source is not None
            and child.source[0] in BRANCH_KEYWORDS
            else None
        )
        for name, sources in child.properties.items():
            inherited = self.properties.setdefault(name, [])
            inherited.extend(sources)
            if source is not None and source not in inherited:
                inherited.append(source)
        for index, sources in child.items.items():
            inherited = self.items.setdefault(index, [])
            inherited.extend(sources)
            if source is not None and source not in inherited:
                inherited.append(source)

    def commit(self, success: bool) -> None:
        parent = self.collector.stack[-2] if len(self.collector.stack) > 1 else None
        if self.source is not None and self.source[0] in BRANCH_KEYWORDS:
            keyword, branch, target, _ = self.source
            self.collector.branch(
                keyword=keyword,
                branch=branch if branch is not None else 0,
                success=success,
                error_count=self.error_count,
                resolved_schema=target,
            )
        if parent is not None:
            parent.inherit(self, success)
            return
        if self.commit_on_success and not success:
            return
        self.collector.commit_frame(self)


class ExplanationCollector:
    def __init__(
        self,
        *,
        limit: int = DEFAULT_EXPLANATION_LIMIT,
        include_values: bool = False,
    ):
        self.include_values = include_values
        self.limit = limit
        self.record_count = 0
        self.explanation = Explanation(limit=limit)
        self.stack: list[_Frame] = []
        self._active_refs: set[tuple[int, str]] = set()

    def _record(self) -> bool:
        if self.record_count >= self.limit:
            self.explanation.truncated = True
            return False
        self.record_count += 1
        return True

    @contextlib.contextmanager
    def schema(
        self,
        *,
        instance_path: tuple[str | int, ...],
        schema_path: tuple[str | int, ...],
        schema_uri: str | None = None,
        report_schema_path: tuple[str | int, ...] | None = None,
        source: tuple[
            str,
            str | int | None,
            str | None,
            str | None,
        ] | None = None,
        commit_on_success: bool = False,
        recursive_key: tuple[int, str] | None = None,
    ):
        if recursive_key is not None and recursive_key in self._active_refs:
            yield RecursionStopped
            return

        if recursive_key is not None:
            self._active_refs.add(recursive_key)
        frame = _Frame(
            self,
            instance_path,
            schema_path,
            schema_uri,
            schema_path if report_schema_path is None else report_schema_path,
            source,
            commit_on_success,
        )
        self.stack.append(frame)
        success = False
        try:
            yield frame
            success = frame.error_count == 0
        finally:
            frame.commit(success)
            self.stack.pop()
            if recursive_key is not None:
                self._active_refs.discard(recursive_key)

    @contextlib.contextmanager
    def keyword(self, keyword: str):
        frame = self.stack[-1]
        previous = frame.keyword
        frame.keyword = keyword
        errors: list[str] = []
        state = {"error_count": 0}
        try:
            yield state, errors
        finally:
            frame.keyword = previous
            status = "passed" if state["error_count"] == 0 else "failed"
            frame.error_count += state["error_count"]
            if self._record():
                self.explanation.keywords.append(
                    KeywordEvaluation(
                        instance=frame.instance_pointer,
                        schema=frame.schema_pointer,
                        keyword=keyword,
                        status=status,
                        error_count=state["error_count"],
                        errors=tuple(errors),
                    ),
                )
            frame.errors.extend(errors)

    def branch(
        self,
        *,
        keyword: str,
        branch: str | int,
        success: bool | None,
        error_count: int,
        resolved_schema: str | None = None,
        status: str | None = None,
    ) -> None:
        frame = self.stack[-1]
        if not self._record():
            return
        self.explanation.branches.append(
            BranchEvaluation(
                instance=frame.instance_pointer,
                schema=json_pointer(frame.report_schema_path),
                keyword=keyword,
                branch=branch,
                status=status
                or ("passed" if success else "failed"),
                error_count=error_count,
                resolved_schema=resolved_schema,
            ),
        )

    def annotate_property(self, name: str) -> None:
        self.stack[-1].annotate_property(name)

    def annotate_item(self, index: int) -> None:
        self.stack[-1].annotate_item(index)

    def evaluated_properties(self) -> set[str]:
        pointer = json_pointer(self.stack[-1].instance_path)
        return {
            each.name
            for each in self.explanation.evaluated_properties
            if each.instance == pointer
        }

    def evaluated_items(self) -> set[int]:
        pointer = json_pointer(self.stack[-1].instance_path)
        return {
            each.index
            for each in self.explanation.evaluated_items
            if each.instance == pointer
        }

    def commit_frame(self, frame: _Frame) -> None:
        pointer = frame.instance_pointer
        self._commit_properties(pointer, frame.properties)
        self._commit_items(pointer, frame.items)

    def _commit_properties(
        self,
        pointer: str,
        properties: dict[str, list[EvaluationSource]],
    ) -> None:
        existing = {
            each.name: each
            for each in self.explanation.evaluated_properties
            if each.instance == pointer
        }
        for name, sources in properties.items():
            if not self._record():
                break
            current = existing.get(name)
            all_sources = (
                tuple(current.sources if current else ()) + tuple(sources)
            )
            record = EvaluatedProperty(pointer, name, all_sources)
            if current is None:
                self.explanation.evaluated_properties.append(record)
            else:
                index = self.explanation.evaluated_properties.index(current)
                self.explanation.evaluated_properties[index] = record

    def _commit_items(
        self,
        pointer: str,
        items: dict[int, list[EvaluationSource]],
    ) -> None:
        existing = {
            each.index: each
            for each in self.explanation.evaluated_items
            if each.instance == pointer
        }
        for index, sources in items.items():
            if not self._record():
                break
            current = existing.get(index)
            all_sources = (
                tuple(current.sources if current else ()) + tuple(sources)
            )
            record = EvaluatedItem(pointer, index, all_sources)
            if current is None:
                self.explanation.evaluated_items.append(record)
            else:
                item_index = self.explanation.evaluated_items.index(current)
                self.explanation.evaluated_items[item_index] = record
