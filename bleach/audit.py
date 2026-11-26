from collections import Counter, defaultdict
from dataclasses import dataclass
from html.parser import HTMLParser


def _freeze(value):
    if isinstance(value, dict):
        return tuple((key, _freeze(item)) for key, item in sorted(value.items()))
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(_freeze(item) for item in value)
    return value


def _token_element(token):
    if token.get("type") not in ("StartTag", "EmptyTag"):
        return None

    attributes = tuple(
        (name, value)
        for (namespace, name), value in token.get("data", {}).items()
    )
    return ElementStructure(tag=token["name"], attributes=attributes)


def _record_structure(tokens, records):
    for token in tokens:
        element = _token_element(token)
        if element is not None:
            records.append(element)
        yield token


@dataclass(frozen=True)
class ElementStructure:
    tag: str
    attributes: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class StageAudit:
    name: str
    rule_source: tuple[tuple[str, object], ...]
    input_structure: tuple[ElementStructure, ...]
    output_structure: tuple[ElementStructure, ...]
    applied_tags: frozenset[str]
    applied_attributes: tuple[tuple[str, frozenset[str]], ...]
    changes: dict[str, dict[object, int]]


class _HTMLStructureParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.elements = []

    def handle_starttag(self, tag, attrs):
        self.elements.append(ElementStructure(tag=tag, attributes=tuple(attrs)))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


def extract_visible_structure(html):
    parser = _HTMLStructureParser()
    parser.feed(html)
    parser.close()
    return tuple(parser.elements)


def diff_structures(left, right):
    left_tags = Counter(element.tag for element in left)
    right_tags = Counter(element.tag for element in right)
    left_attributes = Counter(
        (element.tag, name, value)
        for element in left
        for name, value in element.attributes
    )
    right_attributes = Counter(
        (element.tag, name, value)
        for element in right
        for name, value in element.attributes
    )

    return {
        "added_tags": dict(sorted((right_tags - left_tags).items())),
        "removed_tags": dict(sorted((left_tags - right_tags).items())),
        "added_attributes": dict(sorted((right_attributes - left_attributes).items())),
        "removed_attributes": dict(
            sorted((left_attributes - right_attributes).items())
        ),
    }


def diff_visible_structure(left_html, right_html):
    return diff_structures(
        extract_visible_structure(left_html),
        extract_visible_structure(right_html),
    )


def validate_structure(html, allowed_tags, allowed_attributes=None):
    from bleach.sanitizer import attribute_filter_factory

    attributes = allowed_attributes if allowed_attributes is not None else {}
    attr_filter = attribute_filter_factory(attributes)
    violations = []

    for element in extract_visible_structure(html):
        if element.tag not in allowed_tags:
            violations.append({"type": "tag", "tag": element.tag})

        for name, value in element.attributes:
            if not attr_filter(element.tag, name, value):
                violations.append(
                    {
                        "type": "attribute",
                        "tag": element.tag,
                        "attribute": name,
                    }
                )

    return violations


class AuditedStageFilter:
    def __init__(
        self,
        source,
        stage_factory,
        name,
        rule_source,
        audit_trail,
        input_structure=None,
    ):
        self._source = source
        self._stage_factory = stage_factory
        self.name = name
        self.rule_source = _freeze(rule_source)
        self.audit_trail = audit_trail
        self.input_structure = input_structure

    def __iter__(self):
        input_structure = []
        recorded_source = _record_structure(self._source, input_structure)
        stage = self._stage_factory(recorded_source)

        output_structure = []
        recorded_stage = _record_structure(stage, output_structure)

        yield from recorded_stage
        self.audit_trail.add_stage(
            name=self.name,
            rule_source=self.rule_source,
            input_structure=(
                tuple(input_structure)
                if self.input_structure is None
                else tuple(self.input_structure)
            ),
            output_structure=tuple(output_structure),
        )


class AuditTrail:
    def __init__(self):
        self.stages = []

    def add_stage(self, name, rule_source, input_structure, output_structure):
        attributes = defaultdict(set)
        for element in output_structure:
            for attribute_name, _value in element.attributes:
                attributes[element.tag].add(attribute_name)

        stage = StageAudit(
            name=name,
            rule_source=rule_source,
            input_structure=input_structure,
            output_structure=output_structure,
            applied_tags=frozenset(element.tag for element in output_structure),
            applied_attributes=tuple(
                (tag, frozenset(attribute_names))
                for tag, attribute_names in sorted(attributes.items())
            ),
            changes=diff_structures(input_structure, output_structure),
        )
        self.stages.append(stage)
        return stage

    def stage(self, name):
        for stage in self.stages:
            if stage.name == name:
                return stage
        raise KeyError(name)
