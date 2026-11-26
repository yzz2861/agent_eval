from copy import deepcopy
import re

from bleach import html5lib_shim
from bleach.sanitizer import (
    ALLOWED_ATTRIBUTES,
    ALLOWED_PROTOCOLS,
    ALLOWED_TAGS,
    BleachSanitizerFilter,
)


TOKENIZER_STAGE = "tokenizer.disallowed-tag"
SANITIZER_STAGE = "sanitizer.attribute-policy"


class AuditTokenizer(html5lib_shim.BleachHTMLTokenizer):
    def __init__(self, *args, audit_receipts, **kwargs):
        super().__init__(*args, **kwargs)
        self.audit_receipts = audit_receipts

    def emitCurrentToken(self):
        token = self.currentToken
        receipt_index = None
        if (
            self.parser.tags is not None
            and token["type"] in html5lib_shim.TAG_TOKEN_TYPES
            and token["name"].lower() not in self.parser.tags
            and self.parser.strip
        ):
            source_span = self._source_span(self.stream.get_tag())
            receipt_index = len(self.audit_receipts)
            self.audit_receipts.append(
                {
                    "action": "strip-tag",
                    "stage": TOKENIZER_STAGE,
                    "source_span": source_span,
                    "source_text": self.stream.get_tag(),
                    "token": deepcopy(token),
                    "result_token": None,
                    "reason": "tag is not in the allowed tag policy",
                }
            )

        super().emitCurrentToken()
        if receipt_index is None:
            return
        self.audit_receipts[receipt_index]["result_token"] = deepcopy(self.currentToken)

    def _source_span(self, source_text):
        inner_stream = self.stream._inner_stream
        stream_position = inner_stream.dataStream.tell()
        unread_characters = inner_stream.chunkSize - inner_stream.chunkOffset
        start = stream_position - unread_characters - len(source_text)
        return {"start": start, "end": start + len(source_text)}


class AuditParser(html5lib_shim.BleachHTMLParser):
    def __init__(self, *args, audit_receipts, **kwargs):
        self.audit_receipts = audit_receipts
        super().__init__(*args, **kwargs)

    def _parse(
        self, stream, innerHTML=False, container="div", scripting=True, **kwargs
    ):
        self.innerHTMLMode = innerHTML
        self.container = container
        self.scripting = scripting
        self.tokenizer = AuditTokenizer(
            stream=stream,
            consume_entities=self.consume_entities,
            parser=self,
            audit_receipts=self.audit_receipts,
            **kwargs,
        )
        self.reset()
        try:
            self.mainLoop()
        except html5lib_shim.ReparseException:
            self.reset()
            self.mainLoop()


class AuditSanitizerFilter(BleachSanitizerFilter):
    def __init__(self, *args, audit_receipts, source_html, **kwargs):
        super().__init__(*args, **kwargs)
        self.audit_receipts = audit_receipts
        self.source_html = source_html
        self.tag_occurrences = {}

    def allow_token(self, token):
        if "data" not in token:
            return super().allow_token(token)

        original_token = deepcopy(token)
        sanitized_token = super().allow_token(deepcopy(token))
        original_attributes = original_token["data"]
        retained_attributes = sanitized_token["data"]
        tag_name = original_token["name"]
        occurrence = self.tag_occurrences.get(tag_name, 0)
        self.tag_occurrences[tag_name] = occurrence + 1
        raw_tag, raw_tag_start = self._raw_tag(tag_name, occurrence)

        for namespaced_name, value in original_attributes.items():
            if namespaced_name in retained_attributes:
                continue

            _, name = namespaced_name
            attribute_match = self._attribute_match(raw_tag, name)
            if attribute_match is None:
                source_text = f'{name}="{value}"'
                source_start = -1
                source_end = source_start + len(source_text)
            else:
                source_start = raw_tag_start + attribute_match.start() + 1
                source_end = raw_tag_start + attribute_match.end()
                source_text = self.source_html[source_start:source_end]
            self.audit_receipts.append(
                {
                    "action": "drop-attribute",
                    "stage": SANITIZER_STAGE,
                    "source_span": {"start": source_start, "end": source_end},
                    "source_text": source_text,
                    "token": deepcopy(original_token),
                    "result_token": deepcopy(sanitized_token),
                    "reason": "attribute is not in the allowed attribute policy",
                }
            )

        return sanitized_token

    def _raw_tag(self, tag_name, occurrence):
        matches = list(
            re.finditer(rf"<{re.escape(tag_name)}\b[^>]*>", self.source_html)
        )
        if not matches:
            return self.source_html, 0
        match = matches[occurrence] if occurrence < len(matches) else matches[-1]
        return match.group(0), match.start()

    def _attribute_match(self, raw_tag, attribute_name):
        pattern = (
            rf"""\s{re.escape(attribute_name)}(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?"""
        )
        return re.search(pattern, raw_tag)


def audit_clean(
    text,
    tags=ALLOWED_TAGS,
    attributes=ALLOWED_ATTRIBUTES,
    protocols=ALLOWED_PROTOCOLS,
    strip=False,
    strip_comments=True,
    css_sanitizer=None,
):
    receipts = []
    parser = AuditParser(
        tags=tags,
        strip=strip,
        consume_entities=False,
        namespaceHTMLElements=False,
        audit_receipts=receipts,
    )
    walker = html5lib_shim.getTreeWalker("etree")
    serializer = html5lib_shim.BleachHTMLSerializer(
        quote_attr_values="always",
        omit_optional_tags=False,
        escape_lt_in_attrs=True,
        resolve_entities=False,
        sanitize=False,
        alphabetical_attributes=False,
    )
    dom = parser.parseFragment(text)
    filtered = AuditSanitizerFilter(
        source=walker(dom),
        allowed_tags=tags,
        attributes=attributes,
        strip_disallowed_tags=strip,
        strip_html_comments=strip_comments,
        css_sanitizer=css_sanitizer,
        allowed_protocols=protocols,
        audit_receipts=receipts,
        source_html=text,
    )
    cleaned = serializer.render(filtered)
    for receipt in receipts:
        receipt["cleaned_span"] = _cleaned_span(text, cleaned, receipt)
    return {"cleaned": cleaned, "receipts": receipts}


def _cleaned_span(source_html, cleaned, receipt):
    if receipt["action"] == "strip-tag":
        start = _cleaned_text_position(
            source_html, receipt["source_span"]["start"], cleaned
        )
        return {"start": start, "end": start}

    token = receipt["token"]
    retained_attributes = _retained_attributes(cleaned, token["name"])
    start = len(f"<{token['name']}")
    if retained_attributes:
        start += 1
    return {"start": start, "end": start}


def _cleaned_text_position(source_html, source_position, cleaned):
    remaining = source_html[:source_position]
    remaining = re.sub(r"<[^>]*>", "", remaining)
    position = 0
    for character in remaining:
        if position >= len(cleaned):
            break
        if cleaned[position] == character:
            position += 1
    return position


def _retained_attributes(cleaned, tag_name):
    match = re.search(rf"<{re.escape(tag_name)}\b([^>]*)>", cleaned)
    if match is None:
        return ""
    return match.group(1).strip()
