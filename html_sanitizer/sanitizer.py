import re
import unicodedata
from collections import deque
from typing import NamedTuple

import lxml.html
import lxml.html.clean


__all__ = ("Sanitizer", "SanitizeResult", "SanitizeReport", "ProvenanceEvent")


#: Stage name used for everything present in the initial fragment, that is,
#: content written by the user and not introduced by a hook.
INITIAL_STAGE = "initial"


def sanitize_href(href):
    """
    Verify that a given href is benign and allowed.

    This is a stupid check, which probably should be much more elaborate
    to be safe.
    """
    if href.startswith(("/", "mailto:", "http:", "https:", "#", "tel:")):
        return href
    return "#"


typographic_whitespace_names = [
    "NO-BREAK SPACE",
    "EN QUAD",
    "EM QUAD",
    "EN SPACE",
    "EM SPACE",
    "THREE-PER-EM SPACE",
    "FOUR-PER-EM SPACE",
    "SIX-PER-EM SPACE",
    "FIGURE SPACE",
    "PUNCTUATION SPACE",
    "THIN SPACE",
    "HAIR SPACE",
    "NARROW NO-BREAK SPACE",
    "MEDIUM MATHEMATICAL SPACE",
    "IDEOGRAPHIC SPACE",
]

typographic_whitespace = "".join(
    {unicodedata.lookup(n) for n in typographic_whitespace_names}
)


def bold_span_to_strong(element):
    if element.tag == "span" and "bold" in element.get("style", ""):
        element.tag = "strong"
    return element


def italic_span_to_em(element):
    if element.tag == "span" and "italic" in element.get("style", ""):
        element.tag = "em"
    return element


def tag_replacer(from_, to_):
    def replacer(element):
        if element.tag == from_:
            element.tag = to_
        return element

    return replacer


def target_blank_noopener(element):
    if (
        element.tag == "a"
        and element.attrib.get("target") == "_blank"
        and "noopener" not in element.attrib.get("rel", "")
    ):
        element.attrib["rel"] = " ".join(
            part for part in (element.attrib.get("rel", ""), "noopener") if part
        )
    return element


def anchor_id_to_name(element):
    if (
        element.tag == "a"
        and element.attrib.get("id")
        and not element.attrib.get("name")
    ):
        element.attrib["name"] = element.attrib["id"]
    return element


def filter_control_characters(text):
    """Filter out control characters that lxml cannot handle."""
    if not text:
        return text
    return re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)


class ProvenanceEvent(NamedTuple):
    """
    A single entry of the provenance log.

    ``stage`` is the name of the stage which performed the action (the
    ``"initial"`` stage is the user-written fragment), ``action`` is one of
    ``"create"``, ``"set-attribute"``, ``"move"``, ``"unattributed"`` or
    ``"suspended"`` and ``detail`` is a short serialization of the affected
    node.
    """

    stage: str
    action: str
    detail: str


def _describe(element, max_length=200):
    detail = lxml.html.tostring(element, encoding="unicode")
    if len(detail) > max_length:
        detail = detail[:max_length] + "…"
    return detail


class _ProvenanceTracker:
    """
    Track which stage introduced which node while cleaning a fragment.

    Elements and attributes found in the initial fragment are attributed to
    the ``INITIAL_STAGE`` stage. Everything appearing while a declared hook
    (or another pipeline stage) runs is attributed to that stage. Moves keep
    the original attribution; only the move itself is logged.
    """

    def __init__(self, *, audit=False):
        self.audit = audit
        self.events = []
        self.unattributed = []
        self.suspended = []
        self.element_stages = {}
        self.attribute_stages = {}
        self.parents = {}
        self.root = None

    def initialize(self, root):
        self.root = root
        for el in root.iter():
            self.element_stages[el] = INITIAL_STAGE
            self.attribute_stages[el] = dict.fromkeys(el.attrib, INITIAL_STAGE)
            self.parents[el] = el.getparent()

    def _sync(self, root, stage):
        for el in root.iter():
            if el not in self.element_stages:
                self.element_stages[el] = stage
                self.attribute_stages[el] = dict.fromkeys(el.attrib, stage)
                self.parents[el] = el.getparent()
                if stage is not None:
                    self.events.append(ProvenanceEvent(stage, "create", _describe(el)))
                continue
            attributes = self.attribute_stages[el]
            for key in el.attrib:
                if key not in attributes:
                    attributes[key] = stage
                    if stage is not None:
                        self.events.append(
                            ProvenanceEvent(
                                stage,
                                "set-attribute",
                                f"<{el.tag} @{key}={el.get(key)!r}>",
                            )
                        )
            parent = el.getparent()
            if self.parents.get(el) is not parent:
                self.parents[el] = parent
                if stage is not None:
                    self.events.append(ProvenanceEvent(stage, "move", _describe(el)))

    def absorb(self, root):
        """Sync internal changes of the cleaning machinery without logging."""
        self._sync(root, None)

    def record(self, root, stage):
        """Attribute everything new since the last sync to ``stage``."""
        self._sync(root, stage)

    def check(self, root):
        """
        Check a (possibly re-mounted) tree against the recorded attribution.

        Returns events for all nodes which cannot be attributed to any
        declared stage. In audit mode those nodes are additionally suspended,
        that is, removed from the tree.
        """
        found = []
        for el in root.iter():
            if self.element_stages.get(el) is None:
                found.append(
                    (
                        ProvenanceEvent("unknown", "unattributed", _describe(el)),
                        el,
                        None,
                    )
                )
            else:
                for key in el.attrib:
                    if self.attribute_stages[el].get(key) is None:
                        found.append(
                            (
                                ProvenanceEvent(
                                    "unknown",
                                    "unattributed",
                                    f"<{el.tag} @{key}={el.get(key)!r}>",
                                ),
                                el,
                                key,
                            )
                        )
        events = []
        for event, el, key in found:
            events.append(event)
            self.unattributed.append(event)
            if self.audit:
                self.suspended.append(
                    ProvenanceEvent(event.stage, "suspended", event.detail)
                )
                if key is None:
                    if el.getparent() is not None:
                        el.drop_tree()
                else:
                    del el.attrib[key]
        return events


class SanitizeReport:
    """
    Provenance report of a :meth:`Sanitizer.sanitize_with_report` call.

    ``events`` lists everything hooks and pipeline stages introduced,
    ``unattributed`` lists generated nodes which could not be attributed to
    any declared stage and ``suspended`` lists the nodes which were held
    back because of that (audit mode only).
    """

    def __init__(self, tracker):
        self._tracker = tracker

    @property
    def events(self):
        return self._tracker.events

    @property
    def unattributed(self):
        return self._tracker.unattributed

    @property
    def suspended(self):
        return self._tracker.suspended

    def origin_of(self, element):
        """Return the stage which introduced ``element``, or ``None``."""
        return self._tracker.element_stages.get(element)

    def find(self, text):
        """Return all events whose detail contains ``text``."""
        return [event for event in self.events if text in event.detail]

    def recheck(self, tree):
        """
        Check a tree against the final attribution, e.g. after it has been
        re-mounted (and possibly modified) following the cleaning pass.
        """
        return self._tracker.check(tree)


class SanitizeResult:
    """
    Result of :meth:`Sanitizer.sanitize_with_report`.

    ``html`` is the cleaned fragment, ``report`` the provenance report and
    ``tree`` the (still live) element tree, wrapped in a ``<div>`` element,
    which allows inspecting origins via ``report.origin_of(element)``.
    """

    def __init__(self, *, html, report, tree):
        self.html = html
        self.report = report
        self.tree = tree

    def __str__(self):
        return self.html


def normalize_whitespace_in_text_or_tail(
    element,
    *,
    whitespace_re=None,
    keep_typographic_whitespace=False,
    normalize_text=True,
    normalize_tail=True,
):
    # Always filter control characters regardless of whitespace settings
    if element.text:
        element.text = filter_control_characters(element.text)
    if element.tail:
        element.tail = filter_control_characters(element.tail)

    if keep_typographic_whitespace:
        return element

    if whitespace_re is None:
        whitespace_re = re.compile(r"\s+")
    if element.text and normalize_text:
        while True:
            text = whitespace_re.sub(" ", element.text)
            if element.text == text:
                break
            element.text = text

    if element.tail and normalize_tail:
        while True:
            text = whitespace_re.sub(" ", element.tail)
            if element.tail == text:
                break
            element.tail = text

    return element


DEFAULT_SETTINGS = {
    "tags": {
        "a",
        "h1",
        "h2",
        "h3",
        "strong",
        "em",
        "p",
        "ul",
        "ol",
        "li",
        "br",
        "sub",
        "sup",
        "hr",
    },
    "attributes": {"a": ("href", "name", "target", "title", "rel")},
    "empty": {"hr", "a", "br"},
    "separate": {"a", "p", "li"},
    "whitespace": {"br"},
    "preserve_whitespace": {"pre"},
    "keep_typographic_whitespace": False,
    "drop_disallowed_contents": False,
    "add_nofollow": False,
    "autolink": False,
    "audit": False,
    "embedded_hosts": set(),
    "sanitize_href": sanitize_href,
    "element_preprocessors": [
        # convert span elements into em/strong if a matching style rule
        # has been found. strong has precedence, strong & em at the same
        # time is not supported
        bold_span_to_strong,
        italic_span_to_em,
        tag_replacer("b", "strong"),
        tag_replacer("i", "em"),
        tag_replacer("form", "p"),
        target_blank_noopener,
        anchor_id_to_name,
    ],
    "element_postprocessors": [],
}


def coerce_to_set(value):
    if isinstance(value, set):
        return value
    elif isinstance(value, tuple | list):
        return set(value)
    raise TypeError(f"Expected a set but got value {value!r} of type {type(value)}")


class Sanitizer:
    def __init__(self, settings=None):
        self.__dict__.update(DEFAULT_SETTINGS)
        self.__dict__.update(settings or {})

        # Allow iterables of any kind, not just sets.
        self.tags = coerce_to_set(self.tags)
        self.empty = coerce_to_set(self.empty)
        self.separate = coerce_to_set(self.separate)
        self.whitespace = coerce_to_set(self.whitespace)
        self.embedded_hosts = coerce_to_set(self.embedded_hosts)
        # Preserving whitespace inside tags which are removed later would
        # leak unnormalized whitespace into the output.
        self.preserve_whitespace = coerce_to_set(self.preserve_whitespace) & self.tags
        self.attributes = {
            tag: coerce_to_set(attributes)
            for tag, attributes in self.attributes.items()
        }

        # Hooks may be declared as (name, callable) pairs so that the
        # provenance log can attribute their changes to a meaningful stage
        # name. Plain callables fall back to their __name__.
        self._hook_names = {}
        for key in ("element_preprocessors", "element_postprocessors"):
            hooks = []
            for declared in getattr(self, key):
                if isinstance(declared, tuple):
                    name, hook = declared
                else:
                    hook = declared
                    name = getattr(hook, "__name__", type(hook).__name__)
                self._hook_names[hook] = name
                hooks.append(hook)
            setattr(self, key, hooks)

        if self.keep_typographic_whitespace:
            re_whitespace = r"[^\S%s]" % typographic_whitespace
        else:
            re_whitespace = r"\s"

        self.only_whitespace_re = re.compile(rf"^{re_whitespace}*$")
        self.whitespace_re = re.compile(rf"{re_whitespace}+")

        # Validate the settings.
        if not self.tags:
            raise TypeError(
                "Empty list of allowed tags is not supported by the underlying"
                " lxml cleaner. If you really do not want to pass any tags"
                " pass a made-up tag name which will never exist in your"
                " document."
            )
        if not self.tags.issuperset(self.empty):
            raise TypeError(
                f'Tags in "empty", but not allowed: {self.empty - self.tags!r}'
            )
        if not self.tags.issuperset(self.separate):
            raise TypeError(
                f'Tags in "separate", but not allowed: {self.separate - self.tags!r}'
            )
        if not self.tags.issuperset(self.attributes.keys()):
            raise TypeError(
                f'Tags in "attributes", but not allowed: {set(self.attributes.keys()) - self.tags!r}'
            )

        anchor_attributes = self.attributes.get("a", ())
        if "target" in anchor_attributes and "rel" not in anchor_attributes:
            raise TypeError(
                'Always allow "rel" when allowing "target" as anchor attribute'
            )

    @staticmethod
    def is_mergeable(e1, e2):
        """
        Decide if the adjacent elements of the same type e1 and e2 can be
        merged. This can be overriden to honouring distinct classes etc.
        """
        return True

    def normalize_whitespace(self, element):
        inside = any(e.tag in self.preserve_whitespace for e in element.iterancestors())
        return normalize_whitespace_in_text_or_tail(
            element,
            whitespace_re=self.whitespace_re,
            keep_typographic_whitespace=self.keep_typographic_whitespace,
            normalize_text=not inside and element.tag not in self.preserve_whitespace,
            normalize_tail=not inside,
        )

    def sanitize(self, html):
        """
        Clean HTML code from ugly copy-pasted CSS and empty elements

        Removes everything not explicitly allowed in ``self.allowed_tags``.

        Requires ``lxml`` and, for especially broken HTML, ``beautifulsoup4``.
        """
        return self._sanitize(html)

    def sanitize_with_report(self, html):
        """
        Clean HTML like :meth:`sanitize`, but additionally track the
        provenance of every node: content of the initial fragment is
        attributed to the ``"initial"`` stage, everything hooks and other
        pipeline stages introduce is attributed to the responsible stage.

        Returns a :class:`SanitizeResult`. If the ``audit`` setting is
        enabled, generated nodes which cannot be attributed to any declared
        stage are suspended (held back from the output).
        """
        tracker = _ProvenanceTracker(audit=self.audit)
        html = self._sanitize(html, tracker=tracker)
        return SanitizeResult(
            html=html, report=SanitizeReport(tracker), tree=tracker.root
        )

    def _sanitize(self, html, tracker=None):  # noqa: C901 -- I know.
        # normalize unicode
        if self.keep_typographic_whitespace:
            html = unicodedata.normalize("NFC", html)
        else:
            html = unicodedata.normalize("NFKC", html)

        html = "<div>%s</div>" % html
        try:
            doc = lxml.html.fromstring(html)
            lxml.html.tostring(doc, encoding="utf-8")
        except Exception:
            from lxml.html import soupparser  # noqa: PLC0415

            doc = soupparser.fromstring(html)

        lxml.html.clean.Cleaner(
            remove_unknown_tags=False,
            # Remove style *tags* if not explicitly allowed
            style="style" not in self.tags,
            # Do not strip out style attributes; we still need the style
            # information to convert spans into em/strong tags
            safe_attrs_only=False,
            inline_style=False,
            # Do not strip all form tags; we will filter them below
            forms=False,
            host_whitelist=self.embedded_hosts,
        )(doc)

        if tracker is not None:
            tracker.initialize(doc)

        # walk the tree recursively, because we want to be able to remove
        # previously emptied elements completely
        backlog = deque(doc.iterdescendants())

        doc = self.normalize_whitespace(doc)

        while True:
            try:
                element = backlog.pop()
            except IndexError:
                break

            if tracker is not None:
                tracker.absorb(doc)

            for processor in self.element_preprocessors:
                element = processor(element)
                if tracker is not None:
                    tracker.record(doc, self._hook_names.get(processor, "unknown-hook"))

            if self.drop_disallowed_contents and element.tag not in self.tags:
                element.drop_tree()
                continue

            element = self.normalize_whitespace(element)

            # remove empty tags if they are not explicitly allowed
            if (
                (not element.text or self.only_whitespace_re.match(element.text))
                and element.tag not in self.empty
                and not len(element)
            ):
                element.drop_tag()
                continue

            # remove tags which only contain whitespace and/or <br>s
            if (
                element.tag not in self.empty
                and self.only_whitespace_re.match(element.text or "")
                and {e.tag for e in element} <= self.whitespace
                and all(self.only_whitespace_re.match(e.tail or "") for e in element)
            ):
                element.drop_tree()
                continue

            if element.tag in {"li", "p"}:
                # remove p-in-li and p-in-p tags
                for p in element.findall("p"):
                    if getattr(p, "text", None):
                        p.text = " " + p.text + " "
                    p.drop_tag()

                # remove list markers, maybe copy-pasted from word or whatever
                if element.text:
                    element.text = filter_control_characters(
                        re.sub(r"^\s*(-|\*|&#183;)\s+", "", element.text)
                    )

            elif element.tag in self.whitespace:
                # Drop the next element if
                # 1. it is a <br> too and 2. there is no content in-between
                nx = element.getnext()
                if (
                    nx is not None
                    and nx.tag == element.tag
                    and (
                        not element.tail or self.only_whitespace_re.match(element.tail)
                    )
                ):
                    nx.drop_tag()

            if not element.text:
                # No text before first child and first child is a <br>: Drop it
                first = next(iter(element), None)
                if first is not None and first.tag in self.whitespace:
                    first.drop_tag()
                    # Maybe we have more than one <br>
                    backlog.append(element)
                    continue

            if element.tag in (self.tags - self.separate):
                # Check whether we should merge adjacent elements of the same
                # tag type
                nx = element.getnext()
                if (
                    self.only_whitespace_re.match(element.tail or "")
                    and nx is not None
                    and nx.tag == element.tag
                    and self.is_mergeable(element, nx)
                ):
                    # Yes, we should. Tail is empty, that is, no text between
                    # tags of a mergeable type.
                    if nx.text:
                        if len(element):
                            list(element)[-1].tail = "{}{}".format(
                                list(element)[-1].tail or "",
                                nx.text,
                            )
                        else:
                            element.text = "{}{}{}".format(
                                element.text or "", element.tail or "", nx.text
                            )

                    for child in nx:
                        element.append(child)

                    # tail is merged with previous element.
                    element.tail = nx.tail
                    nx.getparent().remove(nx)

                    # Process element again
                    backlog.append(element)
                    continue

            if tracker is not None:
                tracker.absorb(doc)

            for processor in self.element_postprocessors:
                element = processor(element)
                if tracker is not None:
                    tracker.record(doc, self._hook_names.get(processor, "unknown-hook"))

            # remove all attributes which are not explicitly allowed
            allowed = self.attributes.get(element.tag, [])
            for key in element.keys():  # noqa: SIM118 (do not remove .keys())
                if key not in allowed:
                    del element.attrib[key]
                elif not self.keep_typographic_whitespace:
                    element.set(key, self.whitespace_re.sub(" ", element.get(key)))

            # Clean hrefs so that they are benign
            href = element.get("href")
            if href is not None:
                element.set("href", self.sanitize_href(href))

            element = self.normalize_whitespace(element)

        if self.autolink is True:
            lxml.html.clean.autolink(doc)
        elif isinstance(self.autolink, dict):
            lxml.html.clean.autolink(doc, **self.autolink)

        if tracker is not None and self.autolink:
            tracker.record(doc, "autolink")

        # Run cleaner again, but this time with even more strict settings
        lxml.html.clean.Cleaner(
            allow_tags=self.tags,
            remove_unknown_tags=False,
            safe_attrs_only=False,  # Our attributes allowlist is sufficient.
            add_nofollow=self.add_nofollow,
            forms=False,
            host_whitelist=self.embedded_hosts,
        )(doc)

        if tracker is not None:
            tracker.record(doc, "clean")
            # Final attribution check of the cleaned tree, before it is
            # serialized and possibly re-mounted elsewhere.
            tracker.check(doc)
            tracker.root = doc

        html = lxml.html.tostring(doc, encoding="unicode")

        # add a space before the closing slash in empty tags
        html = re.sub(r"<([^/>]+)/>", r"<\1 />", html)

        # remove wrapping tag needed by XML parser
        html = re.sub(r"^<div>|</div>$", "", html)

        return html
