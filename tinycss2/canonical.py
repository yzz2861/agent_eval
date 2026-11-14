"""
Canonical view of declaration lists.

This module builds on :func:`tinycss2.parse_declaration_list` to give
declarations a stable, comparable identity: property names are normalized
according to CSS rules (ASCII lower case, except custom properties which
are case sensitive), values are serialized from their tokens, and the
``!important`` flag is reduced to a single boolean no matter how it was
written in the source (``!important``, ``! important``, ``!IMPORTANT``...).

Duplicate declarations are kept in source order, and the final cascaded
value of each property is available for auditing.  Parse problems are
classified (invalid ``!important``, empty property name, bad string...)
instead of being silently dropped.

:class:`DeclarationPolicy` can then *flag* declarations (unsafe property,
forbidden ``!important``, locked custom-property prefix) without ever
rewriting them, so the semantics of valid CSS are preserved.

"""

from webencodings import ascii_lower

from .parser import parse_declaration_list
from .serializer import serialize

__all__ = [
    'CanonicalDeclaration',
    'CanonicalDeclarationList',
    'DeclarationIssue',
    'DeclarationPolicy',
    'canonical_name',
    'canonicalize_declarations',
]

_ERROR_KINDS = {
    'bad-string': 'bad-string',
    'eof-in-string': 'bad-string',
    'bad-url': 'bad-url',
    'eof-in-url': 'bad-url',
}


def canonical_name(name):
    """Return the canonical form of a property or descriptor name.

    Custom properties (starting with ``--``) are case sensitive and kept
    as-is; every other name is normalized to ASCII lower case.

    """
    if name.startswith('--'):
        return name
    return ascii_lower(name)


class DeclarationIssue:
    """A classified problem found in a declaration list.

    .. attribute:: kind

        Machine-readable string.  One of ``'invalid-important'``,
        ``'empty-name'``, ``'bad-string'``, ``'bad-url'``,
        ``'unmatched-bracket'``, ``'invalid'``, ``'unsupported'``, or a
        policy violation: ``'forbidden-property'``,
        ``'forbidden-important'``, ``'locked-variable'``.

    .. attribute:: message

        Human-readable explanation of the problem.

    .. attribute:: source_line
    .. attribute:: source_column

        Position of the problem in the CSS source, starting at 1.

    """
    __slots__ = ['kind', 'message', 'source_column', 'source_line']

    def __init__(self, line, column, kind, message):
        self.source_line = line
        self.source_column = column
        self.kind = kind
        self.message = message

    def __repr__(self):
        return f'<DeclarationIssue {self.kind}>'


def _token_end_position(token):
    """Return the (line, column) just after the last character of a token."""
    chunks = []
    token._serialize_to(chunks.append)
    text = ''.join(chunks)
    if '\n' in text:
        return (
            token.source_line + text.count('\n'),
            len(text.rsplit('\n', 1)[1]) + 1)
    return token.source_line, token.source_column + len(text)


def _scan_value_tokens(tokens, issues):
    """Classify invalid ``!important`` and bad tokens in a declaration value.

    Only top-level ``!`` literals are invalid ``important`` markers; bad
    strings and URLs are looked for recursively, inside blocks too.

    """
    stack = list(tokens)
    for token in tokens:
        if token.type == 'literal' and token.value == '!':
            issues.append(DeclarationIssue(
                token.source_line, token.source_column, 'invalid-important',
                "'!' is not followed by a valid 'important' marker"))
    while stack:
        token = stack.pop()
        if token.type == 'error':
            kind = _ERROR_KINDS.get(token.kind)
            if kind is None:
                kind = (
                    'unmatched-bracket' if token.kind in ')]}'
                    else 'invalid')
            issues.append(DeclarationIssue(
                token.source_line, token.source_column, kind, token.message))
        else:
            # Simple blocks keep their tokens in "content",
            # function blocks in "arguments".
            content = (
                getattr(token, 'content', None)
                or getattr(token, 'arguments', None))
            if content:
                stack.extend(content)


class CanonicalDeclaration:
    """Canonical view of a single :class:`~tinycss2.ast.Declaration`.

    .. attribute:: name

        The property name, as in the source.

    .. attribute:: canonical_name

        The normalized property name: ASCII lower case, except custom
        properties which keep their case.  This is the identity to use
        when comparing declarations.

    .. attribute:: value

        The declaration value, serialized from its tokens and stripped of
        leading and trailing whitespace.

    .. attribute:: important

        Whether the declaration had an ``!important`` marker, however it
        was spelled (``!important``, ``! important``, ``!IMPORTANT``...).

    .. attribute:: declaration

        The original :class:`~tinycss2.ast.Declaration` object.

    .. attribute:: issues

        Tuple of :class:`DeclarationIssue` attached to this declaration.

    .. attribute:: valid

        Whether the declaration is free of classified issues.  Invalid
        declarations are kept for auditing but ignored by the cascade in
        :meth:`CanonicalDeclarationList.final`.

    .. attribute:: source_line
    .. attribute:: source_column
    .. attribute:: end_line
    .. attribute:: end_column

        The source range of the declaration.  ``end_line`` and
        ``end_column`` point just after the last character of the value
        (before a possible ``!important`` marker).

    """
    __slots__ = [
        'canonical_name', 'declaration', 'end_column', 'end_line',
        'important', 'issues', 'name', 'source_column', 'source_line',
        'value',
    ]

    def __init__(self, declaration, issues):
        self.declaration = declaration
        self.name = declaration.name
        self.canonical_name = canonical_name(declaration.name)
        self.value = serialize(declaration.value).strip()
        self.important = declaration.important
        self.issues = tuple(issues)
        self.source_line = declaration.source_line
        self.source_column = declaration.source_column
        if declaration.value:
            self.end_line, self.end_column = _token_end_position(
                declaration.value[-1])
        else:
            self.end_line = declaration.source_line
            self.end_column = declaration.source_column + len(declaration.name)

    def __repr__(self):
        return f'<CanonicalDeclaration {self.canonical}>'

    @property
    def valid(self):
        return not self.issues

    @property
    def canonical(self):
        """Canonical serialization: ``name:value`` plus ``!important``."""
        important = '!important' if self.important else ''
        return f'{self.canonical_name}:{self.value}{important}'

    @property
    def identity(self):
        """Hashable identity of the declaration: (name, value, important)."""
        return self.canonical_name, self.value, self.important


class CanonicalDeclarationList:
    """Canonical view of a parsed declaration list.

    .. attribute:: declarations

        Tuple of :class:`CanonicalDeclaration`, in source order, including
        duplicates and invalid declarations.

    .. attribute:: issues

        Tuple of :class:`DeclarationIssue` that are not attached to a
        declaration (e.g. an empty property name or an at-rule).

    """
    __slots__ = ['declarations', 'issues']

    def __init__(self, declarations, issues):
        self.declarations = tuple(declarations)
        self.issues = tuple(issues)

    def __repr__(self):
        total = len(self.declarations)
        return f'<CanonicalDeclarationList {total} declarations>'

    @property
    def valid_declarations(self):
        """Tuple of declarations without classified issues, in source order."""
        return tuple(d for d in self.declarations if d.valid)

    def final(self):
        """Return the final cascaded declaration of each property.

        :returns: A dict mapping canonical property names to the winning
            :class:`CanonicalDeclaration`.  ``!important`` declarations win
            over normal ones; among declarations of the same importance,
            the last one in source order wins.  Invalid declarations do
            not participate in the cascade.

        """
        result = {}
        for declaration in self.declarations:
            if not declaration.valid:
                continue
            current = result.get(declaration.canonical_name)
            if current is None or not (
                    current.important and not declaration.important):
                result[declaration.canonical_name] = declaration
        return result

    def serialize(self):
        """Serialize the final cascaded declarations, separated by ``;``."""
        return ';'.join(d.canonical for d in self.final().values())


def canonicalize_declarations(input, skip_comments=False):
    """Parse a declaration list and return its canonical view.

    :type input: :obj:`str` or :term:`iterable`
    :param input: A string or an iterable of :term:`component values`.
    :type skip_comments: :obj:`bool`
    :param skip_comments: If the input is a string, ignore all CSS comments.
    :returns: A :class:`CanonicalDeclarationList`.

    """
    declarations = []
    issues = []
    parsed = parse_declaration_list(
        input, skip_comments=skip_comments, skip_whitespace=True)
    for node in parsed:
        if node.type == 'declaration':
            declaration_issues = []
            _scan_value_tokens(node.value, declaration_issues)
            declarations.append(CanonicalDeclaration(node, declaration_issues))
        elif node.type == 'error':
            if node.message.startswith('Expected <ident>'):
                kind, message = 'empty-name', 'Declaration has no property name'
            else:
                kind, message = node.kind, node.message
            issues.append(DeclarationIssue(
                node.source_line, node.source_column, kind, message))
        elif node.type == 'at-rule':
            issues.append(DeclarationIssue(
                node.source_line, node.source_column, 'unsupported',
                f'At-rule @{node.name} is not a declaration'))
    return CanonicalDeclarationList(declarations, issues)


class DeclarationPolicy:
    """Rules to flag unwanted declarations, without rewriting them.

    A policy only reports :class:`DeclarationIssue` objects; it never
    modifies declarations, so the semantics of valid CSS are preserved.

    :type allowed_properties: :term:`iterable` or :obj:`None`
    :param allowed_properties:
        If not :obj:`None`, only these property names are allowed
        (normalized with :func:`canonical_name`).
    :type allow_important: :obj:`bool`
    :param allow_important:
        Whether the ``!important`` flag is allowed.
    :type locked_variable_prefixes: :term:`iterable`
    :param locked_variable_prefixes:
        Prefixes of custom properties (e.g. ``--admin-``) that declarations
        are not allowed to set.

    """
    __slots__ = [
        'allow_important', 'allowed_properties', 'locked_variable_prefixes']

    def __init__(self, allowed_properties=None, allow_important=True,
                 locked_variable_prefixes=()):
        self.allowed_properties = (
            None if allowed_properties is None
            else frozenset(
                canonical_name(name) for name in allowed_properties))
        self.allow_important = allow_important
        self.locked_variable_prefixes = tuple(locked_variable_prefixes)

    def check(self, declarations):
        """Check declarations against the policy.

        :param declarations: A :class:`CanonicalDeclarationList` or an
            iterable of :class:`CanonicalDeclaration`.
        :returns: A list of :class:`DeclarationIssue`, one per violation.

        """
        if isinstance(declarations, CanonicalDeclarationList):
            declarations = declarations.declarations
        issues = []
        for declaration in declarations:
            if (self.allowed_properties is not None
                    and declaration.canonical_name
                    not in self.allowed_properties):
                issues.append(DeclarationIssue(
                    declaration.source_line, declaration.source_column,
                    'forbidden-property',
                    f'Property {declaration.name} is not allowed'))
            if declaration.important and not self.allow_important:
                issues.append(DeclarationIssue(
                    declaration.source_line, declaration.source_column,
                    'forbidden-important',
                    f'!important is not allowed on {declaration.name}'))
            if declaration.canonical_name.startswith('--') and any(
                    declaration.canonical_name.startswith(prefix)
                    for prefix in self.locked_variable_prefixes):
                issues.append(DeclarationIssue(
                    declaration.source_line, declaration.source_column,
                    'locked-variable',
                    f'Custom property {declaration.name} is locked'))
        return issues
