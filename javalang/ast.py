import pickle

import six


class MetaNode(type):
    def __new__(mcs, name, bases, dict):
        attrs = list(dict['attrs'])
        dict['attrs'] = list()

        for base in bases:
            if hasattr(base, 'attrs'):
                dict['attrs'].extend(base.attrs)

        dict['attrs'].extend(attrs)

        return type.__new__(mcs, name, bases, dict)


@six.add_metaclass(MetaNode)
class Node(object):
    attrs = ()

    def __init__(self, **kwargs):
        values = kwargs.copy()

        for attr_name in self.attrs:
            value = values.pop(attr_name, None)
            setattr(self, attr_name, value)

        if values:
            raise ValueError('Extraneous arguments')

    def __equals__(self, other):
        if type(other) is not type(self):
            return False

        for attr in self.attrs:
            if getattr(other, attr) != getattr(self, attr):
                return False

        return True

    def __repr__(self):
        attr_values = []
        for attr in sorted(self.attrs):
            attr_values.append('%s=%s' % (attr, getattr(self, attr)))
        return '%s(%s)' % (type(self).__name__, ', '.join(attr_values))

    def __iter__(self):
        return walk_tree(self)

    def filter(self, pattern):
        for path, node in self:
            if ((isinstance(pattern, type) and isinstance(node, pattern)) or
                (node == pattern)):
                yield path, node

    @property
    def children(self):
        return [getattr(self, attr_name) for attr_name in self.attrs]
    
    @property
    def position(self):
        if hasattr(self, "_position"):
            return self._position

def walk_tree(root):
    children = None

    if isinstance(root, Node):
        yield (), root
        children = root.children
    else:
        children = root

    for child in children:
        if isinstance(child, (Node, list, tuple)):
            for path, node in walk_tree(child):
                yield (root,) + path, node

def dump(ast, file):
    pickle.dump(ast, file)

def load(file):
    return pickle.load(file)


def is_annotation_declaration(node):
    """Return True when *node* models an ``@interface`` declaration.

    Annotation declarations (``tree.AnnotationDeclaration``) are distinct from
    annotation applications (``tree.Annotation`` and its subclasses).
    """
    from . import tree
    return isinstance(node, tree.AnnotationDeclaration)


def is_annotation_usage(node):
    """Return True when *node* is an annotation application (``@Name``)."""
    from . import tree
    return isinstance(node, tree.Annotation)


def element_value(node):
    """Return the element value carried by a node.

    Works for annotation usages (Annotation.element) and for annotation
    declaration members with a default value (AnnotationMethod.default).
    """
    from . import tree
    if isinstance(node, tree.Annotation):
        return node.element
    return getattr(node, 'default', None)


def annotation_name(annotation):
    """Return the fully qualified name of an annotation application."""
    return annotation.name


def annotation_element(annotation):
    """Return the raw element of an annotation application.

    The value is one of ``None`` (marker annotation), a single expression /
    nested annotation (single-element form), an ``ElementArrayValue`` (array
    form) or a list of ``ElementValuePair`` (named-argument form).
    """
    return annotation.element


def is_marker_annotation(annotation):
    """Return True for marker annotations such as ``@Deprecated``."""
    from . import tree
    return (isinstance(annotation, tree.MarkerAnnotation)
            or annotation.element is None)


def is_single_element_annotation(annotation):
    """Return True for single-element annotations such as ``@Named("v")``."""
    from . import tree
    return isinstance(annotation, tree.SingleElementAnnotation)


def is_normal_annotation(annotation):
    """Return True for annotations using explicit ``name = value`` pairs."""
    from . import tree
    return isinstance(annotation, tree.NormalAnnotation)


def annotation_value(annotation, name=None, default=None):
    """Stable accessor for the value carried by an annotation application.

    * When *name* is omitted the value of the single-element (or array) form
      is returned, or ``default`` for a marker annotation.
    * When *name* is provided the matching ``ElementValuePair`` value is
      returned, or *default* when the pair is absent.
    """
    from . import tree

    element = annotation.element

    if name is None:
        if isinstance(element, tree.ElementArrayValue):
            return list(element.values)
        if element is None:
            return default
        if isinstance(element, list):
            pairs = dict((pair.name, pair.value) for pair in element)
            if 'value' in pairs:
                return pairs['value']
            return default
        return element

    if isinstance(element, list):
        for pair in element:
            if pair.name == name:
                return pair.value
    return default


def annotation_pairs(annotation):
    """Return the ``name -> value`` mapping of a normal annotation."""
    element = annotation.element
    if isinstance(element, list):
        return dict((pair.name, pair.value) for pair in element)
    return dict()


def annotation_array_values(annotation, name=None):
    """Return the array values of an annotation element as a list.

    Returns an empty list when the element is missing or is not an array.
    A non-array single value is wrapped so callers always receive a list.
    """
    from . import tree

    value = annotation_value(annotation, name=name, default=None)
    if isinstance(value, tree.ElementArrayValue):
        return list(value.values)
    if value is None:
        return []
    return [value]


def annotation_token_range(annotation):
    """Return the ``(start, end)`` token positions of an annotation.

    Each endpoint is a tokenizer ``Position`` (or ``None`` when unavailable).
    """
    return (getattr(annotation, '_position', None),
            getattr(annotation, '_end_position', None))


def is_array_value(value):
    """Return True when *value* is an annotation array value node."""
    from . import tree
    return isinstance(value, tree.ElementArrayValue)


def annotation_default(method):
    """Return the default value of an ``AnnotationMethod`` element."""
    return getattr(method, 'default', None)
