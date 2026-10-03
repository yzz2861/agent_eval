"""Versioned, registry-based serialization for Peewee SELECT queries."""

import base64
import datetime
import decimal
import json
import re
import uuid

from peewee import Alias
from peewee import BitwiseNegated
from peewee import Cast
from peewee import Column
from peewee import Case
from peewee import CTE
from peewee import CompoundSelectQuery
from peewee import Entity
from peewee import Expression
from peewee import Field
from peewee import FieldAlias
from peewee import Function
from peewee import JOIN
from peewee import Join
from peewee import Model
from peewee import ModelAlias
from peewee import ModelCompoundSelectQuery
from peewee import ModelSelect
from peewee import Negated
from peewee import NodeList
from peewee import OP
from peewee import Ordering
from peewee import ROW
from peewee import Select
from peewee import SelectBase
from peewee import SelectQuery
from peewee import SQL
from peewee import Star
from peewee import StringExpression
from peewee import Table
from peewee import Value
from peewee import is_model


FORMAT = 'peewee-query'
VERSION = 1
PYTHON_IDENTIFIER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


class QueryDescriptionError(ValueError):
    """Base class for invalid query descriptions."""


class UnsupportedNodeError(QueryDescriptionError):
    def __init__(self, node, path):
        self.node = node
        self.path = path
        super().__init__('%s: unsupported node %r' % (path, node))


class InvalidQueryDescriptionError(QueryDescriptionError):
    def __init__(self, message, path='$', value=None):
        self.path = path
        self.value = value
        if value is not None:
            message = '%s: %s: %r' % (path, message, value)
        else:
            message = '%s: %s' % (path, message)
        super().__init__(message)


def _join_path(path, key):
    if isinstance(key, int):
        return '%s[%d]' % (path, key)
    return '%s.%s' % (path, key)


def _node_ref(node_id):
    return {'$ref': 'nodes', 'id': node_id}


def _value_ref(value_id):
    return {'$ref': 'values', 'id': value_id}


def _is_ref(value):
    return isinstance(value, dict) and '$ref' in value


class QueryRegistry(object):
    """Application-owned mapping from stable identifiers to Peewee objects."""

    default_functions = (
        'ABS', 'AVG', 'COALESCE', 'COUNT', 'DATE', 'EXISTS', 'GROUP_CONCAT',
        'IFNULL', 'LENGTH', 'LOWER', 'LTRIM', 'MAX', 'MIN', 'NULLIF',
        'REPLACE', 'ROUND', 'RTRIM', 'STRFTIME', 'SUBSTR', 'SUM', 'TRIM',
        'UPPER')

    def __init__(self):
        self.models = {}
        self._models_by_object = {}
        self.tables = {}
        self._tables_by_object = {}
        self.functions = {}
        self._functions_by_name = {}
        self.collations = {'BINARY', 'NOCASE', 'RTRIM'}
        self.casts = {
            'BLOB', 'CHAR', 'DATE', 'DATETIME', 'INTEGER', 'REAL', 'TEXT',
            'TIME', 'VARCHAR'}
        for name in self.default_functions:
            self.register_function(name, name)

    def register_model(self, model, identifier=None):
        if not is_model(model):
            raise TypeError('Expected a Peewee model class.')
        identifier = identifier or model.__name__
        existing_id = self._models_by_object.get(model)
        if existing_id is not None:
            if existing_id != identifier:
                raise ValueError('Model is already registered as %r.' %
                                 existing_id)
            return identifier
        if identifier in self.models and self.models[identifier] is not model:
            raise ValueError('Model identifier %r is already in use.' %
                             identifier)
        self.models[identifier] = model
        self._models_by_object[model] = identifier
        return identifier

    def register_table(self, table, identifier=None):
        if not isinstance(table, Table):
            raise TypeError('Expected a Table instance.')
        identifier = identifier or table.__name__
        existing = self._tables_by_object.get(id(table))
        if existing is not None:
            if existing != identifier:
                raise ValueError('Table is already registered as %r.' %
                                 existing)
            return identifier
        if identifier in self.tables:
            existing_table = self.tables[identifier]
            if (existing_table.__name__, existing_table._columns,
                    existing_table._schema, existing_table._primary_key) != (
                    table.__name__, table._columns, table._schema,
                    table._primary_key):
                raise ValueError('Table identifier %r is already in use.' %
                                 identifier)
        self.tables[identifier] = table
        self._tables_by_object[id(table)] = identifier
        return identifier

    def register_function(self, identifier, sql_name):
        identifier = identifier.upper()
        if (identifier in self.functions and
                self.functions[identifier] != sql_name):
            raise ValueError('Function identifier %r is already in use.' %
                             identifier)
        self.functions[identifier] = sql_name
        self._functions_by_name[sql_name.upper()] = identifier
        return identifier

    def register_collation(self, name):
        self.collations.add(name.upper())

    def register_cast(self, name):
        self.casts.add(name.upper())

    def model_id(self, model):
        try:
            return self._models_by_object[model]
        except KeyError:
            raise QueryDescriptionError(
                'Model %s is not registered.' % model.__name__)

    def get_model(self, identifier, path):
        model = self.models.get(identifier)
        if model is None:
            raise InvalidQueryDescriptionError(
                'unknown model identifier', path, identifier)
        return model

    def table_id(self, table):
        try:
            return self._tables_by_object[id(table)]
        except KeyError:
            raise QueryDescriptionError('Table %s is not registered.' %
                                         table.__name__)

    def get_table(self, identifier, path):
        table = self.tables.get(identifier)
        if table is None:
            raise InvalidQueryDescriptionError(
                'unknown table identifier', path, identifier)
        return table

    def function_id(self, name):
        try:
            return self._functions_by_name[name.upper()]
        except KeyError:
            raise QueryDescriptionError('Function %s is not whitelisted.' %
                                         name)

    def get_function_name(self, identifier, path):
        name = self.functions.get(identifier)
        if name is None:
            raise InvalidQueryDescriptionError(
                'unknown function identifier', path, identifier)
        return name


def encode_scalar(value):
    if value is None:
        return {'type': 'null'}
    if isinstance(value, bool):
        return {'type': 'bool', 'value': value}
    if isinstance(value, int):
        return {'type': 'integer', 'value': value}
    if isinstance(value, float):
        if value != value or value in (float('inf'), float('-inf')):
            raise QueryDescriptionError('Non-finite floats cannot be saved.')
        return {'type': 'float', 'value': value}
    if isinstance(value, str):
        return {'type': 'string', 'value': value}
    if isinstance(value, bytes):
        return {'type': 'bytes',
                'value': base64.b64encode(value).decode('ascii')}
    if isinstance(value, bytearray):
        return {'type': 'bytes',
                'value': base64.b64encode(bytes(value)).decode('ascii')}
    if isinstance(value, decimal.Decimal):
        return {'type': 'decimal', 'value': str(value)}
    if isinstance(value, datetime.datetime):
        return {'type': 'datetime', 'value': value.isoformat()}
    if isinstance(value, datetime.date):
        return {'type': 'date', 'value': value.isoformat()}
    if isinstance(value, datetime.time):
        return {'type': 'time', 'value': value.isoformat()}
    if isinstance(value, uuid.UUID):
        return {'type': 'uuid', 'value': str(value)}
    if isinstance(value, (list, tuple)):
        return {'type': 'array',
                'value': [encode_scalar(item) for item in value]}
    if isinstance(value, dict):
        return {'type': 'object',
                'value': {str(key): encode_scalar(item)
                          for key, item in value.items()}}
    raise QueryDescriptionError('Value of type %s cannot be saved.' %
                                type(value).__name__)


def decode_scalar(descriptor, path):
    if not isinstance(descriptor, dict):
        raise InvalidQueryDescriptionError('value must be an object', path)
    kind = descriptor.get('type')
    raw = descriptor.get('value')
    try:
        if kind == 'null':
            if raw is not None:
                raise ValueError('expected null')
            return None
        if kind == 'bool':
            if not isinstance(raw, bool):
                raise ValueError('expected boolean')
            return raw
        if kind == 'integer':
            if not isinstance(raw, int) or isinstance(raw, bool):
                raise ValueError('expected integer')
            return raw
        if kind == 'float':
            if not isinstance(raw, (int, float)) or isinstance(raw, bool):
                raise ValueError('expected number')
            return float(raw)
        if kind == 'string':
            if not isinstance(raw, str):
                raise ValueError('expected string')
            return raw
        if kind == 'bytes':
            if not isinstance(raw, str):
                raise ValueError('expected string')
            return base64.b64decode(raw.encode('ascii'), validate=True)
        if kind == 'decimal':
            if not isinstance(raw, str):
                raise ValueError('expected string')
            return decimal.Decimal(raw)
        if kind == 'datetime':
            if not isinstance(raw, str):
                raise ValueError('expected string')
            return datetime.datetime.fromisoformat(raw)
        if kind == 'date':
            if not isinstance(raw, str):
                raise ValueError('expected string')
            return datetime.date.fromisoformat(raw)
        if kind == 'time':
            if not isinstance(raw, str):
                raise ValueError('expected string')
            return datetime.time.fromisoformat(raw)
        if kind == 'uuid':
            if not isinstance(raw, str):
                raise ValueError('expected string')
            return uuid.UUID(raw)
        if kind == 'array':
            if not isinstance(raw, list):
                raise ValueError('expected array')
            return [decode_scalar(item, _join_path(path, index))
                    for index, item in enumerate(raw)]
        if kind == 'object':
            if not isinstance(raw, dict):
                raise ValueError('expected object')
            result = {}
            for key, item in raw.items():
                if not isinstance(key, str):
                    raise ValueError('expected string key')
                result[key] = decode_scalar(
                    item, _join_path(path, key))
            return result
    except (TypeError, ValueError) as exc:
        raise InvalidQueryDescriptionError(str(exc), path)
    raise InvalidQueryDescriptionError('unknown value type', path, kind)


GRAPH_NODE_TYPES = {
    'alias', 'cte', 'join', 'model_alias', 'select', 'table',
    'model_select', 'model_compound', 'compound'}

OPERATORS = set(OP.values())
JOIN_TYPES = set(JOIN.values())
NODE_TYPES = frozenset((
    'alias', 'between', 'bitwise_negated', 'case', 'cast', 'column',
    'compound', 'cte', 'expression', 'field', 'field_alias', 'function',
    'join', 'model', 'model_alias', 'model_compound', 'model_select',
    'negated', 'node_list', 'ordering', 'select', 'star',
    'string_between', 'string_expression', 'table', 'value'))
COMMON_QUERY_KEYS = frozenset(
    ('type', 'id', 'cte', 'where', 'order_by', 'limit', 'offset'))
SELECT_KEYS = COMMON_QUERY_KEYS | frozenset((
    'from', 'columns', 'group_by', 'having', 'distinct', 'distinct_on',
    'lateral', 'alias'))
MODEL_SELECT_KEYS = SELECT_KEYS | frozenset((
    'model', 'default', 'join_context', 'joins', 'row_type', 'constructor'))
COMPOUND_KEYS = COMMON_QUERY_KEYS | frozenset(('lhs', 'rhs', 'op', 'alias'))
MODEL_COMPOUND_KEYS = COMPOUND_KEYS | frozenset(
    ('model', 'row_type', 'constructor'))
ALLOWED_NODE_KEYS = {
    'alias': frozenset(('type', 'id', 'node', 'alias')),
    'between': frozenset(('type', 'lhs', 'low', 'high', 'flat')),
    'bitwise_negated': frozenset(('type', 'node')),
    'case': frozenset(('type', 'predicate', 'branches', 'default')),
    'cast': frozenset(('type', 'node', 'cast')),
    'column': frozenset(('type', 'source', 'name')),
    'compound': COMPOUND_KEYS,
    'cte': frozenset(('type', 'id', 'name', 'query', 'recursive', 'columns',
                      'materialized')),
    'expression': frozenset(('type', 'lhs', 'op', 'rhs', 'flat')),
    'field': frozenset(('type', 'model', 'name')),
    'field_alias': frozenset(('type', 'source', 'name', 'column')),
    'function': frozenset(('type', 'name', 'arguments', 'filter',
                           'order_by', 'coerce')),
    'join': frozenset(('type', 'id', 'lhs', 'rhs', 'join_type', 'on',
                       'alias')),
    'model': frozenset(('type', 'id')),
    'model_alias': frozenset(('type', 'id', 'model', 'alias')),
    'model_compound': MODEL_COMPOUND_KEYS,
    'model_select': MODEL_SELECT_KEYS,
    'negated': frozenset(('type', 'node')),
    'node_list': frozenset(('type', 'parts', 'glue', 'parens')),
    'ordering': frozenset(('type', 'node', 'direction', 'collation',
                           'nulls')),
    'select': SELECT_KEYS,
    'star': frozenset(('type', 'source')),
    'string_between': frozenset(('type', 'lhs', 'low', 'high', 'flat')),
    'string_expression': frozenset(('type', 'lhs', 'op', 'rhs', 'flat')),
    'table': frozenset(('type', 'id', 'model', 'table', 'alias')),
    'value': frozenset(('type', 'multi', 'items', 'value', 'converter'))}


def check_keys(descriptor, kind, path):
    allowed = ALLOWED_NODE_KEYS[kind]
    unexpected = set(descriptor) - allowed
    if unexpected:
        raise InvalidQueryDescriptionError(
            'unexpected key', _join_path(path, sorted(unexpected)[0]))


class QueryEncoder(object):
    def __init__(self, registry):
        self.registry = registry
        self.nodes = {}
        self.values = []
        self._node_ids = {}
        self._visiting = set()
        self._next_id = 1

    def encode(self, query):
        if not isinstance(query, SelectQuery):
            raise QueryDescriptionError('Only SELECT queries can be saved.')
        root_id = self.node(query, '$')
        return {
            'format': FORMAT,
            'version': VERSION,
            'root': root_id,
            'nodes': self.nodes,
            'values': self.values,
        }

    def _id_for(self, obj):
        key = id(obj)
        node_id = self._node_ids.get(key)
        if node_id is None:
            node_id = 'n%d' % self._next_id
            self._next_id += 1
            self._node_ids[key] = node_id
        return node_id

    def child(self, obj, path, required=True):
        if obj is None:
            if required:
                raise InvalidQueryDescriptionError('required node', path)
            return None
        return self.node(obj, path)

    def children(self, values, path):
        if values is None:
            return None
        return [self.node(value, _join_path(path, index))
                for index, value in enumerate(values)]

    def node(self, obj, path):
        if obj is None:
            raise InvalidQueryDescriptionError('required node', path)
        is_graph = isinstance(obj, (SelectBase, Join, CTE, Table, ModelAlias,
                                    Alias))
        if not is_graph:
            return self._encode_node(obj, path, None)
        cached = self._node_ids.get(id(obj))
        if cached is not None:
            return _node_ref(cached)
        node_id = self._id_for(obj)
        if node_id in self._visiting:
            return _node_ref(node_id)
        if is_graph:
            self._visiting.add(node_id)
        try:
            descriptor = self._encode_node(obj, path, node_id)
        finally:
            if is_graph:
                self._visiting.discard(node_id)
        self.nodes[node_id] = descriptor
        return _node_ref(node_id)

    def value(self, value, path, in_multi=False):
        if isinstance(value, (list, tuple)) and not in_multi:
            return {'multi': [self.value(item, _join_path(path, index), True)
                             for index, item in enumerate(value)]}
        if isinstance(value, range) and not in_multi:
            return {'multi': [self.value(item, _join_path(path, index), True)
                             for index, item in enumerate(value)]}
        if isinstance(value, (set, frozenset)) and not in_multi:
            raise UnsupportedNodeError(value, path)
        descriptor = encode_scalar(value)
        value_id = 'v%d' % len(self.values)
        self.values.append(descriptor)
        return _value_ref(value_id)

    def _encode_node(self, obj, path, node_id):
        if is_model(obj):
            return {'type': 'model', 'id': self.registry.model_id(obj)}
        if isinstance(obj, FieldAlias):
            source_id = self.node(obj.source,
                                 _join_path(path, 'source'))
            return {'type': 'field_alias', 'source': source_id,
                    'name': obj.field.name, 'column': obj.field.column_name}
        if isinstance(obj, Field):
            model_id = self.registry.model_id(obj.model)
            return {'type': 'field', 'model': model_id, 'name': obj.name}
        if isinstance(obj, Column):
            return {'type': 'column',
                    'source': self.node(obj.source,
                                       _join_path(path, 'source')),
                    'name': obj.name}
        if isinstance(obj, ModelAlias):
            source = self.node(obj.model, _join_path(path, 'model'))
            return {'type': 'model_alias', 'id': node_id, 'model': source,
                    'alias': obj.alias}
        if isinstance(obj, Star):
            return {'type': 'star',
                    'source': self.node(obj.source,
                                       _join_path(path, 'source'))}
        if isinstance(obj, Ordering):
            if obj.direction not in ('ASC', 'DESC'):
                raise InvalidQueryDescriptionError(
                    'invalid ordering direction', path, obj.direction)
            collation = None
            if obj.collation:
                collation = obj.collation.upper()
                if collation not in self.registry.collations:
                    raise QueryDescriptionError(
                        'Collation %s is not whitelisted.' % obj.collation)
            if obj.nulls not in (None, 'first', 'last'):
                raise InvalidQueryDescriptionError(
                    'invalid null ordering', path, obj.nulls)
            return {'type': 'ordering',
                    'node': self.node(obj.node,
                                     _join_path(path, 'node')),
                    'direction': obj.direction, 'collation': collation,
                    'nulls': obj.nulls}
        if isinstance(obj, Alias):
            return {'type': 'alias', 'id': node_id,
                    'node': self.node(obj.node, _join_path(path, 'node')),
                    'alias': obj._alias}
        if isinstance(obj, Value):
            return self._value(obj, path)
        if isinstance(obj, Expression):
            return self._expression(obj, path)
        if isinstance(obj, Function):
            return self._function(obj, path)
        if isinstance(obj, Case):
            return self._case(obj, path)
        if isinstance(obj, NodeList):
            return self._node_list(obj, path)
        if isinstance(obj, Negated):
            return {'type': 'negated',
                    'node': self.node(obj.node,
                                     _join_path(path, 'node'))}
        if isinstance(obj, BitwiseNegated):
            return {'type': 'bitwise_negated',
                    'node': self.node(obj.node,
                                     _join_path(path, 'node'))}
        if isinstance(obj, Cast):
            cast = obj._cast.upper()
            if cast not in self.registry.casts:
                raise QueryDescriptionError('Cast %s is not whitelisted.' %
                                             obj._cast)
            return {'type': 'cast', 'cast': cast,
                    'node': self.node(obj.node,
                                     _join_path(path, 'node'))}
        if isinstance(obj, Join):
            return self._join(obj, path, node_id)
        if isinstance(obj, CTE):
            return self._cte(obj, path, node_id)
        if isinstance(obj, Table):
            return self._table(obj, path, node_id)
        if isinstance(obj, CompoundSelectQuery):
            return self._compound(obj, path, node_id)
        if isinstance(obj, Select):
            return self._select(obj, path, node_id)
        if isinstance(obj, Entity):
            raise UnsupportedNodeError(obj, path)
        if isinstance(obj, SQL):
            raise UnsupportedNodeError(obj, path)
        raise UnsupportedNodeError(obj, path)

    def scalar_or_node(self, obj, path):
        if obj is None:
            return None
        if isinstance(obj, (Select, CTE, Table, Join, Field, Function, Case,
                            Expression, NodeList, Alias, Ordering, Cast,
                            Negated, BitwiseNegated, Value, Column, Star)):
            return self.node(obj, path)
        return self.value(obj, path)

    def _converter(self, value, path):
        converter = value.converter
        if converter is None:
            return None
        if converter is False:
            return False
        owner = getattr(converter, '__self__', None)
        if (isinstance(owner, Field) and
                getattr(converter, '__func__', None) == Field.db_value):
            return self.node(owner, _join_path(path, 'converter'))
        raise UnsupportedNodeError(value, path)

    def _value(self, value, path):
        converter = self._converter(value, path)
        if value.multi:
            items = []
            for index, item in enumerate(value.values):
                item_path = _join_path(path, index)
                if hasattr(item, '__sql__'):
                    items.append(self.node(item, item_path))
                else:
                    items.append(self.value(item, item_path, True))
            return {'type': 'value', 'multi': True, 'items': items,
                    'converter': converter}
        return {'type': 'value', 'multi': False,
                'value': self.value(value.value,
                                   _join_path(path, 'value'), True),
                'converter': converter}

    def _expression(self, expr, path):
        if expr.op not in OPERATORS:
            raise InvalidQueryDescriptionError(
                'unknown operator', _join_path(path, 'op'), expr.op)
        if expr.op == OP.BETWEEN and isinstance(expr.rhs, NodeList):
            nodes = expr.rhs.nodes
            if (len(nodes) == 3 and isinstance(nodes[1], SQL) and
                    nodes[1].sql == 'AND'):
                return {
                    'type': ('between' if type(expr) is Expression
                             else 'string_between'),
                    'lhs': self.node(expr.lhs,
                                    _join_path(path, 'lhs')),
                    'low': self.scalar_or_node(
                        nodes[0], _join_path(path, 'low')),
                    'high': self.scalar_or_node(
                        nodes[2], _join_path(path, 'high')),
                    'flat': bool(expr.flat)}
        kind = ('string_expression' if isinstance(expr, StringExpression)
                else 'expression')
        return {
            'type': kind,
            'lhs': self.node(expr.lhs, _join_path(path, 'lhs')),
            'op': expr.op,
            'rhs': (self.scalar_or_node(expr.rhs,
                                        _join_path(path, 'rhs'))
                    if expr.rhs is not None else None),
            'flat': bool(expr.flat)}

    def _function(self, function, path):
        if function.name is None or function._python_value is not None:
            raise UnsupportedNodeError(function, path)
        return {
            'type': 'function',
            'name': self.registry.function_id(function.name),
            'arguments': [
                self.scalar_or_node(arg,
                                    _join_path(_join_path(path, 'args'),
                                               index))
                for index, arg in enumerate(function.arguments or ())],
            'filter': self.child(function._filter,
                                 _join_path(path, 'filter'), False),
            'order_by': self.children(
                function._order_by,
                _join_path(path, 'order_by')),
            'coerce': bool(function._coerce)}

    def _case(self, case, path):
        branches = []
        for index, (predicate, result) in enumerate(case.expression_tuples):
            branch_path = _join_path(_join_path(path, 'branches'), index)
            branches.append({
                'when': self.scalar_or_node(
                    predicate, _join_path(branch_path, 'when')),
                'then': self.scalar_or_node(
                    result, _join_path(branch_path, 'then'))})
        return {
            'type': 'case',
            'predicate': self.child(
                case.predicate, _join_path(path, 'predicate'), False),
            'branches': branches,
            'default': (self.scalar_or_node(
                case.default, _join_path(path, 'default'))
                if case.default is not None else None)}

    def _node_list(self, node_list, path):
        if node_list.glue not in (' ', ', '):
            raise UnsupportedNodeError(node_list, path)
        parts = []
        for index, item in enumerate(node_list.nodes):
            item_path = _join_path(path, index)
            if isinstance(item, SQL):
                if item.sql not in ('AND', 'DISTINCT', 'ORDER BY') or item.params:
                    raise UnsupportedNodeError(item, item_path)
                parts.append({'keyword': item.sql})
            else:
                parts.append(self.scalar_or_node(item, item_path))
        return {'type': 'node_list', 'parts': parts,
                'glue': 'space' if node_list.glue == ' ' else 'comma',
                'parens': bool(node_list.parens)}

    def _table(self, table, path, node_id):
        if table._model is not None:
            source = self.node(table._model, _join_path(path, 'model'))
            return {'type': 'table', 'id': node_id, 'model': source,
                    'alias': table._alias}
        return {'type': 'table', 'id': node_id,
                'table': self.registry.table_id(table),
                'alias': table._alias}

    def _join(self, join, path, node_id):
        return {
            'type': 'join', 'id': node_id,
            'lhs': self.node(join.lhs, _join_path(path, 'lhs')),
            'rhs': self.node(join.rhs, _join_path(path, 'rhs')),
            'join_type': join.join_type,
            'on': (self.scalar_or_node(join._on,
                                      _join_path(path, 'on'))
                   if join._on is not None else None),
            'alias': join._alias}

    def _cte(self, cte, path, node_id):
        columns = None
        if cte._columns is not None:
            columns = []
            for index, column in enumerate(cte._columns):
                if not isinstance(column, Entity):
                    raise UnsupportedNodeError(column,
                                               _join_path(path, index))
                columns.append(list(column._path))
        return {
            'type': 'cte', 'id': node_id, 'name': cte._alias,
            'query': self.node(cte._query, _join_path(path, 'query')),
            'recursive': bool(cte._recursive),
            'columns': columns, 'materialized': cte._materialized}

    def _query_common(self, query, path):
        if getattr(query, '_windows', None) is not None or \
                getattr(query, '_for_update', None) is not None:
            raise UnsupportedNodeError(query, path)
        if getattr(query, '_load_tree', None):
            raise UnsupportedNodeError(query, path)
        return {
            'cte': self.children(query._cte_list,
                                 _join_path(path, 'cte')),
            'where': self.child(query._where,
                                _join_path(path, 'where'), False),
            'order_by': self.children(query._order_by,
                                      _join_path(path, 'order_by')),
            'limit': (self.scalar_or_node(query._limit,
                                         _join_path(path, 'limit'))
                      if query._limit is not None else None),
            'offset': (self.scalar_or_node(query._offset,
                                          _join_path(path, 'offset'))
                       if query._offset is not None else None)}

    def _row_shape(self, query, path):
        constructor = getattr(query, '_constructor', None)
        if constructor is not None and not is_model(constructor):
            raise UnsupportedNodeError(query, path)
        return {
            'row_type': getattr(query, '_row_type', None),
            'constructor': (self.node(
                constructor, _join_path(path, 'constructor'))
                if is_model(constructor) else None)}

    def _select(self, query, path, node_id):
        descriptor = {
            'type': ('model_select' if isinstance(query, ModelSelect)
                     else 'select'),
            'id': node_id,
            'from': self.children(query._from_list,
                                  _join_path(path, 'from')),
            'columns': self.children(query._returning,
                                     _join_path(path, 'columns')),
            'group_by': self.children(query._group_by,
                                      _join_path(path, 'group_by')),
            'having': self.child(query._having,
                                 _join_path(path, 'having'), False),
            'distinct': query._simple_distinct,
            'distinct_on': self.children(query._distinct,
                                         _join_path(path, 'distinct_on')),
            'lateral': bool(query._lateral),
            'alias': query._alias}
        descriptor.update(self._query_common(query, path))
        if isinstance(query, ModelSelect):
            descriptor['model'] = self.node(query.model,
                                           _join_path(path, 'model'))
            descriptor['default'] = bool(query._is_default)
            descriptor['join_context'] = self.node(
                query._join_ctx, _join_path(path, 'join_context'))
            descriptor['joins'] = self._join_graph(query, path)
            descriptor.update(self._row_shape(query, path))
        return descriptor

    def _join_graph(self, query, path):
        result = []
        for source, joins in query._joins.items():
            source_ref = self.node(source,
                                  _join_path(path, 'join_source'))
            entries = []
            for dest, attr, constructor, join_type in joins:
                entries.append({
                    'destination': self.node(
                        dest, _join_path(path, 'destination')),
                    'attribute': attr,
                    'constructor': (self.node(
                        constructor,
                        _join_path(path, 'join_constructor'))
                        if is_model(constructor) else None),
                    'join_type': join_type})
            result.append({'source': source_ref, 'joins': entries})
        return result

    def _compound(self, query, path, node_id):
        descriptor = {
            'type': ('model_compound'
                     if isinstance(query, ModelCompoundSelectQuery)
                     else 'compound'),
            'id': node_id,
            'lhs': self.node(query.lhs, _join_path(path, 'lhs')),
            'op': query.op,
            'rhs': self.node(query.rhs, _join_path(path, 'rhs')),
            'alias': query._alias}
        descriptor.update(self._query_common(query, path))
        if isinstance(query, ModelCompoundSelectQuery):
            descriptor['model'] = self.node(query.model,
                                           _join_path(path, 'model'))
            descriptor.update(self._row_shape(query, path))
        return descriptor


def _expect_dict(value, path):
    if not isinstance(value, dict):
        raise InvalidQueryDescriptionError('expected object', path, value)
    return value


def _expect_str(value, path):
    if not isinstance(value, str):
        raise InvalidQueryDescriptionError('expected string', path, value)
    return value


def _expect_identifier(value, path):
    value = _expect_str(value, path)
    if not PYTHON_IDENTIFIER_RE.match(value) or value.startswith('__'):
        raise InvalidQueryDescriptionError('invalid identifier', path, value)
    return value


def _expect_sql_identifier(value, path):
    value = _expect_str(value, path)
    if not value or value != value.strip() or '"' in value or ';' in value:
        raise InvalidQueryDescriptionError('invalid SQL identifier', path,
                                          value)
    return value


class QueryDecoder(object):
    def __init__(self, registry, bind_database=True):
        self.registry = registry
        self.bind_database = bind_database
        self.description = None
        self.nodes = {}
        self.values = []
        self.objects = {}
        self.populated = set()
        self.populating = set()

    def decode(self, description, path='$'):
        self.description = _expect_dict(description, path)
        allowed = {'format', 'version', 'root', 'nodes', 'values'}
        unexpected = set(self.description) - allowed
        if unexpected:
            raise InvalidQueryDescriptionError(
                'unexpected key', _join_path(path, sorted(unexpected)[0]))
        if self.description.get('format') != FORMAT:
            raise InvalidQueryDescriptionError(
                'unsupported format', _join_path(path, 'format'),
                self.description.get('format'))
        if self.description.get('version') != VERSION:
            raise InvalidQueryDescriptionError(
                'unsupported version', _join_path(path, 'version'),
                self.description.get('version'))
        nodes = _expect_dict(self.description.get('nodes'),
                             _join_path(path, 'nodes'))
        values = self.description.get('values')
        if not isinstance(values, list):
            raise InvalidQueryDescriptionError(
                'expected list', _join_path(path, 'values'), values)
        self.nodes = nodes
        self.values = values
        for node_id, descriptor in nodes.items():
            if not isinstance(node_id, str):
                raise InvalidQueryDescriptionError(
                    'invalid node id', _join_path(path, 'nodes'), node_id)
            self._allocate(node_id,
                           _expect_dict(descriptor,
                                        _join_path(_join_path(path, 'nodes'),
                                                  node_id)))
        root = self.ref(self.description.get('root'),
                        _join_path(path, 'root'))
        if self.bind_database:
            database = self._database_for(root)
            if database is not None:
                root.bind(database)
        return root

    def _database_for(self, root):
        stack = [root]
        seen = set()
        while stack:
            node = stack.pop()
            if node is None or id(node) in seen:
                continue
            seen.add(id(node))
            if is_model(node):
                database = node._meta.get_database_instance()
                if database is not None:
                    return database
            elif isinstance(node, ModelAlias):
                stack.append(node.model)
            elif isinstance(node, Table) and node._model is not None:
                stack.append(node._model)
            elif isinstance(node, CTE):
                stack.append(node._query)
            elif isinstance(node, Join):
                stack.extend((node.lhs, node.rhs))
            elif isinstance(node, CompoundSelectQuery):
                stack.extend((node.lhs, node.rhs))
                if node._cte_list:
                    stack.extend(node._cte_list)
                if getattr(node, 'model', None) is not None:
                    stack.append(node.model)
            elif isinstance(node, SelectBase):
                stack.extend(node._from_list)
                if node._cte_list:
                    stack.extend(node._cte_list)
                if getattr(node, 'model', None) is not None:
                    stack.append(node.model)
        return None

    def _allocate(self, node_id, descriptor):
        kind = descriptor.get('type')
        if descriptor.get('id') != node_id:
            raise InvalidQueryDescriptionError(
                'node id mismatch', _join_path('$.nodes', node_id),
                descriptor.get('id'))
        if kind in ('select', 'model_select'):
            obj = object.__new__(ModelSelect if kind == 'model_select'
                                 else Select)
        elif kind in ('compound', 'model_compound'):
            obj = object.__new__(
                ModelCompoundSelectQuery if kind == 'model_compound'
                else CompoundSelectQuery)
        elif kind == 'join':
            obj = object.__new__(Join)
            obj._alias = None
        elif kind == 'cte':
            obj = object.__new__(CTE)
            obj._hash = id(obj)
            obj._query = Select()
        elif kind == 'table':
            obj = object.__new__(Table)
            obj._hash = id(obj)
        elif kind == 'model_alias':
            obj = object.__new__(ModelAlias)
        elif kind == 'alias':
            obj = object.__new__(Alias)
            obj.node = None
            obj._alias = None
            obj._coerce = True
            obj._converter = None
        elif kind not in GRAPH_NODE_TYPES:
            raise InvalidQueryDescriptionError(
                'node cannot be shared',
                _join_path('$.nodes', node_id), kind)
        else:
            obj = None
        self.objects[node_id] = obj

    def ref(self, ref, path):
        _expect_dict(ref, path)
        namespace = ref.get('$ref')
        ref_id = ref.get('id')
        if not isinstance(ref_id, str):
            raise InvalidQueryDescriptionError('invalid reference id', path,
                                              ref_id)
        if namespace == 'nodes':
            if ref_id not in self.objects:
                raise InvalidQueryDescriptionError('unknown node', path,
                                                  ref_id)
            self.populate(ref_id, path)
            return self.objects[ref_id]
        if namespace == 'values':
            if not ref_id or ref_id[0] != 'v' or not ref_id[1:].isdigit():
                raise InvalidQueryDescriptionError('unknown value', path,
                                                  ref_id)
            index = int(ref_id[1:])
            if index >= len(self.values):
                raise InvalidQueryDescriptionError('unknown value', path,
                                                  ref_id)
            descriptor = self.values[index]
            return decode_scalar(descriptor, path)
        raise InvalidQueryDescriptionError('unknown reference namespace', path,
                                          namespace)

    def build(self, value, path):
        if value is None:
            return None
        if _is_ref(value):
            return self.ref(value, path)
        descriptor = _expect_dict(value, path)
        if 'multi' in descriptor and set(descriptor) == {'multi'}:
            items = descriptor.get('multi')
            if not isinstance(items, list):
                raise InvalidQueryDescriptionError(
                    'expected list', _join_path(path, 'multi'), items)
            return Value([self.build(item,
                                    _join_path(_join_path(path, 'multi'),
                                               index))
                           for index, item in enumerate(items)],
                         None, unpack=True)
        kind = descriptor.get('type')
        if not isinstance(kind, str) or kind not in NODE_TYPES:
            raise InvalidQueryDescriptionError('unknown node type', path, kind)
        check_keys(descriptor, kind, path)
        method = getattr(self, '_node_%s' % kind, None)
        if method is None:
            raise InvalidQueryDescriptionError('unknown node type', path, kind)
        return method(descriptor, path)

    def require(self, descriptor, key, path, required=True):
        value = descriptor.get(key)
        if value is None and required:
            raise InvalidQueryDescriptionError('missing %s' % key,
                                              _join_path(path, key))
        return value

    def populate(self, node_id, path='$'):
        if node_id in self.populated:
            return self.objects[node_id]
        if node_id in self.populating:
            raise InvalidQueryDescriptionError(
                'reference cycle', path, node_id)
        descriptor = self.nodes.get(node_id)
        if descriptor is None:
            raise InvalidQueryDescriptionError('unknown node', path, node_id)
        if descriptor.get('id') != node_id:
            raise InvalidQueryDescriptionError('node id mismatch', path,
                                              descriptor.get('id'))
        self.populating.add(node_id)
        kind = descriptor.get('type')
        if not isinstance(kind, str) or kind not in GRAPH_NODE_TYPES:
            raise InvalidQueryDescriptionError('unknown graph node', path,
                                              kind)
        check_keys(descriptor, kind, path)
        method = getattr(self, '_populate_%s' % kind, None)
        if method is None:
            raise InvalidQueryDescriptionError('unknown graph node', path,
                                              kind)
        try:
            method(node_id, descriptor,
                   _join_path('$.nodes', node_id))
        finally:
            self.populating.discard(node_id)
        self.populated.add(node_id)
        return self.objects[node_id]

    def _node_model(self, d, path):
        return self.registry.get_model(
            _expect_str(d.get('id'), _join_path(path, 'id')), path)

    def _node_field(self, d, path):
        model = self.registry.get_model(
            _expect_str(self.require(d, 'model', path),
                        _join_path(path, 'model')), path)
        name = _expect_str(self.require(d, 'name', path),
                           _join_path(path, 'name'))
        _expect_identifier(name, _join_path(path, 'name'))
        try:
            return model._meta.fields[name]
        except KeyError:
            raise InvalidQueryDescriptionError('unknown field', path, name)

    def _node_field_alias(self, d, path):
        source = self.build(self.require(d, 'source', path),
                           _join_path(path, 'source'))
        name = _expect_str(self.require(d, 'name', path),
                           _join_path(path, 'name'))
        _expect_identifier(name, _join_path(path, 'name'))
        if not isinstance(source, ModelAlias):
            raise InvalidQueryDescriptionError(
                'field alias source must be a model alias', path)
        return getattr(source, name)

    def _node_column(self, d, path):
        return Column(self.build(self.require(d, 'source', path),
                                _join_path(path, 'source')),
                      _expect_str(self.require(d, 'name', path),
                                  _join_path(path, 'name')))

    def _node_star(self, d, path):
        return Star(self.build(self.require(d, 'source', path),
                              _join_path(path, 'source')))

    def _node_ordering(self, d, path):
        direction = d.get('direction')
        if direction not in ('ASC', 'DESC'):
            raise InvalidQueryDescriptionError(
                'invalid direction', _join_path(path, 'direction'),
                direction)
        collation = d.get('collation')
        if collation is not None:
            collation = _expect_str(collation,
                                   _join_path(path, 'collation'))
            if collation.upper() not in self.registry.collations:
                raise InvalidQueryDescriptionError(
                    'collation is not whitelisted', path, collation)
        nulls = d.get('nulls')
        if nulls not in (None, 'first', 'last'):
            raise InvalidQueryDescriptionError(
                'invalid null ordering', _join_path(path, 'nulls'), nulls)
        return Ordering(self.build(d.get('node'),
                                  _join_path(path, 'node')),
                        direction, collation, nulls)

    def _node_value(self, d, path):
        converter = self.build(d.get('converter'),
                              _join_path(path, 'converter'))
        if isinstance(converter, Field):
            converter = converter.db_value
        if d.get('multi'):
            items = d.get('items')
            if not isinstance(items, list):
                raise InvalidQueryDescriptionError(
                    'expected list', _join_path(path, 'items'), items)
            values = [self.build(item, _join_path(path, index))
                      for index, item in enumerate(items)]
            return Value(values, converter, unpack=True)
        return Value(self.build(self.require(d, 'value', path),
                               _join_path(path, 'value')),
                     converter, unpack=False)

    def _expression(self, d, path, cls=Expression):
        op = d.get('op')
        if op not in OPERATORS:
            raise InvalidQueryDescriptionError(
                'operator is not whitelisted', _join_path(path, 'op'), op)
        expression = cls(self.build(self.require(d, 'lhs', path),
                                   _join_path(path, 'lhs')),
                         op,
                         self.build(d.get('rhs'),
                                   _join_path(path, 'rhs')),
                         flat=bool(d.get('flat')))
        return expression

    def _node_expression(self, d, path):
        return self._expression(d, path)

    def _node_string_expression(self, d, path):
        return self._expression(d, path, StringExpression)

    def _node_between(self, d, path):
        expression = Expression(
            self.build(self.require(d, 'lhs', path),
                       _join_path(path, 'lhs')),
            OP.BETWEEN,
            NodeList((self.build(self.require(d, 'low', path),
                       _join_path(path, 'low')),
                      SQL('AND'),
                      self.build(self.require(d, 'high', path),
                       _join_path(path, 'high')))),
            flat=bool(d.get('flat')))
        return expression

    def _node_string_between(self, d, path):
        expression = self._node_between(d, path)
        expression.__class__ = StringExpression
        return expression

    def _node_function(self, d, path):
        identifier = _expect_str(self.require(d, 'name', path),
                                 _join_path(path, 'name'))
        name = self.registry.get_function_name(
            identifier, _join_path(path, 'name'))
        args = d.get('arguments', [])
        if not isinstance(args, list):
            raise InvalidQueryDescriptionError(
                'expected list', _join_path(path, 'arguments'), args)
        function = Function(name, tuple(
            self.build(arg, _join_path(_join_path(path, 'arguments'), index))
            for index, arg in enumerate(args)),
            coerce=bool(d.get('coerce', True)))
        if d.get('filter') is not None:
            function = function.filter(self.build(
                d.get('filter'), _join_path(path, 'filter')))
        order_by = d.get('order_by')
        if order_by is not None:
            function = function.order_by(*self._list(order_by,
                                                    _join_path(path,
                                                               'order_by')))
        return function

    def _node_case(self, d, path):
        branches = d.get('branches', [])
        if not isinstance(branches, list):
            raise InvalidQueryDescriptionError(
                'expected list', _join_path(path, 'branches'), branches)
        tuples = []
        for index, branch in enumerate(branches):
            branch_path = _join_path(_join_path(path, 'branches'), index)
            tuples.append((
                self.build(self.require(branch, 'when', branch_path),
                           _join_path(branch_path, 'when')),
                self.build(self.require(branch, 'then', branch_path),
                           _join_path(branch_path, 'then'))))
        return Case(self.build(d.get('predicate'),
                              _join_path(path, 'predicate')),
                    tuples,
                    self.build(d.get('default'),
                              _join_path(path, 'default')))

    def _node_negated(self, d, path):
        return Negated(self.build(self.require(d, 'node', path),
                                _join_path(path, 'node')))

    def _node_bitwise_negated(self, d, path):
        return BitwiseNegated(self.build(self.require(d, 'node', path),
                                       _join_path(path, 'node')))

    def _node_cast(self, d, path):
        cast = _expect_str(self.require(d, 'cast', path),
                           _join_path(path, 'cast')).upper()
        if cast not in self.registry.casts:
            raise InvalidQueryDescriptionError(
                'cast is not whitelisted', path, cast)
        return Cast(self.build(self.require(d, 'node', path),
                    _join_path(path, 'node')), cast)

    def _node_node_list(self, d, path):
        glue = d.get('glue')
        if glue not in ('space', 'comma'):
            raise InvalidQueryDescriptionError(
                'invalid glue', _join_path(path, 'glue'), glue)
        parts = d.get('parts', [])
        if not isinstance(parts, list):
            raise InvalidQueryDescriptionError(
                'expected list', _join_path(path, 'parts'), parts)
        nodes = []
        for index, part in enumerate(parts):
            part_path = _join_path(_join_path(path, 'parts'), index)
            if isinstance(part, dict) and part.get('keyword'):
                keyword = part.get('keyword')
                if keyword not in ('AND', 'DISTINCT', 'ORDER BY'):
                    raise InvalidQueryDescriptionError(
                        'keyword is not whitelisted', part_path, keyword)
                nodes.append(SQL(keyword))
            else:
                nodes.append(self.build(part, part_path))
        return NodeList(nodes, ' ' if glue == 'space' else ', ',
                        parens=bool(d.get('parens')))

    def _list(self, value, path):
        if not isinstance(value, list):
            raise InvalidQueryDescriptionError('expected list', path, value)
        return [self.build(item, _join_path(path, index))
                for index, item in enumerate(value)]

    def _populate_alias(self, node_id, d, path):
        obj = self.objects[node_id]
        obj.node = self.build(self.require(d, 'node', path),
                             _join_path(path, 'node'))
        obj._alias = _expect_sql_identifier(
            self.require(d, 'alias', path), _join_path(path, 'alias'))
        obj._coerce = getattr(obj.node, '_coerce', True)
        obj._converter = getattr(obj.node, '_converter', None)

    def _populate_model_alias(self, node_id, d, path):
        model = self.build(self.require(d, 'model', path),
                          _join_path(path, 'model'))
        obj = self.objects[node_id]
        obj.__dict__['model'] = model
        alias = d.get('alias')
        if alias is not None:
            alias = _expect_sql_identifier(alias,
                                           _join_path(path, 'alias'))
        obj.__dict__['alias'] = alias

    def _populate_table(self, node_id, d, path):
        if d.get('model') is not None:
            model = self.build(d.get('model'), _join_path(path, 'model'))
            table = model._meta.table.clone()
        else:
            table = self.registry.get_table(
                _expect_str(self.require(d, 'table', path),
                            _join_path(path, 'table')), path).clone()
        if d.get('alias') is not None:
            table._alias = _expect_sql_identifier(
                d.get('alias'), _join_path(path, 'alias'))
        self.objects[node_id].__dict__.clear()
        self.objects[node_id].__dict__.update(table.__dict__)

    def _populate_join(self, node_id, d, path):
        join_type = d.get('join_type')
        if join_type not in JOIN_TYPES:
            raise InvalidQueryDescriptionError(
                'join type is not whitelisted',
                _join_path(path, 'join_type'), join_type)
        obj = self.objects[node_id]
        obj.lhs = self.build(self.require(d, 'lhs', path),
                             _join_path(path, 'lhs'))
        obj.rhs = self.build(self.require(d, 'rhs', path),
                             _join_path(path, 'rhs'))
        obj.join_type = join_type
        obj._on = self.build(d.get('on'), _join_path(path, 'on'))
        alias = d.get('alias')
        if alias is not None:
            alias = _expect_sql_identifier(alias,
                                           _join_path(path, 'alias'))
        obj._alias = alias

    def _populate_cte(self, node_id, d, path):
        columns_data = d.get('columns')
        columns = None
        if columns_data is not None:
            if not isinstance(columns_data, list):
                raise InvalidQueryDescriptionError(
                    'expected list', _join_path(path, 'columns'),
                    columns_data)
            columns = []
            for index, column_path in enumerate(columns_data):
                if not isinstance(column_path, list) or not column_path:
                    raise InvalidQueryDescriptionError(
                        'expected identifier path',
                        _join_path(_join_path(path, 'columns'), index),
                        column_path)
                columns.append(Entity(*[
                    _expect_sql_identifier(
                        part,
                        _join_path(_join_path(path, 'columns'), index))
                    for part in column_path]))
        materialized = d.get('materialized')
        if materialized not in (None, True, False):
            raise InvalidQueryDescriptionError(
                'invalid materialized value', path, materialized)
        placeholder = self.objects[node_id]
        obj = CTE(_expect_sql_identifier(
                      self.require(d, 'name', path),
                      _join_path(path, 'name')),
                  self.objects[node_id]._query,
                  recursive=bool(d.get('recursive')),
                  columns=columns,
                  materialized=materialized)
        placeholder.__dict__.clear()
        placeholder.__dict__.update(obj.__dict__)
        query = self.build(self.require(d, 'query', path),
                          _join_path(path, 'query'))
        placeholder._query = query

    def _set_common_query(self, query, d, path):
        query._database = None
        query._cursor_wrapper = None
        query._where = self.build(d.get('where'),
                                 _join_path(path, 'where'))
        query._order_by = (tuple(self._list(d['order_by'],
                                           _join_path(path, 'order_by')))
                           if d.get('order_by') is not None else None)
        query._limit = self.build(d.get('limit'),
                                 _join_path(path, 'limit'))
        query._offset = self.build(d.get('offset'),
                                  _join_path(path, 'offset'))
        query._cte_list = (tuple(self._list(d['cte'],
                                            _join_path(path, 'cte')))
                           if d.get('cte') is not None else None)

    def _populate_select(self, node_id, d, path):
        query = self.objects[node_id]
        from_list = self._list(self.require(d, 'from', path),
                               _join_path(path, 'from'))
        columns = self._list(self.require(d, 'columns', path),
                             _join_path(path, 'columns'))
        query._from_list = list(from_list)
        query._returning = tuple(columns)
        query._group_by = (self._list(d['group_by'],
                                     _join_path(path, 'group_by'))
                           if d.get('group_by') is not None else None)
        query._having = self.build(d.get('having'),
                                  _join_path(path, 'having'))
        simple_distinct = d.get('distinct')
        if simple_distinct not in (None, True, False):
            raise InvalidQueryDescriptionError(
                'invalid distinct flag', path, simple_distinct)
        query._simple_distinct = simple_distinct
        query._distinct = (tuple(self._list(d['distinct_on'],
                                           _join_path(path, 'distinct_on')))
                            if d.get('distinct_on') is not None else None)
        query._windows = None
        query._for_update = None
        query._lateral = bool(d.get('lateral'))
        alias = d.get('alias')
        if alias is not None:
            alias = _expect_sql_identifier(alias,
                                           _join_path(path, 'alias'))
        query._alias = alias
        self._set_common_query(query, d, path)
        query._update_hash()

    def _populate_model_select(self, node_id, d, path):
        self._populate_select(node_id, d, path)
        query = self.objects[node_id]
        model = self.build(self.require(d, 'model', path),
                          _join_path(path, 'model'))
        query.model = model
        query._join_ctx = self.build(self.require(d, 'join_context', path),
                                    _join_path(path, 'join_context'))
        query._is_default = bool(d.get('default'))
        query._joins = self._join_graph(d, path)
        query._load_tree = None
        row_type = d.get('row_type')
        if row_type not in (None, ROW.MODEL, ROW.DICT, ROW.TUPLE,
                            ROW.NAMED_TUPLE, ROW.CONSTRUCTOR):
            raise InvalidQueryDescriptionError(
                'invalid row type', _join_path(path, 'row_type'), row_type)
        query._row_type = row_type
        query._constructor = self.build(d.get('constructor'),
                                       _join_path(path, 'constructor'))
        if self.bind_database:
            database = model._meta.get_database_instance()
            query._database = database

    def _join_graph(self, d, path):
        joins_data = d.get('joins', [])
        if not isinstance(joins_data, list):
            raise InvalidQueryDescriptionError(
                'expected list', _join_path(path, 'joins'), joins_data)
        result = {}
        for index, item in enumerate(joins_data):
            item_path = _join_path(_join_path(path, 'joins'), index)
            _expect_dict(item, item_path)
            source = self.build(self.require(item, 'source', item_path),
                                _join_path(item_path, 'source'))
            entries = []
            join_entries = item.get('joins', [])
            if not isinstance(join_entries, list):
                raise InvalidQueryDescriptionError(
                    'expected list', _join_path(item_path, 'joins'),
                    join_entries)
            for j_index, entry in enumerate(join_entries):
                entry_path = _join_path(_join_path(item_path, 'joins'),
                                        j_index)
                _expect_dict(entry, entry_path)
                join_type = entry.get('join_type')
                if join_type not in JOIN_TYPES:
                    raise InvalidQueryDescriptionError(
                        'join type is not whitelisted',
                        _join_path(entry_path, 'join_type'), join_type)
                constructor = self.build(entry.get('constructor'),
                                        _join_path(entry_path,
                                                   'constructor'))
                if constructor is not None and not is_model(constructor):
                    raise InvalidQueryDescriptionError(
                        'invalid constructor', entry_path)
                attribute = entry.get('attribute')
                if attribute is not None:
                    _expect_identifier(
                        attribute,
                        _join_path(entry_path, 'attribute'))
                entries.append((
                    self.build(self.require(entry, 'destination', entry_path),
                               _join_path(entry_path, 'destination')),
                    attribute, constructor, join_type))
            result[source] = entries
        return result

    def _populate_compound(self, node_id, d, path):
        if node_id in self.populated:
            return
        query = self.objects[node_id]
        query.lhs = self.build(self.require(d, 'lhs', path),
                              _join_path(path, 'lhs'))
        query.rhs = self.build(self.require(d, 'rhs', path),
                              _join_path(path, 'rhs'))
        op = d.get('op')
        if op not in ('UNION', 'UNION ALL', 'INTERSECT', 'EXCEPT'):
            raise InvalidQueryDescriptionError(
                'invalid compound operation', _join_path(path, 'op'), op)
        query.op = op
        alias = d.get('alias')
        if alias is not None:
            alias = _expect_sql_identifier(alias,
                                           _join_path(path, 'alias'))
        query._alias = alias
        self._set_common_query(query, d, path)
        if hasattr(query, '_update_hash'):
            query._update_hash()

    def _populate_model_compound(self, node_id, d, path):
        self._populate_compound(node_id, d, path)
        query = self.objects[node_id]
        model = self.build(self.require(d, 'model', path),
                          _join_path(path, 'model'))
        query.model = model
        query._load_tree = None
        row_type = d.get('row_type')
        if row_type not in (None, ROW.MODEL, ROW.DICT, ROW.TUPLE,
                            ROW.NAMED_TUPLE, ROW.CONSTRUCTOR):
            raise InvalidQueryDescriptionError(
                'invalid row type', _join_path(path, 'row_type'), row_type)
        query._row_type = row_type
        query._constructor = self.build(d.get('constructor'),
                                       _join_path(path, 'constructor'))
        if self.bind_database:
            query._database = model._meta.get_database_instance()


def dumps_query(query, registry):
    """Return a JSON-safe query description."""
    return QueryEncoder(registry).encode(query)


def loads_query(description, registry, bind_database=True):
    """Rebuild a query without importing modules or executing SQL."""
    return QueryDecoder(registry, bind_database).decode(description)


def save_query(path, query, registry, **json_kwargs):
    description = dumps_query(query, registry)
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(description, fh, ensure_ascii=False,
                  separators=(',', ':'), allow_nan=False, **json_kwargs)


def load_query(path, registry, bind_database=True):
    with open(path, 'r', encoding='utf-8') as fh:
        description = json.load(fh)
    return loads_query(description, registry, bind_database)
