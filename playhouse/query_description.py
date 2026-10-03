"""Versioned, safe serialization for a supported subset of Peewee queries.

The description is a JSON-compatible document.  It contains no SQL text,
callables, module paths or database connection settings.  Models and fields
are resolved through identifiers explicitly registered by the application.
"""

import datetime
import decimal
import json
import math
import re
import types
import uuid

from peewee import Alias
from peewee import BitwiseNegated
from peewee import Case
from peewee import Column
from peewee import Entity
from peewee import Expression
from peewee import Field
from peewee import FieldAlias
from peewee import Function
from peewee import JOIN
from peewee import Model
from peewee import ModelAlias
from peewee import ModelCompoundSelectQuery
from peewee import ModelSelect
from peewee import Negated
from peewee import Node
from peewee import NodeList
from peewee import OP
from peewee import Ordering
from peewee import ROW
from peewee import Select
from peewee import SelectBase
from peewee import Star
from peewee import StringExpression
from peewee import Value
from peewee import ValueLiterals
from peewee import ValuesList
from peewee import CompoundSelectQuery
from peewee import CTE
from peewee import Join
from peewee import is_model
from peewee import SQL


FORMAT = "peewee-query"
VERSION = 1


class QueryDescriptionError(ValueError):
    """Raised when a query cannot be encoded or safely decoded."""


def _path(path, item):
    if not path:
        return str(item)
    return "%s.%s" % (path, item)


def _unsupported(node, path):
    raise QueryDescriptionError(
        "%s: unsupported node %r" % (path, type(node).__name__))


def _require(value, expected, path):
    if not isinstance(value, expected):
        raise QueryDescriptionError(
            "%s: expected %s, got %s" % (
                path, expected, type(value).__name__))
    return value


def _identifier(value, path):
    value = _require(value, str, path)
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", value):
        raise QueryDescriptionError("%s: invalid identifier %r" % (path, value))
    return value


JOIN_NAMES = {
    JOIN.INNER: "inner",
    JOIN.LEFT_OUTER: "left_outer",
    JOIN.RIGHT_OUTER: "right_outer",
    JOIN.FULL_OUTER: "full_outer",
    JOIN.CROSS: "cross",
    JOIN.FULL: "full",
}
JOIN_VALUES = dict((value, key) for key, value in JOIN_NAMES.items())

OPERATORS = frozenset((
    OP.AND, OP.OR, OP.ADD, OP.SUB, OP.MUL, OP.DIV, OP.BIN_AND,
    OP.BIN_OR, OP.XOR, OP.MOD, OP.EQ, OP.LT, OP.LTE, OP.GT, OP.GTE, OP.NE,
    OP.IN, OP.NOT_IN, OP.IS, OP.IS_NOT, OP.LIKE, OP.ILIKE, OP.BETWEEN,
    OP.REGEXP, OP.IREGEXP, OP.CONCAT, OP.BITWISE_NEGATION))

ROW_TYPES = {
    ROW.TUPLE: "tuple",
    ROW.DICT: "dict",
    ROW.NAMED_TUPLE: "named_tuple",
    ROW.MODEL: "model",
}
ROW_TYPE_VALUES = dict((value, key) for key, value in ROW_TYPES.items())


def _is_graph_node(value):
    return is_model(value) or (isinstance(value, Node)
                               and not isinstance(value, Model))


class QueryRegistry(object):
    def __init__(self):
        self._models = {}
        self._model_ids = {}
        self._fields = {}
        self._field_ids = {}
        self._functions = {}

    def register_model(self, model, identifier=None):
        if not is_model(model):
            raise QueryDescriptionError("expected a Peewee model class")
        identifier = identifier or model.__name__
        _identifier(identifier, "model identifier")
        previous = self._models.get(identifier)
        if previous is not None and previous is not model:
            raise QueryDescriptionError(
                "model identifier %r is already registered" % identifier)
        self._models[identifier] = model
        self._model_ids[id(model)] = identifier
        return self

    def register_field(self, field, identifier=None, model=None):
        if not isinstance(field, Field):
            raise QueryDescriptionError("expected a Peewee field")
        model = model or getattr(field, "model", None)
        if not is_model(model):
            raise QueryDescriptionError("field is not bound to a model")
        model_id = self.model_id(model)
        identifier = identifier or field.name
        _identifier(identifier, "field identifier")
        key = (model_id, identifier)
        previous = self._fields.get(key)
        if previous is not None and previous is not field:
            raise QueryDescriptionError(
                "field identifier %r is already registered" % (key,))
        self._fields[key] = field
        self._field_ids[id(field)] = key
        return self

    def register_fields(self, model, identifiers=None):
        self.register_model(model)
        identifiers = identifiers or {}
        for name, field in model._meta.fields.items():
            self.register_field(field, identifiers.get(name, name), model)
        return self

    def model_id(self, model):
        try:
            return self._model_ids[id(model)]
        except KeyError:
            raise QueryDescriptionError(
                "model %s is not registered" % model.__name__)

    def field_id(self, field):
        if isinstance(field, FieldAlias):
            field = field.field
        try:
            return self._field_ids[id(field)]
        except KeyError:
            raise QueryDescriptionError(
                "field %s is not registered" % field)

    def resolve_model(self, identifier):
        model = self._models.get(identifier)
        if model is None:
            raise QueryDescriptionError("unknown model identifier %r" % identifier)
        return model

    def resolve_field(self, model_identifier, field_identifier):
        key = (model_identifier, field_identifier)
        field = self._fields.get(key)
        if field is None:
            raise QueryDescriptionError("unknown field identifier %r" % (key,))
        return field

    def allow_function(self, name, identifier=None):
        if not isinstance(name, str) or not re.match(
                r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            raise QueryDescriptionError("invalid function name %r" % name)
        identifier = identifier or name.lower()
        _identifier(identifier, "function identifier")
        previous = self._functions.get(identifier)
        if previous is not None and previous != name:
            raise QueryDescriptionError(
                "function identifier %r is already registered" % identifier)
        self._functions[identifier] = name
        return self

    def function_name(self, name):
        key = name.lower()
        allowed = self._functions.get(key)
        if allowed is None or allowed != name:
            raise QueryDescriptionError("function %r is not allowed" % name)
        return name

    def resolve_function(self, identifier):
        name = self._functions.get(identifier)
        if name is None:
            raise QueryDescriptionError(
                "unknown function identifier %r" % identifier)
        return name

    def dumps(self, query, **kwargs):
        return dumps_query(query, self, **kwargs)

    def loads(self, description, **kwargs):
        return loads_query(description, self, **kwargs)


def dumps_query(query, registry, *, indent=None, sort_keys=False):
    description = encode_query(query, registry)
    return json.dumps(description, indent=indent, sort_keys=sort_keys,
                      allow_nan=False)


def loads_query(text, registry):
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8")
    return decode_query(json.loads(text), registry)


class _ValueEncoder(object):
    def __init__(self, registry):
        self.registry = registry
        self.values = []
        self.node_encoder = None

    def add(self, value, path):
        encoded = self.encode(value, path)
        index = len(self.values)
        self.values.append(encoded)
        return index

    def compound(self, value, path):
        items = []
        for index, item in enumerate(value):
            if _is_graph_node(item):
                node = self.node_encoder.visit(item, _path(path, index))
                items.append({"kind": "node", "id": node["id"]})
            else:
                items.append({
                    "kind": "value",
                    "id": self.add(item, _path(path, index)),
                })
        return {"type": type(value).__name__, "items": items}

    def encode(self, value, path):
        if value is None:
            return {"type": "null"}
        if isinstance(value, bool):
            return {"type": "bool", "value": value}
        if isinstance(value, int):
            return {"type": "int", "value": value}
        if isinstance(value, float):
            if not math.isfinite(value):
                raise QueryDescriptionError("%s: non-finite float" % path)
            return {"type": "float", "value": value}
        if isinstance(value, str):
            return {"type": "str", "value": value}
        if isinstance(value, (bytes, bytearray)):
            return {"type": "bytes", "value": bytes(value).hex()}
        if isinstance(value, decimal.Decimal):
            return {"type": "decimal", "value": str(value)}
        if isinstance(value, uuid.UUID):
            return {"type": "uuid", "value": str(value)}
        if isinstance(value, datetime.datetime):
            return {"type": "datetime", "value": value.isoformat()}
        if isinstance(value, datetime.date):
            return {"type": "date", "value": value.isoformat()}
        if isinstance(value, datetime.time):
            return {"type": "time", "value": value.isoformat()}
        if isinstance(value, range):
            return {
                "type": "range",
                "start": self.encode(value.start, _path(path, "start")),
                "stop": self.encode(value.stop, _path(path, "stop")),
                "step": self.encode(value.step, _path(path, "step")),
            }
        if isinstance(value, Model):
            return self.model_value(value, path)
        if isinstance(value, dict):
            return self.sequence_or_mapping("dict", value, path, True)
        if isinstance(value, (list, tuple, frozenset, set,
                              types.GeneratorType)):
            kind = type(value).__name__
            materialized = list(value)
            if any(_is_graph_node(item) for item in materialized):
                return self.compound(materialized, path)
            return self.sequence_or_mapping(kind, materialized, path, False)
        raise QueryDescriptionError(
            "%s: unsupported value type %s" % (path, type(value).__name__))

    def model_value(self, model, path):
        model_id = self.registry.model_id(type(model))
        pk_name = type(model)._meta.primary_key.name
        pk_value = getattr(model, pk_name)
        return {
            "type": "model",
            "model": model_id,
            "pk": self.encode(pk_value, _path(path, "pk")),
        }

    def sequence_or_mapping(self, kind, items, path, mapping):
        if mapping:
            encoded_items = []
            for key, item in items.items():
                if not isinstance(key, str):
                    raise QueryDescriptionError("%s: dict keys must be strings" % path)
                encoded_items.append({
                    "key": key,
                    "value": self.encode(item, _path(path, key)),
                })
        else:
            encoded_items = [
                self.encode(item, _path(path, i))
                for i, item in enumerate(items)]
        return {"type": kind, "items": encoded_items}

    def converter(self, converter, path):
        if converter is None:
            return None
        if converter is False:
            return False
        func = getattr(converter, "__func__", None)
        target = getattr(converter, "__self__", None)
        if func is Field.db_value and isinstance(target, Field):
            model_id = self.registry.model_id(target.model)
            return {
                "type": "field",
                "model": model_id,
                "field": self.registry.field_id(target)[1],
            }
        raise QueryDescriptionError("%s: unsupported value converter" % path)


NODE_TYPES = (
    Model, Select, CompoundSelectQuery, CTE, Join, ValuesList, Field,
    ModelAlias, FieldAlias, Column, Star, Alias, Ordering, Negated,
    BitwiseNegated, Expression, Function, Case, ValueLiterals, NodeList,
    Value, SQL)


class QueryEncoder(object):
    def __init__(self, query, registry):
        self.registry = registry
        self.value_encoder = _ValueEncoder(registry)
        self.value_encoder.node_encoder = self
        self.nodes = {}
        self.ids = {}
        self.next_id = 0
        self.query = query

    def encode(self):
        if not isinstance(self.query, SelectBase):
            _unsupported(self.query, "root")
        root = self.visit(self.query, "root")
        return {
            "format": FORMAT,
            "version": VERSION,
            "root": root,
            "nodes": [self.nodes[index] for index in sorted(self.nodes)],
            "values": self.value_encoder.values,
        }

    def visit(self, node, path):
        if is_model(node):
            return {"kind": "model_ref", "model": self.model_id(node)}
        if not isinstance(node, NODE_TYPES):
            _unsupported(node, path)
        identity = id(node)
        if identity in self.ids:
            return {"kind": "node_ref", "id": self.ids[identity]}
        node_id = self.next_id
        self.next_id += 1
        self.ids[identity] = node_id
        descriptor = self.encode_node(node, _path(path, "n%s" % node_id))
        descriptor["id"] = node_id
        self.nodes[node_id] = descriptor
        return {"kind": "node_ref", "id": node_id}

    def model_id(self, model):
        return self.registry.model_id(model)

    def field_descriptor(self, field, path):
        if isinstance(field, FieldAlias):
            return {
                "kind": "field_alias",
                "model": self.model_id(field.source.model),
                "field": self.registry.field_id(field)[1],
                "source": self.visit(field.source,
                                    _path(path, "source")),
            }
        return {
            "kind": "field",
            "model": self.model_id(field.model),
            "field": self.registry.field_id(field)[1],
        }

    def encode_node(self, node, path):
        if isinstance(node, ModelSelect):
            return self.encode_model_select(node, path)
        if isinstance(node, CompoundSelectQuery):
            return self.encode_compound(node, path)
        if isinstance(node, Select):
            return self.encode_select(node, path)
        if isinstance(node, CTE):
            return self.encode_cte(node, path)
        if isinstance(node, Join):
            return self.encode_join(node, path)
        if isinstance(node, ValuesList):
            return self.encode_values_list(node, path)
        if isinstance(node, ModelAlias):
            return {
                "kind": "model_alias",
                "model": self.model_id(node.model),
                "alias": node.alias,
            }
        if isinstance(node, FieldAlias):
            return self.field_descriptor(node, path)
        if isinstance(node, Field):
            return self.field_descriptor(node, path)
        if isinstance(node, Column):
            return self.encode_column(node, path)
        if isinstance(node, Star):
            d = {"kind": "star"}
            self.encode_source_ref(node.source, d, "source", path)
            return d
        if isinstance(node, Alias):
            d = {"kind": "alias", "alias": node._alias}
            self.child(node.node, d, "node", path)
            return d
        if isinstance(node, Ordering):
            if node.collation is not None:
                _identifier(node.collation, _path(path, "collation"))
            d = {
                "kind": "ordering",
                "direction": node.direction,
                "collation": node.collation,
                "nulls": node.nulls,
            }
            self.child(node.node, d, "node", path)
            return d
        if isinstance(node, Negated):
            d = {"kind": "negated"}
            self.child(node.node, d, "node", path)
            return d
        if isinstance(node, BitwiseNegated):
            d = {"kind": "bitwise_negated"}
            self.child(node.node, d, "node", path)
            return d
        if isinstance(node, Expression):
            return self.encode_expression(node, path)
        if isinstance(node, Function):
            return self.encode_function(node, path)
        if isinstance(node, Case):
            return self.encode_case(node, path)
        if isinstance(node, ValueLiterals):
            d = {"kind": "value_literals"}
            self.child(node.node, d, "node", path)
            return d
        if isinstance(node, NodeList):
            return self.encode_node_list(node, path)
        if isinstance(node, Value):
            return self.encode_value(node, path)
        if isinstance(node, SQL):
            if node.sql != "*" or node.params:
                _unsupported(node, path)
            return {"kind": "sql_star"}
        _unsupported(node, path)

    def child(self, node, descriptor, key, path):
        if node is None:
            descriptor[key] = {"kind": "none"}
        elif is_model(node):
            descriptor[key] = self.visit(node, _path(path, key))
        elif _is_graph_node(node):
            descriptor[key] = self.visit(node, _path(path, key))
        else:
            descriptor[key] = {
                "kind": "value",
                "id": self.value_encoder.add(node, _path(path, key)),
            }

    def children(self, nodes, path, key="items"):
        items = []
        for index, node in enumerate(nodes or ()):
            item = {}
            self.child(node, item, "ref", _path(path, _path(key, index)))
            items.append(item["ref"])
        return items

    def encode_source_ref(self, source, descriptor, key, path):
        descriptor[key] = self.visit(source, _path(path, key))

    def encode_column(self, node, path):
        source = node.source
        if isinstance(source, ModelAlias):
            source_ref = self.visit(source, _path(path, "source"))
        else:
            source_ref = self.visit(source, _path(path, "source"))
        return {
            "kind": "column",
            "source": source_ref,
            "name": node.name,
        }

    def encode_expression(self, node, path):
        if node.op not in OPERATORS:
            raise QueryDescriptionError("%s: unsupported operator %r" % (
                path, node.op))
        kind = ("string_expression" if isinstance(node, StringExpression)
                else "expression")
        descriptor = {
            "kind": kind,
            "op": node.op,
            "flat": bool(node.flat),
        }
        self.child(node.lhs, descriptor, "lhs", path)
        self.child(node.rhs, descriptor, "rhs", path)
        return descriptor

    def encode_function(self, node, path):
        if not node.name:
            _unsupported(node, path)
        name = self.registry.function_name(node.name)
        descriptor = {
            "kind": "function",
            "name": name.lower(),
            "coerce": bool(node._coerce),
            "arguments": [],
        }
        arguments = []
        for index, argument in enumerate(node.arguments):
            item = {}
            self.child(argument, item, "ref", _path(path, index))
            arguments.append(item["ref"])
        descriptor["arguments"] = arguments
        if node._filter is not None:
            self.child(node._filter, descriptor, "filter", path)
        if node._order_by is not None:
            descriptor["order_by"] = self.children(
                node._order_by, path, "order_by")
        if node._python_value is not None:
            _unsupported(node._python_value, _path(path, "python_value"))
        return descriptor

    def encode_case(self, node, path):
        descriptor = {"kind": "case", "branches": []}
        if node.predicate is not None:
            self.child(node.predicate, descriptor, "predicate", path)
        for index, (condition, result) in enumerate(node.expression_tuples):
            branch = {}
            self.child(condition, branch, "condition",
                       _path(path, "branches.%s" % index))
            self.child(result, branch, "result",
                       _path(path, "branches.%s" % index))
            descriptor["branches"].append(branch)
        if node.default is not None:
            self.child(node.default, descriptor, "default", path)
        return descriptor

    def encode_node_list(self, node, path):
        if (len(node.nodes) == 3 and isinstance(node.nodes[1], SQL)
                and node.nodes[1].sql == "AND"
                and not node.nodes[1].params
                and node.glue == " " and not node.parens):
            descriptor = {"kind": "between_list"}
            self.child(node.nodes[0], descriptor, "lower", path)
            self.child(node.nodes[2], descriptor, "upper", path)
            return descriptor
        if (len(node.nodes) == 2 and isinstance(node.nodes[0], SQL)
                and node.nodes[0].sql == "DISTINCT"
                and not node.nodes[0].params
                and node.glue == " " and not node.parens):
            descriptor = {"kind": "distinct_expr"}
            self.child(node.nodes[1], descriptor, "node", path)
            return descriptor
        if node.glue not in (" ", ", "):
            raise QueryDescriptionError("%s: unsupported node-list glue %r" % (
                path, node.glue))
        return {
            "kind": "nodelist",
            "items": self.children(node.nodes, path),
            "glue": node.glue,
            "parens": bool(node.parens),
        }

    def encode_value(self, node, path):
        descriptor = {
            "kind": "value",
            "unpack": bool(node.multi),
            "converter": self.value_encoder.converter(
                node.converter, _path(path, "converter")),
        }
        if node.multi:
            items = []
            for index, child in enumerate(node.values):
                item = {}
                self.child(child, item, "ref", _path(path, index))
                items.append(item["ref"])
            descriptor["items"] = items
        else:
            descriptor["id"] = self.value_encoder.add(
                node.value, _path(path, "value"))
        return descriptor

    def encode_values_list(self, node, path):
        rows = []
        for row_index, row in enumerate(node._values):
            row_refs = []
            for col_index, value in enumerate(row):
                item = {}
                self.child(value, item, "ref",
                          _path(path, "rows.%s.%s" % (row_index, col_index)))
                row_refs.append(item["ref"])
            rows.append(row_refs)
        descriptor = {
            "kind": "values_list",
            "rows": rows,
            "columns": list(node._columns or ()),
            "alias": node._alias,
        }
        return descriptor

    def common_query(self, node, descriptor, path):
        if node._where is not None:
            self.child(node._where, descriptor, "where", path)
        if node._order_by is not None:
            descriptor["order_by"] = self.children(
                node._order_by, path, "order_by")
        if node._limit is not None:
            self.child(node._limit, descriptor, "limit", path)
        if node._offset is not None:
            self.child(node._offset, descriptor, "offset", path)
        if node._cte_list:
            descriptor["ctes"] = self.children(node._cte_list, path, "ctes")
        if getattr(node, "_row_type", None) is not None:
            row_type = ROW_TYPES.get(node._row_type)
            if row_type is None:
                raise QueryDescriptionError("%s: unsupported row type" % path)
            descriptor["row_type"] = row_type
        if getattr(node, "_constructor", None) is not None:
            constructor = node._constructor
            if not is_model(constructor):
                _unsupported(constructor, _path(path, "constructor"))
            descriptor["constructor"] = self.model_id(constructor)

    def select_parts(self, node, descriptor, path):
        descriptor["from"] = self.children(node._from_list, path, "from")
        descriptor["projection"] = self.children(
            node._returning, path, "projection")
        if node._group_by is not None:
            descriptor["group_by"] = self.children(
                node._group_by, path, "group_by")
        if node._having is not None:
            self.child(node._having, descriptor, "having", path)
        if node._distinct is not None:
            descriptor["distinct"] = self.children(
                node._distinct, path, "distinct")
            descriptor["simple_distinct"] = False
        else:
            descriptor["simple_distinct"] = node._simple_distinct
        if node._windows is not None:
            _unsupported(node._windows, _path(path, "windows"))
        if node._for_update is not None:
            _unsupported(node._for_update, _path(path, "for_update"))
        if node._lateral:
            raise QueryDescriptionError("%s: lateral queries unsupported" % path)
        if node._alias is not None:
            descriptor["alias"] = node._alias

    def encode_select(self, node, path):
        descriptor = {"kind": "select"}
        self.common_query(node, descriptor, path)
        self.select_parts(node, descriptor, path)
        return descriptor

    def encode_model_select(self, node, path):
        if getattr(node, "_load_tree", None):
            _unsupported(node._load_tree, _path(path, "load_tree"))
        descriptor = {
            "kind": "model_select",
            "model_ref": (self.visit(node.model, _path(path, "model"))
                          if isinstance(node.model, ModelAlias)
                          else {"kind": "model_ref",
                                "model": self.model_id(node.model)}),
            "default": bool(node._is_default),
        }
        self.common_query(node, descriptor, path)
        self.select_parts(node, descriptor, path)
        joins = []
        for source, entries in node._joins.items():
            source_ref = self.visit(source, _path(path, "join_sources"))
            for dest, attr, constructor, join_type in entries:
                entry = {
                    "source": source_ref,
                    "attr": attr,
                    "join_type": JOIN_NAMES[join_type],
                }
                if is_model(constructor):
                    entry["constructor"] = self.model_id(constructor)
                elif constructor is dict:
                    entry["constructor"] = "dict"
                else:
                    _unsupported(constructor, _path(path, "join_constructor"))
                self.child(dest, entry, "dest", _path(path, "joins"))
                joins.append(entry)
        descriptor["join_graph"] = joins
        descriptor["join_context"] = self.visit(
            node._join_ctx, _path(path, "join_context"))
        return descriptor

    def encode_compound(self, node, path):
        descriptor = {
            "kind": "model_compound" if isinstance(
                node, ModelCompoundSelectQuery) else "compound",
            "op": node.op,
        }
        if isinstance(node, ModelCompoundSelectQuery):
            descriptor["model_ref"] = (
                self.visit(node.model, _path(path, "model"))
                if isinstance(node.model, ModelAlias)
                else {"kind": "model_ref",
                      "model": self.model_id(node.model)})
        self.child(node.lhs, descriptor, "lhs", path)
        self.child(node.rhs, descriptor, "rhs", path)
        self.common_query(node, descriptor, path)
        if node._alias is not None:
            descriptor["alias"] = node._alias
        return descriptor

    def encode_cte(self, node, path):
        columns = []
        for column in node._columns or ():
            if isinstance(column, Entity):
                if len(column._path) != 1:
                    _unsupported(column, _path(path, "columns"))
                columns.append(column._path[0])
            elif isinstance(column, str):
                columns.append(column)
            else:
                _unsupported(column, _path(path, "columns"))
        descriptor = {
            "kind": "cte",
            "name": node._alias,
            "recursive": bool(node._recursive),
            "materialized": node._materialized,
            "columns": columns,
        }
        self.child(node._query, descriptor, "query", path)
        return descriptor

    def encode_join(self, node, path):
        descriptor = {
            "kind": "join",
            "join_type": JOIN_NAMES[node.join_type],
        }
        self.child(node.lhs, descriptor, "lhs", path)
        self.child(node.rhs, descriptor, "rhs", path)
        if node._on is not None:
            self.child(node._on, descriptor, "on", path)
        return descriptor


encode_query = lambda query, registry: QueryEncoder(query, registry).encode()


class ValueDecoder(object):
    def __init__(self, registry, values):
        self.registry = registry
        self.values = values
        self.resolve_node = None

    def ref(self, ref, path):
        ref = _require(ref, dict, path)
        kind = ref.get("kind")
        if kind == "node":
            return self.resolve_node(ref, path)
        if kind == "none":
            return None
        if kind == "value":
            return self.value(ref.get("id"), path)
        raise QueryDescriptionError("%s: invalid value reference %r" % (
            path, kind))

    def value(self, index, path):
        if not isinstance(index, int) or isinstance(index, bool):
            raise QueryDescriptionError("%s: invalid value id" % path)
        try:
            descriptor = self.values[index]
        except IndexError:
            raise QueryDescriptionError("%s: unknown value id %s" % (
                path, index))
        return self.decode(descriptor, _path(path, "v%s" % index))

    def compound_item(self, descriptor, path):
        descriptor = _require(descriptor, dict, path)
        kind = descriptor.get("kind")
        if kind == "node":
            node_id = descriptor.get("id")
            if not isinstance(node_id, int) or isinstance(node_id, bool):
                raise QueryDescriptionError("%s: invalid node id" % path)
            return self.resolve_node({"kind": "node_ref", "id": node_id},
                                     path)
        if kind == "value":
            return self.value(descriptor.get("id"), path)
        raise QueryDescriptionError("%s: invalid compound item" % path)

    def decode(self, descriptor, path):
        descriptor = _require(descriptor, dict, path)
        kind = descriptor.get("type")
        if kind == "null":
            return None
        if kind == "bool":
            return _require(descriptor.get("value"), bool, _path(path, "value"))
        if kind == "int":
            value = descriptor.get("value")
            if not isinstance(value, int) or isinstance(value, bool):
                raise QueryDescriptionError("%s: expected int" % path)
            return value
        if kind == "float":
            return _require(descriptor.get("value"), float,
                            _path(path, "value"))
        if kind == "str":
            return _require(descriptor.get("value"), str,
                            _path(path, "value"))
        if kind == "bytes":
            text = _require(descriptor.get("value"), str,
                            _path(path, "value"))
            try:
                return bytes.fromhex(text)
            except ValueError:
                raise QueryDescriptionError("%s: invalid bytes value" % path)
        if kind == "decimal":
            return decimal.Decimal(_require(descriptor.get("value"), str,
                                           _path(path, "value")))
        if kind == "uuid":
            return uuid.UUID(_require(descriptor.get("value"), str,
                                      _path(path, "value")))
        if kind == "datetime":
            return datetime.datetime.fromisoformat(
                _require(descriptor.get("value"), str, _path(path, "value")))
        if kind == "date":
            return datetime.date.fromisoformat(
                _require(descriptor.get("value"), str, _path(path, "value")))
        if kind == "time":
            return datetime.time.fromisoformat(
                _require(descriptor.get("value"), str, _path(path, "value")))
        if kind == "range":
            for part in ("start", "stop", "step"):
                if part not in descriptor:
                    raise QueryDescriptionError(
                        "%s: missing %s" % (path, part))
            return range(
                self.decode(descriptor["start"], _path(path, "start")),
                self.decode(descriptor["stop"], _path(path, "stop")),
                self.decode(descriptor["step"], _path(path, "step")))
        if kind == "model":
            if "pk" not in descriptor:
                raise QueryDescriptionError("%s: missing pk" % path)
            model = self.registry.resolve_model(_identifier(
                descriptor.get("model"), _path(path, "model")))
            pk_name = model._meta.primary_key.name
            instance = model(__no_default__=True)
            setattr(instance, pk_name,
                    self.decode(descriptor["pk"], _path(path, "pk")))
            return instance
        if kind == "dict":
            result = {}
            for index, item in enumerate(descriptor.get("items", ())):
                item = _require(item, dict, _path(path, index))
                if "key" not in item:
                    raise QueryDescriptionError(
                        "%s.items.%s: missing key" % (path, index))
                if "value" not in item:
                    raise QueryDescriptionError(
                        "%s.items.%s: missing value" % (path, index))
                key = _require(item.get("key"), str,
                               _path(path, "items.%s.key" % index))
                result[key] = self.decode(
                    item.get("value"), _path(path, key))
            return result
        if kind in ("list", "tuple", "set", "frozenset", "generator"):
            items = []
            for index, item in enumerate(descriptor.get("items", ())):
                item_path = _path(path, index)
                if (isinstance(item, dict)
                        and item.get("kind") in ("node", "value")):
                    items.append(self.compound_item(item, item_path))
                else:
                    items.append(self.decode(item, item_path))
            if kind != "list":
                return tuple(items)
            return items
        raise QueryDescriptionError("%s: unsupported value type %r" % (
            path, kind))

    def converter(self, descriptor, path):
        if descriptor is None:
            return None
        if descriptor is False:
            return False
        descriptor = _require(descriptor, dict, path)
        if descriptor.get("type") != "field":
            raise QueryDescriptionError("%s: unsupported converter" % path)
        model_id = _identifier(descriptor.get("model"),
                               _path(path, "model"))
        field_id = _identifier(descriptor.get("field"),
                               _path(path, "field"))
        return self.registry.resolve_field(model_id, field_id).db_value


class QueryDecoder(object):
    def __init__(self, description, registry):
        self.description = description
        self.registry = registry
        self.raw_nodes = {}
        self.objects = {}
        self.value_decoder = ValueDecoder(
            registry, _require(description.get("values"), list, "values"))
        self.value_decoder.resolve_node = self.resolve_ref

    def decode(self):
        if self.description.get("format") != FORMAT:
            raise QueryDescriptionError("unsupported query description format")
        if self.description.get("version") != VERSION:
            raise QueryDescriptionError("unsupported query description version")
        nodes = _require(self.description.get("nodes"), list, "nodes")
        for index, descriptor in enumerate(nodes):
            descriptor = _require(descriptor, dict, "nodes.%s" % index)
            node_id = descriptor.get("id")
            if not isinstance(node_id, int) or isinstance(node_id, bool):
                raise QueryDescriptionError("nodes.%s: invalid id" % index)
            if node_id in self.raw_nodes:
                raise QueryDescriptionError("nodes.%s: duplicate id" % index)
            self.raw_nodes[node_id] = descriptor
            self.objects[node_id] = self.skeleton(
                descriptor, "nodes.%s" % node_id)
        for node_id in sorted(self.raw_nodes):
            self.populate(node_id, self.raw_nodes[node_id],
                          "nodes.%s" % node_id)
        root = self.resolve_ref(_require(self.description.get("root"), dict,
                                         "root"), "root")
        if not isinstance(root, SelectBase):
            raise QueryDescriptionError("root: expected a select query")
        return root

    def model(self, identifier, path):
        return self.registry.resolve_model(
            _identifier(identifier, _path(path, "model")))

    def model_ref(self, descriptor, path, key="model"):
        if "model_ref" in descriptor:
            return self.resolve_ref(descriptor["model_ref"],
                                    _path(path, "model_ref"))
        return self.model(descriptor.get(key), path)

    def field(self, descriptor, path):
        descriptor = _require(descriptor, dict, path)
        if descriptor.get("kind") != "field":
            raise QueryDescriptionError("%s: invalid field descriptor" % path)
        field = self.registry.resolve_field(
            descriptor.get("model"),
            _identifier(descriptor.get("field"), _path(path, "field")))
        return field

    def resolve_ref(self, ref, path):
        ref = _require(ref, dict, path)
        kind = ref.get("kind")
        if kind == "model_ref":
            return self.model(ref.get("model"), path)
        if kind == "node_ref":
            node_id = ref.get("id")
            if not isinstance(node_id, int) or isinstance(node_id, bool):
                raise QueryDescriptionError("%s: invalid node id" % path)
            if node_id not in self.objects:
                raise QueryDescriptionError("%s: unknown node id %s" % (
                    path, node_id))
            return self.objects[node_id]
        raise QueryDescriptionError("%s: invalid reference %r" % (path, kind))

    def refs(self, refs, path):
        return [self.resolve_ref(_require(ref, dict, _path(path, index)),
                                 _path(path, index))
                for index, ref in enumerate(refs or ())]

    def ref(self, descriptor, key, path):
        if key not in descriptor:
            return None
        ref = descriptor[key]
        ref_path = _path(path, key)
        ref = _require(ref, dict, ref_path)
        kind = ref.get("kind")
        if kind == "node_ref" or kind == "model_ref":
            return self.resolve_ref(ref, ref_path)
        return self.value_decoder.ref(descriptor[key], ref_path)

    def required_ref(self, descriptor, key, path):
        if key not in descriptor:
            raise QueryDescriptionError("%s: missing %s" % (path, key))
        return self.ref(descriptor, key, path)

    def skeleton(self, d, path):
        kind = d.get("kind")
        if kind in ("select", "model_select"):
            obj = (ModelSelect.__new__(ModelSelect) if kind == "model_select"
                   else Select.__new__(Select))
        elif kind in ("compound", "model_compound"):
            obj = (ModelCompoundSelectQuery.__new__(ModelCompoundSelectQuery)
                   if kind == "model_compound"
                   else CompoundSelectQuery.__new__(CompoundSelectQuery))
        elif kind == "cte":
            obj = CTE.__new__(CTE)
        elif kind == "join":
            obj = Join.__new__(Join)
        elif kind == "values_list":
            obj = ValuesList.__new__(ValuesList)
        elif kind == "model_alias":
            return ModelAlias(self.model(d.get("model"), path), d.get("alias"))
        elif kind == "field":
            return self.field(d, path)
        elif kind == "field_alias":
            source = self.required_ref(d, "source", path)
            field = self.registry.resolve_field(
                d.get("model"),
                _identifier(d.get("field"), _path(path, "field")))
            return FieldAlias.create(source, field)
        elif kind == "column":
            return Column(None, None)
        elif kind == "star":
            return Star(None)
        elif kind == "alias":
            return Alias.__new__(Alias)
        elif kind == "ordering":
            return Ordering.__new__(Ordering)
        elif kind == "negated":
            return Negated.__new__(Negated)
        elif kind == "bitwise_negated":
            return BitwiseNegated.__new__(BitwiseNegated)
        elif kind in ("expression", "string_expression"):
            cls = (StringExpression if kind == "string_expression"
                   else Expression)
            return cls.__new__(cls)
        elif kind == "function":
            return Function.__new__(Function)
        elif kind == "case":
            return Case.__new__(Case)
        elif kind == "value_literals":
            return ValueLiterals.__new__(ValueLiterals)
        elif kind in ("nodelist", "between_list", "distinct_expr"):
            return NodeList.__new__(NodeList)
        elif kind == "value":
            return Value.__new__(Value)
        elif kind == "sql_star":
            return SQL("*")
        else:
            raise QueryDescriptionError("%s: unsupported node kind %r" % (
                path, kind))
        return obj

    def populate_common_query(self, obj, d, path, model=None):
        database = model._meta.database if is_model(model) else None
        obj._database = database
        obj._cursor_wrapper = None
        obj._where = self.ref(d, "where", path)
        obj._order_by = (tuple(self.refs(d["order_by"], _path(path, "order_by")))
                         if "order_by" in d else None)
        obj._limit = self.ref(d, "limit", path)
        obj._offset = self.ref(d, "offset", path)
        obj._cte_list = (tuple(self.refs(d["ctes"], _path(path, "ctes")))
                         if "ctes" in d else None)
        if "row_type" in d:
            row_type = d["row_type"]
            if row_type not in ROW_TYPE_VALUES:
                raise QueryDescriptionError("%s: invalid row type" % path)
            obj._row_type = ROW_TYPE_VALUES[row_type]
        else:
            obj._row_type = None
        if "constructor" in d:
            obj._constructor = self.model(d["constructor"],
                                          _path(path, "constructor"))
        else:
            obj._constructor = None

    def populate(self, node_id, d, path):
        obj = self.objects[node_id]
        kind = d.get("kind")
        if kind in ("field", "field_alias", "model_alias", "sql_star"):
            return
        if kind == "model_select":
            model = self.model_ref(d, path)
            self.populate_common_query(obj, d, path, model)
            self.populate_select_parts(obj, d, path)
            obj.model = model
            obj._is_default = bool(d.get("default"))
            obj._load_tree = None
            obj._join_ctx = self.resolve_ref(d["join_context"],
                                             _path(path, "join_context"))
            obj._joins = {}
            for index, entry in enumerate(d.get("join_graph", ())):
                entry_path = _path(path, "join_graph.%s" % index)
                entry = _require(entry, dict, entry_path)
                source = self.required_ref(entry, "source", entry_path)
                dest = self.required_ref(entry, "dest", entry_path)
                constructor_name = entry.get("constructor")
                if constructor_name == "dict":
                    constructor = dict
                else:
                    constructor = self.model(constructor_name,
                                            _path(entry_path, "constructor"))
                join_name = entry.get("join_type")
                if join_name not in JOIN_VALUES:
                    raise QueryDescriptionError(
                        "%s: invalid join type" % entry_path)
                obj._joins.setdefault(source, []).append((
                    dest,
                    _require(entry.get("attr"), str,
                             _path(entry_path, "attr")),
                    constructor,
                    JOIN_VALUES[join_name]))
            obj._update_hash()
            return
        if kind == "select":
            self.populate_common_query(obj, d, path)
            self.populate_select_parts(obj, d, path)
            obj._update_hash()
            return
        if kind in ("compound", "model_compound"):
            model = None
            if kind == "model_compound":
                model = self.model_ref(d, path)
                obj.model = model
            self.populate_common_query(obj, d, path, model)
            obj.lhs = self.required_ref(d, "lhs", path)
            obj.rhs = self.required_ref(d, "rhs", path)
            op = d.get("op")
            if op not in ("UNION", "UNION ALL", "INTERSECT", "EXCEPT"):
                raise QueryDescriptionError("%s: invalid compound op" % path)
            obj.op = op
            obj._alias = d.get("alias")
            obj._update_hash()
            return
        if kind == "cte":
            query = self.required_ref(d, "query", path)
            query._cte_list = ()
            columns = []
            for index, column in enumerate(d.get("columns", ())):
                if not isinstance(column, str):
                    raise QueryDescriptionError(
                        "%s.columns.%s: expected string" % (path, index))
                columns.append(Entity(column))
            obj._alias = _require(d.get("name"), str, _path(path, "name"))
            obj._query = query
            obj._recursive = bool(d.get("recursive"))
            obj._materialized = d.get("materialized")
            if obj._materialized is not None and not isinstance(
                    obj._materialized, bool):
                raise QueryDescriptionError("%s: invalid materialized" % path)
            obj._columns = columns
            obj._hash = hash((obj.__class__, obj._alias, id(obj._query)))
            return
        if kind == "join":
            obj.lhs = self.required_ref(d, "lhs", path)
            obj.rhs = self.required_ref(d, "rhs", path)
            join_name = d.get("join_type")
            if join_name not in JOIN_VALUES:
                raise QueryDescriptionError("%s: invalid join type" % path)
            obj.join_type = JOIN_VALUES[join_name]
            obj._on = self.ref(d, "on", path)
            obj._alias = None
            return
        if kind == "values_list":
            rows = []
            for row_index, row in enumerate(d.get("rows", ())):
                row_path = _path(path, "rows.%s" % row_index)
                rows.append(tuple(self.refs(_require(row, list, row_path),
                                           row_path)))
            obj._values = rows
            obj._columns = tuple(d.get("columns", ()))
            obj._alias = d.get("alias")
            obj._update_hash()
            return
        if kind == "column":
            obj.source = self.required_ref(d, "source", path)
            obj.name = _require(d.get("name"), str, _path(path, "name"))
            return
        if kind == "star":
            obj.source = self.required_ref(d, "source", path)
            return
        if kind == "alias":
            obj.node = self.required_ref(d, "node", path)
            obj._alias = _require(d.get("alias"), str,
                                  _path(path, "alias"))
            obj._coerce = getattr(obj.node, "_coerce", True)
            obj._converter = getattr(obj.node, "_converter", None)
            return
        if kind in ("ordering", "negated", "bitwise_negated",
                    "value_literals"):
            obj.node = self.required_ref(d, "node", path)
            obj._coerce = getattr(obj.node, "_coerce", True)
            obj._converter = getattr(obj.node, "_converter", None)
            if kind == "ordering":
                direction = d.get("direction")
                if direction not in ("ASC", "DESC"):
                    raise QueryDescriptionError("%s: invalid direction" % path)
                obj.direction = direction
                collation = d.get("collation")
                if collation is not None and not isinstance(collation, str):
                    raise QueryDescriptionError("%s: invalid collation" % path)
                obj.collation = collation
                nulls = d.get("nulls")
                if nulls is not None and nulls not in ("first", "last"):
                    raise QueryDescriptionError("%s: invalid nulls" % path)
                obj.nulls = nulls
            return
        if kind in ("expression", "string_expression"):
            obj.lhs = self.required_ref(d, "lhs", path)
            obj.rhs = self.required_ref(d, "rhs", path)
            op = d.get("op")
            if op not in OPERATORS:
                raise QueryDescriptionError("%s: invalid operator" % path)
            obj.op = op
            obj.flat = bool(d.get("flat"))
            obj._coerce = True
            return
        if kind == "function":
            name = self.registry.resolve_function(_identifier(
                d.get("name"), _path(path, "name")))
            arguments = []
            for argument in self.refs(d.get("arguments", ()),
                                     _path(path, "arguments")):
                arguments.append(argument)
            obj.name = name
            obj.arguments = tuple(arguments)
            obj._filter = self.ref(d, "filter", path)
            obj._order_by = (tuple(self.refs(d["order_by"],
                                           _path(path, "order_by")))
                             if "order_by" in d else None)
            obj._python_value = None
            obj._coerce = bool(d.get("coerce"))
            return
        if kind == "case":
            obj.predicate = self.ref(d, "predicate", path)
            branches = []
            for index, branch in enumerate(d.get("branches", ())):
                branch_path = _path(path, "branches.%s" % index)
                branch = _require(branch, dict, branch_path)
                branches.append((
                    self.ref(branch, "condition", branch_path),
                    self.required_ref(branch, "result", branch_path)))
            obj.expression_tuples = tuple(branches)
            obj.default = self.ref(d, "default", path)
            return
        if kind == "nodelist":
            obj.nodes = tuple(self.refs(d.get("items", ()),
                                   _path(path, "items")))
            glue = d.get("glue")
            if glue not in (" ", ", "):
                raise QueryDescriptionError("%s: invalid glue" % path)
            obj.glue = glue
            obj.parens = bool(d.get("parens"))
            return
        if kind == "between_list":
            obj.nodes = (self.required_ref(d, "lower", path), SQL("AND"),
                         self.required_ref(d, "upper", path))
            obj.glue = " "
            obj.parens = False
            return
        if kind == "distinct_expr":
            obj.nodes = (SQL("DISTINCT"), self.required_ref(d, "node", path))
            obj.glue = " "
            obj.parens = False
            return
        if kind == "value":
            converter = self.value_decoder.converter(d.get("converter"),
                                                     _path(path, "converter"))
            if bool(d.get("unpack")):
                values = []
                for item in self.refs(d.get("items", ()),
                                      _path(path, "items")):
                    if not _is_graph_node(item):
                        item = Value(item, converter)
                    values.append(item)
                obj.value = tuple(values)
                obj.converter = converter
                obj.multi = True
                obj.values = values
            else:
                obj.value = self.value_decoder.value(
                    d["id"], _path(path, "id"))
                obj.converter = converter
                obj.multi = False
                obj.values = None
            return
        if kind == "sql_star":
            return
        raise QueryDescriptionError("%s: cannot populate node kind %r" % (
            path, kind))

    def populate_select_parts(self, obj, d, path):
        obj._from_list = list(self.refs(d.get("from", ()),
                                  _path(path, "from")))
        obj._returning = tuple(self.refs(d.get("projection", ()),
                                        _path(path, "projection")))
        obj._group_by = (list(self.refs(d["group_by"],
                                       _path(path, "group_by")))
                         if "group_by" in d else None)
        obj._having = self.ref(d, "having", path)
        if "distinct" in d:
            obj._distinct = tuple(self.refs(d["distinct"],
                                           _path(path, "distinct")))
            obj._simple_distinct = False
        else:
            obj._distinct = None
            value = d.get("simple_distinct")
            if value is not None and not isinstance(value, bool):
                raise QueryDescriptionError(
                    "%s: simple_distinct must be boolean or null" % path)
            obj._simple_distinct = value
        obj._windows = None
        obj._for_update = None
        obj._lateral = bool(d.get("lateral"))
        obj._alias = d.get("alias")


def decode_query(description, registry):
    return QueryDecoder(description, registry).decode()
