import threading

from collections.abc import Mapping

from peewee import *
from peewee import Alias
from peewee import CompoundSelectQuery
from peewee import Column
from peewee import Entity
from peewee import FieldAlias
from peewee import Metadata
from peewee import ROW
from peewee import callable_
from peewee import is_model


_clone_set = lambda s: set(s) if s else set()


def model_to_dict(model, recurse=True, backrefs=False, only=None,
                  exclude=None, seen=None, extra_attrs=None,
                  fields_from_query=None, max_depth=None, manytomany=False):
    """
    Convert a model instance (and any related objects) to a dictionary.

    :param bool recurse: Whether foreign-keys should be recursed.
    :param bool backrefs: Whether lists of related objects should be recursed.
    :param only: A list (or set) of field instances indicating which fields
        should be included.
    :param exclude: A list (or set) of field instances that should be
        excluded from the dictionary.
    :param list extra_attrs: Names of model instance attributes or methods
        that should be included.
    :param SelectQuery fields_from_query: Query that was source of model. Take
        fields explicitly selected by the query and serialize them.
    :param int max_depth: Maximum depth to recurse, value <= 0 means no max.
    :param bool manytomany: Process many-to-many fields.
    """
    max_depth = -1 if max_depth is None else max_depth
    if max_depth == 0:
        recurse = False

    only = _clone_set(only)
    extra_attrs = _clone_set(extra_attrs)
    should_skip = lambda n: (n in exclude) or (only and (n not in only))

    if fields_from_query is not None:
        only.add('__sentinel__')  # Add a placeholder to make non-empty.
        for item in fields_from_query._returning:
            if isinstance(item, Field):
                only.add(item)
            elif isinstance(item, Alias):
                extra_attrs.add(item._alias)

    data = {}
    exclude = _clone_set(exclude)
    seen = _clone_set(seen)
    exclude |= seen
    model_class = type(model)

    if manytomany:
        for name, m2m in model._meta.manytomany.items():
            if should_skip(m2m):
                continue

            exclude.update((m2m, m2m.rel_model._meta.manytomany[m2m.backref]))
            for fkf in m2m.through_model._meta.refs:
                exclude.add(fkf)

            accum = []
            for rel_obj in getattr(model, name):
                accum.append(model_to_dict(
                    rel_obj,
                    recurse=recurse,
                    backrefs=backrefs,
                    only=only,
                    exclude=exclude,
                    max_depth=max_depth - 1))
            data[name] = accum

    for field in model._meta.sorted_fields:
        if should_skip(field):
            continue

        field_data = model.__data__.get(field.name)
        if isinstance(field, ForeignKeyField) and recurse and field.lazy_load:
            # rel_obj may be None despite a fk value: a cached outer-join miss.
            rel_obj = getattr(model, field.name) \
                if field_data is not None else None
            if rel_obj is not None:
                field_data = model_to_dict(
                    rel_obj,
                    recurse=recurse,
                    backrefs=backrefs,
                    only=only,
                    exclude=exclude,
                    seen=seen | set((field,)),
                    max_depth=max_depth - 1)
            else:
                field_data = None

        data[field.name] = field_data

    if extra_attrs:
        for attr_name in extra_attrs:
            attr = getattr(model, attr_name)
            if callable_(attr):
                data[attr_name] = attr()
            else:
                data[attr_name] = attr

    if backrefs and recurse:
        for foreign_key, rel_model in model._meta.backrefs.items():
            if foreign_key.backref == '+': continue
            descriptor = getattr(model_class, foreign_key.backref)
            if descriptor in exclude or foreign_key in exclude:
                continue
            if only and (descriptor not in only) and (foreign_key not in only):
                continue

            accum = []
            exclude.add(foreign_key)
            related_query = getattr(model, foreign_key.backref)

            for rel_obj in related_query:
                accum.append(model_to_dict(
                    rel_obj,
                    recurse=recurse,
                    backrefs=backrefs,
                    only=only,
                    exclude=exclude,
                    max_depth=max_depth - 1))

            data[foreign_key.backref] = accum

    return data


def update_model_from_dict(instance, data, ignore_unknown=False):
    meta = instance._meta
    backrefs = dict([(fk.backref, fk) for fk in meta.backrefs])

    for key, value in data.items():
        if key in meta.combined:
            field = meta.combined[key]
            is_backref = False
        elif key in backrefs:
            field = backrefs[key]
            is_backref = True
        elif ignore_unknown:
            setattr(instance, key, value)
            continue
        else:
            raise AttributeError('Unrecognized attribute "%s" for model '
                                 'class %s.' % (key, type(instance)))

        is_foreign_key = isinstance(field, ForeignKeyField)

        if not is_backref and is_foreign_key and isinstance(value, dict):
            rel_instance = instance.__rel__.get(field.name)
            if rel_instance is None:
                rel_instance = field.rel_model()
            setattr(
                instance,
                field.name,
                update_model_from_dict(rel_instance, value, ignore_unknown))
        elif is_backref and isinstance(value, (list, tuple)):
            instances = [
                dict_to_model(field.model, row_data, ignore_unknown)
                for row_data in value]
            for rel_instance in instances:
                setattr(rel_instance, field.name, instance)
            setattr(instance, field.backref, instances)
        else:
            setattr(instance, field.name, value)

    return instance


def dict_to_model(model_class, data, ignore_unknown=False):
    return update_model_from_dict(model_class(), data, ignore_unknown)


def insert_where(cls, data, where=None):
    """
    Helper for generating conditional INSERT queries.

    For example, prevent INSERTing a new tweet if the user has tweeted within
    the last hour::

        INSERT INTO "tweet" ("user_id", "content", "timestamp")
        SELECT 234, 'some content', now()
        WHERE NOT EXISTS (
            SELECT 1 FROM "tweet"
            WHERE user_id = 234 AND timestamp > now() - interval '1 hour')

    Using this helper:

        cond = ~fn.EXISTS(Tweet.select().where(
            Tweet.user == user_obj,
            Tweet.timestamp > one_hour_ago))

        iq = insert_where(Tweet, {
            Tweet.user: user_obj,
            Tweet.content: 'some content'}, where=cond)

        res = iq.execute()
    """
    for field, default in cls._meta.defaults.items():
        if field.name in data or field in data: continue
        value = default() if callable_(default) else default
        data[field] = value
    fields, values = zip(*data.items())
    sq = Select(columns=values).where(where)
    return cls.insert_from(sq, fields).as_rowcount()


class ReconnectMixin(object):
    """
    Mixin class that attempts to automatically reconnect to the database under
    certain error conditions.

    For example, MySQL servers will typically close connections that are idle
    for 28800 seconds ("wait_timeout" setting). If your application makes use
    of long-lived connections, you may find your connections are closed after
    a period of no activity. This mixin will attempt to reconnect automatically
    when these errors occur.

    This mixin class probably should not be used with Postgres (unless you
    REALLY know what you are doing) and definitely has no business being used
    with Sqlite. If you wish to use with Postgres, you will need to adapt the
    `reconnect_errors` attribute to something appropriate for Postgres.
    """
    reconnect_errors = (
        # Error class, error message fragment (or empty string for all).
        (OperationalError, '2006'),  # MySQL server has gone away.
        (OperationalError, '2013'),  # Lost connection to MySQL server.
        (OperationalError, '2014'),  # Commands out of sync.
        (OperationalError, '4031'),  # Client interaction timeout.
        (InterfaceError, "(0, '')"),  # Dead connection reused (pymysql).

        # mysql-connector raises a slightly different error when an idle
        # connection is terminated by the server. This is equivalent to 2013.
        (OperationalError, 'MySQL Connection not available.'),

        # Postgres error examples:
        #(OperationalError, 'server closed the connection'),  # psycopg2.
        #(InterfaceError, 'connection already closed'),  # psycopg2.
        #(OperationalError, 'terminating connection'),  # psycopg3.
        #(OperationalError, 'the connection is closed'),  # psycopg3.
    )

    def __init__(self, *args, **kwargs):
        super(ReconnectMixin, self).__init__(*args, **kwargs)

        # Normalize the reconnect errors to a more efficient data-structure.
        self._reconnect_errors = {}
        for exc_class, err_fragment in self.reconnect_errors:
            self._reconnect_errors.setdefault(exc_class, [])
            self._reconnect_errors[exc_class].append(err_fragment.lower())

    def execute_sql(self, sql, params=None):
        return self._reconnect(super(ReconnectMixin, self).execute_sql,
                               sql, params)

    def begin(self, *args, **kwargs):
        return self._reconnect(super(ReconnectMixin, self).begin,
                               *args, **kwargs)

    def _reconnect(self, func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            # If we are in a transaction, do not reconnect silently as
            # any changes could be lost.
            if self.in_transaction():
                raise exc

            exc_class = type(exc)
            if exc_class not in self._reconnect_errors:
                raise exc

            exc_repr = str(exc).lower()
            for err_fragment in self._reconnect_errors[exc_class]:
                if err_fragment in exc_repr:
                    break
            else:
                raise exc

            if not self.is_closed():
                self.close()
                self.connect()

            return func(*args, **kwargs)


class _MultiModelResult(object):
    def __init__(self, key, label_to_model, field_map, leaves):
        self.key = key
        self.label_to_model = dict(label_to_model)
        self.model_to_label = dict((model, label)
                                   for label, model in self.label_to_model.items())
        self.field_map = field_map or {}
        self.leaves = tuple(leaves)
        self.query = None
        self.layouts = {}

    def prepare(self):
        for model in self.label_to_model.values():
            if not model._meta.get_primary_keys():
                raise ValueError('Model %s must declare a primary key.' %
                                 model.__name__)

        clone = self._clone_with_markers(self.query)
        for leaf in self.leaves:
            self._add_leaf(leaf)
            self._validate_leaf_marker(leaf.query)
        if set(label for _, label in self.layouts) != \
                set(self.label_to_model):
            raise ValueError('Every mapped model must occur in the compound '
                             'query.')
        self._validate_layouts()
        clone._row_type = ROW.MULTIMODEL
        clone._constructor = self
        return clone

    def validate(self, ncols):
        for (marker_index, label), layout in self.layouts.items():
            if marker_index >= ncols:
                raise ValueError('Multi-model type marker %s is outside the '
                                 'result set.' % label)
            for index, _, _ in layout:
                if index >= ncols:
                    raise ValueError('Multi-model column index %s is outside '
                                     'the result set.' % index)

    def row(self, values):
        candidates = []
        for (marker_index, label), layout in self.layouts.items():
            if (marker_index < len(values) and
                    values[marker_index] == label):
                candidates.append((label, layout))
        if not candidates:
            label = None
            for index, _ in enumerate(values):
                if values[index] in self.label_to_model:
                    label = values[index]
                    break
            raise ValueError('Unknown multi-model type marker: %r.' % label)
        labels = set(label for label, _ in candidates)
        if len(labels) > 1:
            raise ValueError('Ambiguous multi-model type marker: %r.' %
                             sorted(labels))

        label = next(iter(labels))
        layout = next(layout for candidate_label, layout in candidates
                      if candidate_label == label)

        model = self.label_to_model[label]
        data = {}
        for index, field, converter in layout:
            value = values[index]
            if value is not None:
                value = converter(value)
            data[field.name] = value

        for primary_key in model._meta.get_primary_keys():
            if data.get(primary_key.name) is None:
                raise ValueError(
                    'Primary key %s is missing or NULL for %s.' %
                    (primary_key.name, model.__name__))

        instance = model(__no_default__=1, **data)
        instance._dirty.clear()
        return instance

    def _clone_with_markers(self, query):
        if isinstance(query, CompoundSelectQuery):
            clone = query.clone()
            clone.lhs = self._clone_with_markers(query.lhs)
            clone.rhs = self._clone_with_markers(query.rhs)
            return clone

        clone = query.clone()
        label = self._leaf_label(query.model)
        marker_index = self._marker_index(query)
        if marker_index is None:
            clone._returning = tuple(clone._returning) + (
                Value(label).alias(self.key),)
            marker_index = len(query._returning)
        return clone

    def _add_leaf(self, leaf):
        label = self._leaf_label(leaf.model)
        marker_index = self._marker_index(leaf.query)
        if marker_index is None:
            marker_index = len(leaf.query._returning)

        mapping = self._resolve_leaf_mapping(leaf.model, label,
                                             leaf.query._returning,
                                             marker_index)
        layout_key = (marker_index, label)
        existing_layout = self.layouts.get(layout_key)
        layout = self.layouts.setdefault(layout_key, [])
        by_target = dict((field.name, (index, field))
                         for index, field, _ in layout)
        for index, field, converter in mapping:
            existing = by_target.get(field.name)
            if existing is not None and existing[0] != index:
                raise ValueError(
                    'Duplicate field mapping for %s.%s.' %
                    (label, field.name))
            by_target[field.name] = (index, field)
            if existing is None:
                layout.append((index, field, converter))
        if existing_layout is not None and \
                [(i, f.name) for i, f, _ in existing_layout] != \
                [(i, f.name) for i, f, _ in layout]:
            raise ValueError('Branches with marker %r must use the same field '
                             'mapping.' % label)

        primary_keys = leaf.model._meta.get_primary_keys()
        missing = [field.name for field in primary_keys
                   if field.name not in by_target]
        if missing:
            raise ValueError(
                'Primary key %s is missing from the field mapping for %s.' %
                (', '.join(missing), label))

    def _resolve_leaf_mapping(self, model, label, selection, marker_index):
        config = self._config_for(model, label)
        if isinstance(config, (list, tuple)):
            return self._positional_mapping(model, label, config,
                                            marker_index)

        resolved = {}
        for index, raw_node in enumerate(selection):
            if index == marker_index:
                continue
            field = _selected_model_field(raw_node, model)
            if field is not None:
                resolved[index] = field

        for selector, target in (config or {}).items():
            index = self._selection_index(selection, marker_index,
                                          selector, target)
            if target is None:
                resolved.pop(index, None)
                continue
            field = _resolve_target_field(model, target)
            existing = resolved.get(index)
            if existing is not None and existing is not field:
                raise ValueError('Duplicate field mapping for column %s.' %
                                 index)
            for existing_index, existing_field in list(resolved.items()):
                if (existing_field.name == field.name and
                        existing_index != index):
                    raise ValueError(
                        'Duplicate field mapping for %s.%s.' %
                        (label, field.name))
            resolved[index] = field

        return self._finalize_mapping(model, label, resolved,
                                     len(selection))

    def _positional_mapping(self, model, label, config, marker_index):
        resolved = {}
        for index, target in enumerate(config):
            if target is None:
                continue
            if index == marker_index:
                raise ValueError(
                    'Field mapping for %s cannot map the type marker.' % label)
            resolved[index] = _resolve_target_field(model, target)
        return self._finalize_mapping(model, label, resolved, len(config))

    def _finalize_mapping(self, model, label, resolved, ncols):
        result = []
        seen = set()
        for index in sorted(resolved):
            if index >= ncols:
                raise ValueError('Multi-model column index %s is outside '
                                 'the result set.' % index)
            field = resolved[index]
            if field.name in seen:
                raise ValueError('Duplicate field mapping for %s.%s.' %
                                 (label, field.name))
            seen.add(field.name)
            result.append((index, field, field.python_value))
        return tuple(result)

    def _selection_index(self, selection, marker_index, selector, target):
        if isinstance(selector, Field):
            for index, raw_node in enumerate(selection):
                field = _selected_model_field(raw_node, selector.model)
                if field is not None and field is selector:
                    return index
            raise ValueError('Field %s is not selected in branch %r.' %
                             (selector.name, self.model_to_label.get(target)))

        name = selector
        for index, raw_node in enumerate(selection):
            if index == marker_index:
                continue
            if _selection_name(raw_node) == name:
                return index
        raise ValueError('Column %r is not selected in branch %r.' %
                         (name, self.model_to_label.get(target)))

    def _config_for(self, model, label):
        if model in self.field_map:
            return self.field_map[model]
        return self.field_map.get(label, {})

    def _leaf_label(self, model):
        if model in self.model_to_label:
            return self.model_to_label[model]
        label = model._meta.table_name
        if label not in self.label_to_model:
            raise ValueError('Model %s is not present in the type mapping.' %
                             model.__name__)
        if self.label_to_model[label] is not model:
            raise ValueError('Duplicate model marker %r.' % label)
        self.model_to_label[model] = label
        return label

    def _marker_index(self, query):
        matches = [index for index, node in enumerate(query._returning)
                   if node.is_alias() and getattr(node, '_alias', None) ==
                   self.key]
        if len(matches) > 1:
            raise ValueError('Duplicate type marker %s in a query branch.' %
                             self.key)
        return matches[0] if matches else None

    def _validate_leaf_marker(self, query):
        index = self._marker_index(query)
        if index is None:
            return
        node = query._returning[index].unwrap()
        label = getattr(node, 'value', None)
        if isinstance(node, Value) and label not in self.label_to_model:
            raise ValueError('Unknown multi-model type marker: %r.' % label)

    def _validate_layouts(self):
        for (marker_index, label), layout in self.layouts.items():
            positions = {}
            for index, field, _ in layout:
                if index == marker_index:
                    raise ValueError(
                        'Field mapping for %s cannot map the type marker.' %
                        label)
                if field.name in positions:
                    raise ValueError('Duplicate field mapping for %s.%s.' %
                                     (label, field.name))
                positions[field.name] = index


def _selected_model_field(raw_node, model):
    node = raw_node.unwrap()
    if not isinstance(node, Field):
        return None
    field = node.field if isinstance(node, FieldAlias) else node
    if field.model is model:
        return field
    return None


def _selection_name(raw_node):
    node = raw_node.unwrap()
    if raw_node.is_alias():
        return raw_node._alias
    if isinstance(node, Field):
        field = node.field if isinstance(node, FieldAlias) else node
        return field.name
    if isinstance(node, Entity) and node._path:
        return node._path[-1]
    if isinstance(node, Column):
        return node.name
    return None


def _resolve_target_field(model, target):
    if isinstance(target, Field):
        field = target.field if isinstance(target, FieldAlias) else target
        if field.model is not model:
            raise ValueError('Field %s does not belong to %s.' %
                             (field.name, model.__name__))
        return field
    try:
        return model._meta.combined[target]
    except KeyError:
        raise ValueError('Unknown field %r for model %s.' %
                         (target, model.__name__))


def _collect_model_leaves(query):
    if isinstance(query, CompoundSelectQuery):
        return (_collect_model_leaves(query.lhs) +
                _collect_model_leaves(query.rhs))
    if not hasattr(query, 'model') or not is_model(query.model):
        raise ValueError('resolve_multimodel_query() requires model selects.')
    return (_MultiModelLeaf(query, query.model),)


class _MultiModelLeaf(object):
    __slots__ = ('query', 'model')

    def __init__(self, query, model):
        self.query = query
        self.model = model


def resolve_multimodel_query(query, key='_model_identifier', models=None,
                             field_map=None):
    if not isinstance(query, CompoundSelectQuery):
        raise ValueError('resolve_multimodel_query() requires a compound '
                         'select query.')
    nodes = [query]
    while nodes:
        node = nodes.pop()
        if isinstance(node, CompoundSelectQuery):
            if node.op not in ('UNION', 'UNION ALL'):
                raise ValueError(
                    'resolve_multimodel_query() requires a UNION or '
                    'UNION ALL query.')
            nodes.extend((node.lhs, node.rhs))

    leaves = _collect_model_leaves(query)
    if models is None:
        label_to_model = {}
        for leaf in leaves:
            label = leaf.model._meta.table_name
            if label in label_to_model and \
                    label_to_model[label] is not leaf.model:
                raise ValueError('Duplicate type marker %r.' % label)
            label_to_model[label] = leaf.model
    elif isinstance(models, Mapping):
        label_to_model = dict(models)
    else:
        label_to_model = {}
        for model in models:
            label = model._meta.table_name
            if label in label_to_model:
                raise ValueError('Duplicate type marker %r.' % label)
            label_to_model[label] = model

    for label, model in label_to_model.items():
        if not is_model(model):
            raise ValueError('Type marker %r must map to a model.' % label)
    if len(set(label_to_model.values())) != len(label_to_model):
        raise ValueError('A model cannot be mapped to multiple type markers.')

    result = _MultiModelResult(key, label_to_model, field_map, leaves)
    result.query = query
    return result.prepare()


class ThreadSafeDatabaseMetadata(Metadata):
    """
    Metadata class to allow swapping database at run-time in a multi-threaded
    application. To use:

    class Base(Model):
        class Meta:
            model_metadata_class = ThreadSafeDatabaseMetadata
    """
    def __init__(self, *args, **kwargs):
        # The database attribute is stored in a thread-local.
        self._database = None
        self._table = None
        self._lock = threading.Lock()
        self._local = threading.local()
        super(ThreadSafeDatabaseMetadata, self).__init__(*args, **kwargs)

    def _get_db(self):
        return getattr(self._local, 'database', self._database)
    def _set_db(self, db):
        if self._database is None:
            self._database = db
        self._local.database = db
    database = property(_get_db, _set_db)

    def set_database(self, database):
        with self._lock:
            return super(ThreadSafeDatabaseMetadata,
                         self).set_database(database)

    @property
    def table(self):
        if getattr(self._local, 'table', None) is None:
            self._local.table = super(ThreadSafeDatabaseMetadata, self).table
        return self._local.table
    @table.setter
    def table(self, value):
        raise AttributeError('Cannot set the "table".')
    @table.deleter
    def table(self):
        self._local.table = None
