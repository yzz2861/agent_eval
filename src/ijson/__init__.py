'''
Iterative JSON parser.

Main API:

- ``ijson.parse``: iterator returning parsing events with the object tree context,
  see ``ijson.common.parse`` for docs.

- ``ijson.items``: iterator returning Python objects found under a specified prefix,
  see ``ijson.common.items`` for docs.

Top-level ``ijson`` module exposes method from the pure Python backend. There's
also two other backends using the C library yajl in ``ijson.backends`` that have
the same API and are faster under CPython.
'''
from ijson.adapters import from_iter
from ijson.common import JSONError, IncompleteJSONError, ObjectBuilder

from ijson.utils import coroutine, sendable_list
from .version import __version__


ALL_BACKENDS = ('yajl2_c', 'yajl2_cffi', 'yajl2', 'yajl', 'python')
"""
All supported backends, in descending order or speed. Not all might be available at
runtime.
"""

def get_backend(backend):
    """Import the backend named ``backend``"""
    import importlib
    return importlib.import_module('ijson.backends.' + backend)

def _default_backend():
    import os
    if 'IJSON_BACKEND' in os.environ:
        return get_backend(os.environ['IJSON_BACKEND'])
    for backend in ALL_BACKENDS:
        try:
            return get_backend(backend)
        except ImportError:
            continue
    raise ImportError('no backends available')
backend = _default_backend()
del _default_backend

basic_parse = backend.basic_parse
basic_parse_coro = backend.basic_parse_coro
parse = backend.parse
parse_coro = backend.parse_coro
items = backend.items
items_coro = backend.items_coro
kvitems = backend.kvitems
kvitems_coro = backend.kvitems_coro
basic_parse_async = backend.basic_parse_async
parse_async = backend.parse_async
items_async = backend.items_async
kvitems_async = backend.kvitems_async
backend_name = backend.backend_name
backend = backend.backend

from ijson.multivalue import (
    AsyncMultiValueStream,
    MultiValueBatch,
    MultiValueStream,
    consume_multi_values,
    consume_multi_values_async,
    items_multi,
    items_multi_async,
    items_stream,
    multi_value_items,
    multi_value_items_async,
    multi_value_parse,
    multi_value_stream,
    multi_value_stream_async,
    multi_values,
    parse_multi,
    stream_values,
)


# Keep the traditional functions as the default, but allow callers to request
# the explicit stream mode through the function they already use.
_single_value_basic_parse = basic_parse
_single_value_parse = parse
_single_value_items = items


def _stream_requested(config):
    requested = any(config.pop(name, False) for name in (
        'multi_value_stream', 'stream_mode', 'batches', 'with_cursor',
    ))
    if any(name in config for name in ('callback', 'on_batch', 'on_value')):
        requested = True
    if config.get('multiple_values') == 'stream':
        config.pop('multiple_values')
        requested = True
    if requested:
        config.pop('multiple_values', None)
    return requested


def basic_parse(source, *args, **config):
    if _stream_requested(config):
        return multi_value_stream(source, *args, **config)
    return _single_value_basic_parse(source, *args, **config)


def parse(source, *args, **config):
    if _stream_requested(config):
        return multi_value_stream(source, *args, **config)
    return _single_value_parse(source, *args, **config)


def items(source, *args, **config):
    if _stream_requested(config):
        return multi_value_items(source, *args, **config)
    return _single_value_items(source, *args, **config)


_single_value_basic_parse_async = basic_parse_async
_single_value_parse_async = parse_async
_single_value_items_async = items_async


def basic_parse_async(source, *args, **config):
    if _stream_requested(config):
        return multi_value_stream_async(source, *args, **config)
    return _single_value_basic_parse_async(source, *args, **config)


def parse_async(source, *args, **config):
    if _stream_requested(config):
        return multi_value_stream_async(source, *args, **config)
    return _single_value_parse_async(source, *args, **config)


def items_async(source, *args, **config):
    if _stream_requested(config):
        return multi_value_items_async(source, *args, **config)
    return _single_value_items_async(source, *args, **config)
