'''
Common ctypes routines for yajl library handling
'''

from ctypes import Structure, c_uint, c_char, c_ubyte, c_int, c_long, c_longlong, c_double,\
                   c_void_p, c_char_p, CFUNCTYPE, POINTER, string_at, cast

from ijson import common, backends, numbers


C_EMPTY = CFUNCTYPE(c_int, c_void_p)
C_INT = CFUNCTYPE(c_int, c_void_p, c_int)
C_LONG = CFUNCTYPE(c_int, c_void_p, c_long)
C_LONGLONG = CFUNCTYPE(c_int, c_void_p, c_longlong)
C_DOUBLE = CFUNCTYPE(c_int, c_void_p, c_double)
C_STR = CFUNCTYPE(c_int, c_void_p, POINTER(c_ubyte), c_uint)
_all_cfunct_types = (C_EMPTY, C_INT, C_LONG, C_LONGLONG, C_DOUBLE, C_STR)


def _get_callback_data(yajl_version):
    return  [
        # Mapping of JSON parser events to callback C types and value converters.
        # Used to define the Callbacks structure and actual callback functions
        # inside the parse function.
        ('null', 'null', C_EMPTY, lambda: None),
        ('boolean', 'boolean', C_INT, lambda v: bool(v)),
        ('integer', 'number', C_LONG if yajl_version == 1 else C_LONGLONG, lambda v: int(v)),
        ('double', 'number', C_DOUBLE, lambda v: v),
        ('number', 'number', C_STR, None),
        ('string', 'string', C_STR, lambda v, l: string_at(v, l).decode('utf-8')),
        ('start_map', 'start_map', C_EMPTY, lambda: None),
        ('map_key', 'map_key', C_STR, lambda v, l: string_at(v, l).decode('utf-8')),
        ('end_map', 'end_map', C_EMPTY, lambda: None),
        ('start_array', 'start_array', C_EMPTY, lambda: None),
        ('end_array', 'end_array', C_EMPTY, lambda: None),
    ]


YAJL_OK = 0
YAJL_CANCELLED = 1
YAJL_INSUFFICIENT_DATA = 2
YAJL_ERROR = 3


def get_yajl(version):
    yajl = backends.find_yajl_ctypes(version)
    yajl.yajl_alloc.restype = POINTER(c_char)
    yajl.yajl_get_error.restype = POINTER(c_char)
    return yajl

class PendingException:
    '''
    Holds an exception raised inside a callback. ctypes would otherwise print
    it and carry on, so the callback stores it here and cancels the parse,
    and the parsing loop re-raises it once control is back in Python.
    '''
    def __init__(self):
        self.exception = None

    def raise_if_set(self):
        exception, self.exception = self.exception, None
        if exception is not None:
            raise exception

    def raise_annotated(self, state):
        exception, self.exception = self.exception, None
        if isinstance(exception, numbers.NumberLimitError):
            if exception.offset is None:
                exception.offset = state.bytes_consumed
            exception.set_path(exception.path)
        raise exception


class NumberParseState:
    '''Holds the per-parse configuration shared with the C callbacks.'''

    def __init__(self, use_float, number_limits):
        self.use_float = use_float
        self.number_limits = number_limits
        self.bytes_consumed = 0

def _make_callback(send, state, pending, field, event, func_type, func):
    # All numbers go through the string-based ``number`` callback so the
    # original token is converted (and validated) by the shared Python code.
    # Relying on yajl's own integer/double callbacks would produce slightly
    # different rounding than the pure Python backend and would bypass the
    # configured number limits.
    if field in ('integer', 'double'):
        return func_type()
    def c_callback(_context, *args):
        try:
            if field == 'number':
                token = string_at(args[0], args[1]).decode("utf-8")
                value = numbers.convert_number(token, use_float=state.use_float,
                                                 limits=state.number_limits)
            else:
                value = func(*args)
            send((event, value))
        except BaseException as e:
            pending.exception = e
            return 0
        return 1
    return func_type(c_callback)

def make_callbaks(send, use_float, yajl_version, number_limits):
    callback_data = _get_callback_data(yajl_version)
    class Callbacks(Structure):
        _fields_ = [(name, type) for name, _, type, _ in callback_data]
    pending = PendingException()
    state = NumberParseState(use_float, number_limits)
    callbacks = Callbacks(*[
        _make_callback(send, state, pending, *data)
        for data in callback_data
    ])
    return callbacks, _all_cfunct_types, pending, state

def yajl_get_error(yajl, handle, buffer):
    perror = yajl.yajl_get_error(handle, 1, buffer, len(buffer))
    error = cast(perror, c_char_p).value
    try:
        error = error.decode('utf-8')
    except UnicodeDecodeError:
        pass
    yajl.yajl_free_error(handle, perror)
    return error
