'''
CFFI-Wrapper for YAJL C library version 2.x.
'''

from cffi import FFI
import functools

from ijson import common, backends, numbers, utils


ffi = FFI()
ffi.cdef("""
typedef void * (*yajl_malloc_func)(void *ctx, size_t sz);
typedef void (*yajl_free_func)(void *ctx, void * ptr);
typedef void * (*yajl_realloc_func)(void *ctx, void * ptr, size_t sz);
typedef struct
{
    yajl_malloc_func malloc;
    yajl_realloc_func realloc;
    yajl_free_func free;
    void * ctx;
} yajl_alloc_funcs;
typedef struct yajl_handle_t * yajl_handle;
typedef enum {
    yajl_status_ok,
    yajl_status_client_canceled,
    yajl_status_error
} yajl_status;
typedef enum {
    yajl_allow_comments = 0x01,
    yajl_dont_validate_strings     = 0x02,
    yajl_allow_trailing_garbage = 0x04,
    yajl_allow_multiple_values = 0x08,
    yajl_allow_partial_values = 0x10
} yajl_option;
typedef struct {
    int (* yajl_null)(void * ctx);
    int (* yajl_boolean)(void * ctx, int boolVal);
    int (* yajl_integer)(void * ctx, long long integerVal);
    int (* yajl_double)(void * ctx, double doubleVal);
    int (* yajl_number)(void * ctx, const char * numberVal,
                        size_t numberLen);
    int (* yajl_string)(void * ctx, const unsigned char * stringVal,
                        size_t stringLen);
    int (* yajl_start_map)(void * ctx);
    int (* yajl_map_key)(void * ctx, const unsigned char * key,
                         size_t stringLen);
    int (* yajl_end_map)(void * ctx);
    int (* yajl_start_array)(void * ctx);
    int (* yajl_end_array)(void * ctx);
} yajl_callbacks;
int yajl_version(void);
yajl_handle yajl_alloc(const yajl_callbacks *callbacks, yajl_alloc_funcs *afs, void *ctx);
int yajl_config(yajl_handle h, yajl_option opt, ...);
yajl_status yajl_parse(yajl_handle hand, const unsigned char *jsonText, size_t jsonTextLength);
yajl_status yajl_complete_parse(yajl_handle hand);
unsigned char* yajl_get_error(yajl_handle hand, int verbose, const unsigned char *jsonText, size_t jsonTextLength);
void yajl_free_error(yajl_handle hand, unsigned char * str);
void yajl_free(yajl_handle handle);
""")


yajl = backends.find_yajl_cffi(ffi, 2)

YAJL_OK = 0
YAJL_CANCELLED = 1
YAJL_INSUFFICIENT_DATA = 2
YAJL_ERROR = 3

# constants defined in yajl_parse.h
YAJL_ALLOW_COMMENTS = 1
YAJL_MULTIPLE_VALUES = 8


def append_event_to_ctx(event):
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(ctx, *args, **kwargs):
            scope = ffi.from_handle(ctx)
            try:
                scope.send((event, func(*args, **kwargs)))
            except BaseException as e:
                # cffi would print the exception and return 0; keep it so
                # yajl_parse can re-raise it after yajl cancels the parse
                scope.exception = e
                return 0
            return 1
        return wrapped
    return wrapper


@ffi.callback('int(void *ctx)')
@append_event_to_ctx('null')
def null():
    return None


@ffi.callback('int(void *ctx, int val)')
@append_event_to_ctx('boolean')
def boolean(val):
    return bool(val)


def _make_number_callback(use_float):
    @ffi.callback('int(void *ctx, const char *numberVal, size_t numberLen)')
    def number(ctx, val, length):
        scope = ffi.from_handle(ctx)
        try:
            token = ffi.string(val, maxlen=length).decode("utf-8")
            value = numbers.convert_number(
                token, use_float=scope.use_float, limits=scope.number_limits
            )
            scope.send(('number', value))
        except BaseException as e:
            scope.exception = e
            return 0
        return 1
    return number


@ffi.callback('int(void *ctx, const unsigned char *stringVal, size_t stringLen)')
@append_event_to_ctx('string')
def string(val, length):
    # yajl gives an explicit length; ffi.string would stop at an embedded NUL
    return ffi.buffer(val, length)[:].decode('utf-8')


@ffi.callback('int(void *ctx)')
@append_event_to_ctx('start_map')
def start_map():
    return None


@ffi.callback('int(void *ctx, const unsigned char *key, size_t stringLen)')
@append_event_to_ctx('map_key')
def map_key(key, length):
    return ffi.buffer(key, length)[:].decode('utf-8')


@ffi.callback('int(void *ctx)')
@append_event_to_ctx('end_map')
def end_map():
    return None


@ffi.callback('int(void *ctx)')
@append_event_to_ctx('start_array')
def start_array():
    return None


@ffi.callback('int(void *ctx)')
@append_event_to_ctx('end_array')
def end_array():
    return None


def yajl_init(scope, send, allow_comments=False, multiple_values=False,
              use_float=False, number_limits=None):
    scope.send = send
    scope.exception = None
    scope.bytes_consumed = 0
    scope.use_float = use_float
    scope.number_limits = numbers.resolve_number_limits(number_limits)
    scope.ctx = ffi.new_handle(scope)
    # The string-based number callback is always used: it keeps conversion
    # (and rounding) identical across backends and applies the number limits
    # before any value is built.  The integer/double callbacks stay NULL.
    number_cb = _make_number_callback(use_float)
    scope._number_cb = number_cb  # keep the callback alive
    callback_data = (
        null, boolean, ffi.NULL, ffi.NULL, number_cb, string,
        start_map, map_key, end_map, start_array, end_array
    )
    scope.callbacks = ffi.new('yajl_callbacks*', callback_data)
    handle = yajl.yajl_alloc(scope.callbacks, ffi.NULL, scope.ctx)

    if allow_comments:
        yajl.yajl_config(handle, YAJL_ALLOW_COMMENTS, ffi.cast('int', 1))
    if multiple_values:
        yajl.yajl_config(handle, YAJL_MULTIPLE_VALUES, ffi.cast('int', 1))

    return handle


def yajl_parse(scope, handle, buffer):
    if buffer:
        result = yajl.yajl_parse(handle, buffer, len(buffer))
    else:
        result = yajl.yajl_complete_parse(handle)
    if result == YAJL_OK and buffer:
        scope.bytes_consumed += len(buffer)

    if result != YAJL_OK:
        if scope.exception is not None:
            exception, scope.exception = scope.exception, None
            if isinstance(exception, numbers.NumberLimitError):
                if exception.offset is None:
                    exception.offset = scope.bytes_consumed
                exception.set_path(exception.path)
            raise exception
        perror = yajl.yajl_get_error(handle, 1, buffer, len(buffer))
        error = ffi.string(perror)
        try:
            error = error.decode('utf8')
        except UnicodeDecodeError:
            pass
        yajl.yajl_free_error(handle, perror)
        exception = common.IncompleteJSONError if result == YAJL_INSUFFICIENT_DATA else common.JSONError
        raise exception(error)


class Container:
    pass


@utils.coroutine
def basic_parse_basecoro(target, **config):
    '''
    Coroutine dispatching unprefixed events.

    Parameters:

    - allow_comments: tells parser to allow comments in JSON input
    - multiple_values: allows the parser to parse multiple JSON objects
    '''

    # the scope objects makes sure the C objects allocated in _yajl.init
    # are kept alive until this function is done
    scope = Container()

    handle = yajl_init(scope, target.send, **config)
    try:
        while True:
            try:
                buffer = (yield)
            except GeneratorExit:
                buffer = b''
            yajl_parse(scope, handle, buffer)
            if not buffer:
                break
    finally:
        yajl.yajl_free(handle)


common.enrich_backend(globals())
