import ctypes
import json
import os
import threading

_C = ctypes
_c_ubyte = _C.c_ubyte
_c_void_p = _C.c_void_p
_c_size_t = _C.c_size_t
_c_uint64 = _C.c_uint64
_c_uint32 = _C.c_uint32
_c_ulonglong = _C.c_ulonglong
_c_ulong = _C.c_ulong
_c_int = _C.c_int

_HERE = os.path.dirname(os.path.abspath(__file__))
_CANDIDATES = [
    os.path.join(_HERE, "..", "..", "build", "pynacl_sodium_shim.dylib"),
    os.path.join(_HERE, "..", "..", "build", "pynacl_sodium_shim.so"),
    os.path.join(_HERE, "pynacl_sodium_shim.dylib"),
    os.path.join(_HERE, "pynacl_sodium_shim.so"),
]

_lib = None
_load_error = None
for _path in _CANDIDATES:
    _ap = os.path.abspath(_path)
    if os.path.exists(_ap):
        try:
            _lib = _C.CDLL(_ap)
            break
        except OSError as exc:
            _load_error = exc
if _lib is None:
    for _name in ("libsodium.dylib", "libsodium.so"):
        try:
            _lib = _C.CDLL(_name)
            break
        except OSError as exc:
            _load_error = exc
if _lib is None:
    raise OSError(
        "could not locate a libsodium shared library"
    ) from _load_error


class _Buffer:
    def __init__(self, address, size):
        self._address = int(address)
        self._size = int(size)

    def __len__(self):
        return self._size

    def _bytes(self):
        if self._size <= 0:
            return b""
        return _C.string_at(self._address, self._size)

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            start, stop, step = idx.indices(self._size)
            if step != 1 or start >= stop:
                return self._bytes()[idx]
            return _C.string_at(self._address + start, stop - start)
        if idx < 0:
            idx += self._size
        return _c_ubyte.from_address(self._address + idx).value

    def __setitem__(self, idx, value):
        if isinstance(idx, slice):
            start, stop, _step = idx.indices(self._size)
            data = bytes(value)
            _C.memmove(self._address + start, data, len(data))
            return
        if idx < 0:
            idx += self._size
        _c_ubyte.from_address(self._address + idx).value = value

    def __bytes__(self):
        return self._bytes()

    def __eq__(self, other):
        if isinstance(other, (_Buffer, bytes, bytearray, memoryview)):
            return self._bytes() == bytes(other)
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash(self._bytes())

    def __repr__(self):
        return "ffi.buffer(size=%d)" % self._size


class _Ptr:
    def __init__(self, cobj):
        self._obj = cobj

    @property
    def value(self):
        return self._obj.value

    @value.setter
    def value(self, val):
        self._obj.value = val

    def __int__(self):
        return int(self._obj.value or 0)

    def __index__(self):
        return int(self._obj.value or 0)

    def __getitem__(self, idx):
        return self._obj[idx]

    def __setitem__(self, idx, value):
        self._obj[idx] = value

    def __bool__(self):
        return bool(self._obj)


class _FFILoader:
    NULL = None

    def __init__(self):
        self._once = threading.Lock()
        self._done = set()

    def init_once(self, func, tag):
        with self._once:
            if tag in self._done:
                return
            func()
            self._done.add(tag)

    @staticmethod
    def _array_type(type_str):
        t = type_str.replace("const", " ")
        t = " ".join(t.split())
        t = t.replace(chr(42), " ").replace("[", " ").replace("]", " ")
        t = " ".join(t.split())
        if t in ("unsigned char", "uint8_t", "char", "void"):
            return _c_ubyte
        if t == "size_t":
            return _c_size_t
        if t in ("unsigned long long", "uint64_t"):
            return _c_ulonglong
        if t == "unsigned long":
            return _c_ulong
        if t in ("uint32_t", "unsigned int"):
            return _c_uint32
        if t == "int":
            return _c_int
        return _c_ubyte

    def new(self, type_str, init=None):
        spec = " ".join(type_str.split())
        is_pointer = spec.endswith(chr(42))
        if is_pointer:
            base = self._array_type(spec)
            backing = (base * 1)()
            ptr = _C.cast(backing, _C.POINTER(base))
            ptr._pynacl_backing = backing
            if init is not None:
                if base is _c_ubyte:
                    backing[0] = int(init)
                else:
                    backing[0] = init
            return _Ptr(ptr)
        base = self._array_type(spec)
        if init is None:
            init = 0
        return (base * int(init))()

    @staticmethod
    def buffer(cobj, size=None):
        if isinstance(cobj, _Ptr):
            target = cobj._obj
            if not target:
                raise ValueError("cannot build a buffer around NULL")
            address = _C.cast(target, _c_void_p).value
            if size is None:
                raise ValueError("size required for pointer buffers")
            return _Buffer(address, size)
        if isinstance(cobj, _C.Array):
            address = _C.addressof(cobj)
            if size is None:
                size = _C.sizeof(cobj)
            return _Buffer(address, size)
        if isinstance(cobj, (bytes, bytearray, memoryview)):
            mv = memoryview(cobj)
            arr = (_c_ubyte * len(mv)).from_buffer(mv)
            address = _C.addressof(arr)
            if size is None:
                size = len(mv)
            return _Buffer(address, size)
        raise TypeError("unsupported buffer object: %r" % type(cobj))

    def cast(self, type_str, cobj):
        if isinstance(cobj, _Ptr):
            cobj = cobj._obj
        if cobj is None:
            return _Ptr(_c_void_p(None))
        if isinstance(cobj, int):
            return _Ptr(_c_void_p(cobj))
        try:
            address = _C.cast(cobj, _c_void_p).value
        except _C.ArgumentError:
            address = int(cobj)
        return _Ptr(_c_void_p(address))

    @staticmethod
    def string(cobj, maxlen=-1):
        if isinstance(cobj, _Ptr):
            target = cobj._obj
            if not target:
                raise ValueError("cannot read a NULL C string")
            address = _C.cast(target, _c_void_p).value
        elif isinstance(cobj, int):
            address = cobj
        elif isinstance(cobj, _C.Array):
            address = _C.addressof(cobj)
        else:
            address = _C.cast(cobj, _c_void_p).value
        if maxlen is None or maxlen < 0:
            return _C.string_at(address)
        return _C.string_at(address, maxlen)

    @staticmethod
    def memmove(dst, src, n):
        def _addr(obj):
            if isinstance(obj, _Ptr):
                return _C.cast(obj._obj, _c_void_p).value
            if isinstance(obj, _C.Array):
                return _C.addressof(obj)
            if isinstance(obj, int):
                return obj
            return obj

        d = _addr(dst)
        if isinstance(src, (bytes, bytearray, memoryview)):
            data = bytes(src)[:n]
            _C.memmove(d, data, len(data))
        else:
            _C.memmove(d, _addr(src), n)


ffi = _FFILoader()

_KIND_TO_CTYPE = {
    "i": _c_int,
    "sz": _c_size_t,
    "ull": _c_ulonglong,
    "ul": _c_ulong,
    "u32": _c_uint32,
    "u64": _c_uint64,
    "P": _c_void_p,
    "v": None,
}



class _Func:
    def __init__(self, raw, ret_kind, arg_kinds):
        self._raw = raw
        self._arg_kinds = arg_kinds
        argtypes = []
        for kind in arg_kinds:
            if kind == "P":
                argtypes.append(_C.c_char_p)
            else:
                argtypes.append(_KIND_TO_CTYPE[kind])
        raw.argtypes = argtypes
        if ret_kind == "v":
            raw.restype = None
        elif ret_kind == "P":
            raw.restype = _c_void_p
        else:
            raw.restype = _KIND_TO_CTYPE[ret_kind]

    def _convert(self, arg, owned):
        if arg is None:
            return None
        if isinstance(arg, _Ptr):
            target = arg._obj
            if hasattr(target, "_pynacl_backing"):
                owned.append(target._pynacl_backing)
            if isinstance(target, _c_void_p):
                address = target.value
                if address is None:
                    return None
                return _C.c_char_p(address)
            return _C.cast(target, _C.c_char_p)
        if isinstance(arg, _C.Array):
            owned.append(arg)
            return _C.cast(arg, _C.c_char_p)
        if isinstance(arg, (bytes, bytearray, memoryview)):
            return bytes(arg)
        return arg

    def __call__(self, *args):
        owned = []
        converted = [self._convert(a, owned) for a in args]
        result = self._raw(*converted)
        del owned
        return result



class _Lib:
    pass


lib = _Lib()

_sig_path = os.path.abspath(
    os.path.join(_HERE, "..", "..", "build", "shim_signatures.json")
)
with open(_sig_path) as _fp:
    _SIGNATURES = json.load(_fp)

for _name, (_ret, _args) in _SIGNATURES.items():
    try:
        _raw = getattr(_lib, _name)
    except AttributeError:
        continue
    setattr(lib, _name, _Func(_raw, _ret, _args))

for _flag in (
    "PYNACL_HAS_CRYPTO_CORE_ED25519",
    "PYNACL_HAS_CRYPTO_PWHASH_SCRYPTSALSA208SHA256",
    "PYNACL_HAS_CRYPTO_SCALARMULT_ED25519",
    "PYNACL_HAS_CRYPTO_SHORTHASH_SIPHASHX24",
):
    setattr(lib, _flag, 1)
