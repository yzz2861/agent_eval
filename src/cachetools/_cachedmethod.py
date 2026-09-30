"""Method decorator helpers."""

__all__ = ()

import functools
import threading
import warnings
import weakref


def _warn_classmethod(stacklevel):
    warnings.warn(
        "decorating class methods with @cachedmethod is deprecated",
        DeprecationWarning,
        stacklevel=stacklevel,
    )


def _warn_instance_dict(msg, stacklevel):
    warnings.warn(
        msg,
        DeprecationWarning,
        stacklevel=stacklevel,
    )


def _none(_):
    return None


_weak_self = object()


class _DescriptorNameBase:
    """Descriptor mixin handling __set_name__."""

    def __init__(self, deprecated=False):
        self._attrname = None
        self._deprecated = deprecated

    def __set_name__(self, owner, name):
        if self._attrname is None:
            self._attrname = name
        elif name != self._attrname:
            raise TypeError(
                "Cannot assign the same @cachedmethod to two different names "
                f"({self._attrname!r} and {name!r})."
            )


class _WeakInstanceKey:
    """Cache key identifying an instance without keeping it alive."""

    __slots__ = ("state", "key")

    def __init__(self, state, key):
        self.state = state
        self.key = key

    def __hash__(self):
        return hash((id(self.state), self.key))

    def __eq__(self, other):
        return (
            type(other) is type(self)
            and other.state is self.state
            and other.key == self.key
        )


class _WeakInstanceState:
    __slots__ = (
        "ref",
        "obj_id",
        "caches",
        "pending",
        "hits",
        "misses",
    )

    def __init__(self, ref, obj_id):
        self.ref = ref
        self.obj_id = obj_id
        self.caches = {}
        self.pending = set()
        self.hits = self.misses = 0

    def remember(self, cache, lock):
        self.caches[id(cache)] = (cache, lock)


class _WeakInstanceRegistry:
    __slots__ = ("cache", "lock", "condition", "states", "guard")

    def __init__(self, cache, lock, condition):
        self.cache = cache
        self.lock = lock
        self.condition = condition
        self.states = {}
        self.guard = threading.RLock()

    def get(self, obj):
        if isinstance(obj, type):
            raise TypeError(
                "@cachedmethod(weak=True) cannot be used with class methods"
            )
        try:
            weakref.ref(obj)
        except TypeError as exc:
            raise TypeError(
                "@cachedmethod(weak=True) requires weak-referenceable "
                f"instances, but {type(obj).__name__!r} does not support "
                "weak references"
            ) from exc

        obj_id = id(obj)
        with self.guard:
            for state in self.states.get(obj_id, ()):
                if state.ref() is obj:
                    return state

            state = _WeakInstanceState(weakref.ref(obj), obj_id)
            state.ref = weakref.ref(
                obj, lambda ref, state=state: self.discard(state, ref)
            )
            self.states.setdefault(obj_id, []).append(state)
            return state

    def discard(self, state, ref):
        with self.guard:
            states = self.states.get(state.obj_id)
            if states is not None:
                try:
                    states.remove(state)
                except ValueError:
                    pass
                if not states:
                    del self.states[state.obj_id]

        for cache, lock in tuple(state.caches.values()):
            self.purge(cache, lock, state)

    @staticmethod
    def purge(cache, lock, state):
        def remove():
            for key in list(cache):
                if type(key) is _WeakInstanceKey and key.state is state:
                    try:
                        del cache[key]
                    except KeyError:
                        pass

        if lock is None:
            remove()
        else:
            with lock:
                remove()


class _WeakDescriptorBase(_DescriptorNameBase):
    def __init__(self, registry):
        super().__init__()
        self.registry = registry

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        return self.Wrapper(self.registry.get(obj))  # type: ignore

    def __call__(self, *args, **kwargs):
        raise TypeError("@cachedmethod(weak=True) cannot be used with class methods")


class _WeakWrapperBase:
    __slots__ = (
        "__dict__",
        "state",
        "_key",
        "_info",
        "_registry",
        "__wrapped__",
    )

    def __init__(self, state, method, key, info, registry):
        self.state = state
        self._key = key
        self._info = info
        self._registry = registry
        functools.update_wrapper(self, method)

    def _instance(self):
        obj = self.state.ref()
        if obj is None:
            raise ReferenceError(
                "weakly referenced instance has been garbage collected"
            )
        return obj

    def _contexts(self, obj):
        cache = self._cache(obj)
        lock = self._lock(obj)
        condition = self._condition(obj)
        self.state.remember(cache, lock if lock is not None else condition)
        return cache, lock, condition

    def _cache(self, obj):
        return self._registry.cache(obj)

    def _lock(self, obj):
        cache_lock = self._registry.lock
        return cache_lock(obj) if cache_lock is not None else None

    def _condition(self, obj):
        condition = self._registry.condition
        return condition(obj) if condition is not None else None

    def _make_key(self, *args, **kwargs):
        return _WeakInstanceKey(self.state, self._key(_weak_self, *args, **kwargs))

    @property
    def cache(self):
        return self._cache(self._instance())

    @property
    def cache_key(self):
        def make_key(*args, **kwargs):
            self._instance()
            return self._make_key(*args, **kwargs)

        return make_key

    @property
    def cache_lock(self):
        return self._lock(self._instance())

    @property
    def cache_condition(self):
        return self._condition(self._instance())

    def cache_clear(self):
        obj = self._instance()
        cache, lock, condition = self._contexts(obj)
        self._registry.purge(cache, lock if lock is not None else condition, self.state)
        self.state.hits = self.state.misses = 0


class _WeakWrapper(_WeakWrapperBase):
    def __call__(self, *args, **kwargs):
        obj = self._instance()
        cache, lock, condition = self._contexts(obj)
        key = self._make_key(*args, **kwargs)

        if condition is not None:
            condition_lock = lock if lock is not None else condition
            with condition_lock:
                condition.wait_for(lambda: key not in self.state.pending)
                try:
                    result = cache[key]
                    self.state.hits += 1
                    return result
                except KeyError:
                    self.state.pending.add(key)
                    self.state.misses += 1
            try:
                value = self.__wrapped__(obj, *args, **kwargs)
                with condition_lock:
                    try:
                        cache[key] = value
                    except ValueError:
                        pass  # value too large
                    self.state.pending.remove(key)
                    condition.notify_all()
                    return value
            except BaseException:
                with condition_lock:
                    self.state.pending.remove(key)
                    condition.notify_all()
                raise

        if lock is not None:
            with lock:
                try:
                    result = cache[key]
                    self.state.hits += 1
                    return result
                except KeyError:
                    self.state.misses += 1
            value = self.__wrapped__(obj, *args, **kwargs)
            with lock:
                try:
                    value = cache.setdefault(key, value)
                except ValueError:
                    pass  # value too large
                return value

        try:
            result = cache[key]
            self.state.hits += 1
            return result
        except KeyError:
            self.state.misses += 1
        value = self.__wrapped__(obj, *args, **kwargs)
        try:
            cache[key] = value
        except ValueError:
            pass  # value too large
        return value

    def cache_info(self):
        if self._info is None:
            raise AttributeError("cache_info")
        obj = self._instance()
        cache, lock, condition = self._contexts(obj)
        context_lock = lock if lock is not None else condition
        if context_lock is not None:
            with context_lock:
                return self._info(cache, self.state.hits, self.state.misses)
        return self._info(cache, self.state.hits, self.state.misses)


def _weak_wrapper(method, cache, key, lock, cond, info):
    registry = _WeakInstanceRegistry(cache, lock, cond)

    class Descriptor(_WeakDescriptorBase):
        class Wrapper(_WeakWrapper):
            def __init__(self, state):
                super().__init__(state, method, key, info, registry)

    descriptor = functools.update_wrapper(Descriptor(registry), method)
    descriptor.cache = cache  # type: ignore
    descriptor.cache_key = key  # type: ignore
    descriptor.cache_lock = lock if lock is not None else cond  # type: ignore
    descriptor.cache_condition = cond  # type: ignore
    if info is None:
        descriptor.cache_info = None  # type: ignore
    return descriptor


class _WrapperBase:
    """Wrapper base class providing default implementations for properties."""

    def __init__(self, obj, method, cache, key, lock=None, cond=None):
        if isinstance(obj, type):
            _warn_classmethod(stacklevel=5)
        functools.update_wrapper(self, method)
        self._obj = obj  # protected
        self.__cache = cache
        self.__key = functools.partial(key, obj)
        self.__lock = lock if lock is not None else _none
        self.__cond = cond if cond is not None else _none

    def __call__(self, *args, **kwargs):
        raise NotImplementedError()  # pragma: no cover

    def cache_clear(self):
        raise NotImplementedError()  # pragma: no cover

    @property
    def cache(self):
        return self.__cache(self._obj)

    @property
    def cache_key(self):
        return self.__key  # self._obj passed via functools.partial

    @property
    def cache_lock(self):
        return self.__lock(self._obj)

    @property
    def cache_condition(self):
        return self.__cond(self._obj)


class _DescriptorBase(_DescriptorNameBase):
    """Descriptor base class implementing the basic descriptor protocol."""

    def __get__(self, obj, objtype=None):
        wrapper = self.Wrapper(obj)  # type: ignore
        if obj is None:
            # Return the wrapper itself without modification when accessed
            # through the class to support class-level introspection, such
            # as for mocking with autospec=True in unittest.mock.
            pass
        elif self._attrname is not None:
            # replace descriptor instance with wrapper in instance dict
            try:
                # In case of a race condition where another thread already replaced
                # the descriptor, prefer the initial wrapper.
                wrapper = obj.__dict__.setdefault(self._attrname, wrapper)
            except AttributeError:
                # not all objects have __dict__ (e.g. class defines slots)
                msg = (
                    f"No '__dict__' attribute on {type(obj).__name__!r} "
                    f"instance to cache {self._attrname!r} property."
                )
                if self._deprecated:
                    _warn_instance_dict(msg, 3)
                else:
                    raise TypeError(msg) from None
            except TypeError:
                msg = (
                    f"The '__dict__' attribute on {type(obj).__name__!r} "
                    f"instance does not support item assignment for "
                    f"caching {self._attrname!r} property."
                )
                if self._deprecated:
                    _warn_instance_dict(msg, 3)
                else:
                    raise TypeError(msg) from None
        elif self._deprecated:
            pass  # deprecated @classmethod, warning already raised elsewhere
        else:
            msg = "Cannot use @cachedmethod instance without calling __set_name__ on it"
            raise TypeError(msg) from None
        return wrapper


class _DeprecatedDescriptorBase(_DescriptorBase):
    """Descriptor base class supporting deprecated @classmethod use."""

    def __init__(self, wrapper, cache_clear):
        super().__init__(deprecated=True)
        self.__wrapper = wrapper
        self.__cache_clear = cache_clear

    # called for @classmethod with Python >= 3.13
    def __call__(self, *args, **kwargs):
        _warn_classmethod(stacklevel=3)
        return self.__wrapper(*args, **kwargs)

    # backward-compatible @classmethod handling with Python >= 3.13
    def cache_clear(self, objtype):
        _warn_classmethod(stacklevel=3)
        return self.__cache_clear(objtype)


# At least for now, the implementation prefers clarity and performance
# over ease of maintenance, thus providing separate descriptors for
# all valid combinations of decorator parameters lock, condition and
# info.


def _condition_info(method, cache, key, lock, cond, info):
    class Descriptor(_DescriptorBase):
        class Wrapper(_WrapperBase):
            def __init__(self, obj):
                super().__init__(obj, method, cache, key, lock, cond)
                self.__hits = self.__misses = 0
                self.__pending = set()

            def __call__(self, *args, **kwargs):
                cache = self.cache
                lock = self.cache_lock
                cond = self.cache_condition
                key = self.cache_key(*args, **kwargs)

                with lock:
                    cond.wait_for(lambda: key not in self.__pending)
                    try:
                        result = cache[key]
                        self.__hits += 1
                        return result
                    except KeyError:
                        self.__pending.add(key)
                        self.__misses += 1
                try:
                    val = method(self._obj, *args, **kwargs)
                    with lock:
                        try:
                            cache[key] = val
                        except ValueError:
                            pass  # value too large
                        return val
                finally:
                    with lock:
                        self.__pending.remove(key)
                        cond.notify_all()

            def cache_clear(self):
                with self.cache_lock:
                    self.cache.clear()
                    self.__hits = self.__misses = 0

            def cache_info(self):
                with self.cache_lock:
                    return info(self.cache, self.__hits, self.__misses)

    return Descriptor()


def _locked_info(method, cache, key, lock, info):
    class Descriptor(_DescriptorBase):
        class Wrapper(_WrapperBase):
            def __init__(self, obj):
                super().__init__(obj, method, cache, key, lock)
                self.__hits = self.__misses = 0

            def __call__(self, *args, **kwargs):
                cache = self.cache
                lock = self.cache_lock
                key = self.cache_key(*args, **kwargs)
                with lock:
                    try:
                        result = cache[key]
                        self.__hits += 1
                        return result
                    except KeyError:
                        self.__misses += 1
                val = method(self._obj, *args, **kwargs)
                with lock:
                    try:
                        # In case of a race condition, i.e. if another thread
                        # stored a value for this key while we were calling
                        # method(), prefer the cached value.
                        return cache.setdefault(key, val)
                    except ValueError:
                        return val  # value too large

            def cache_clear(self):
                with self.cache_lock:
                    self.cache.clear()
                    self.__hits = self.__misses = 0

            def cache_info(self):
                with self.cache_lock:
                    return info(self.cache, self.__hits, self.__misses)

    return Descriptor()


def _unlocked_info(method, cache, key, info):
    class Descriptor(_DescriptorBase):
        class Wrapper(_WrapperBase):
            def __init__(self, obj):
                super().__init__(obj, method, cache, key)
                self.__hits = self.__misses = 0

            def __call__(self, *args, **kwargs):
                cache = self.cache
                key = self.cache_key(*args, **kwargs)
                try:
                    result = cache[key]
                    self.__hits += 1
                    return result
                except KeyError:
                    self.__misses += 1
                val = method(self._obj, *args, **kwargs)
                try:
                    cache[key] = val
                except ValueError:
                    pass  # value too large
                return val

            def cache_clear(self):
                self.cache.clear()
                self.__hits = self.__misses = 0

            def cache_info(self):
                return info(self.cache, self.__hits, self.__misses)

    return Descriptor()


def _condition(method, cache, key, lock, cond):
    # backward-compatible weakref dictionary for Python >= 3.13
    pending = weakref.WeakKeyDictionary()

    def wrapper(self, pending, *args, **kwargs):
        c = cache(self)
        k = key(self, *args, **kwargs)
        with lock(self):
            cond(self).wait_for(lambda: k not in pending)
            try:
                return c[k]
            except KeyError:
                pending.add(k)
        try:
            v = method(self, *args, **kwargs)
            with lock(self):
                try:
                    c[k] = v
                except ValueError:
                    pass  # value too large
                return v
        finally:
            with lock(self):
                pending.remove(k)
                cond(self).notify_all()

    def cache_clear(self):
        c = cache(self)
        with lock(self):
            c.clear()

    def classmethod_wrapper(self, *args, **kwargs):
        p = pending.setdefault(self, set())
        return wrapper(self, p, *args, **kwargs)

    class Descriptor(_DeprecatedDescriptorBase):
        class Wrapper(_WrapperBase):
            def __init__(self, obj):
                super().__init__(obj, method, cache, key, lock, cond)
                self.__pending = set()

            def __call__(self, *args, **kwargs):
                return wrapper(self._obj, self.__pending, *args, **kwargs)

            # objtype: backward-compatible @classmethod handling with Python < 3.13
            def cache_clear(self, _objtype=None):
                return cache_clear(self._obj)

    return Descriptor(classmethod_wrapper, cache_clear)


def _locked(method, cache, key, lock):
    def wrapper(self, *args, **kwargs):
        c = cache(self)
        k = key(self, *args, **kwargs)
        with lock(self):
            try:
                return c[k]
            except KeyError:
                pass  # key not found
        v = method(self, *args, **kwargs)
        with lock(self):
            try:
                # In case of a race condition, i.e. if another thread
                # stored a value for this key while we were calling
                # method(), prefer the cached value.
                return c.setdefault(k, v)
            except ValueError:
                return v  # value too large

    def cache_clear(self):
        c = cache(self)
        with lock(self):
            c.clear()

    class Descriptor(_DeprecatedDescriptorBase):
        class Wrapper(_WrapperBase):
            def __init__(self, obj):
                super().__init__(obj, method, cache, key, lock)

            def __call__(self, *args, **kwargs):
                return wrapper(self._obj, *args, **kwargs)

            # objtype: backward-compatible @classmethod handling with Python < 3.13
            def cache_clear(self, _objtype=None):
                return cache_clear(self._obj)

    return Descriptor(wrapper, cache_clear)


def _unlocked(method, cache, key):
    def wrapper(self, *args, **kwargs):
        c = cache(self)
        k = key(self, *args, **kwargs)
        try:
            return c[k]
        except KeyError:
            pass  # key not found
        v = method(self, *args, **kwargs)
        try:
            c[k] = v
        except ValueError:
            pass  # value too large
        return v

    def cache_clear(self):
        c = cache(self)
        c.clear()

    class Descriptor(_DeprecatedDescriptorBase):
        class Wrapper(_WrapperBase):
            def __init__(self, obj):
                super().__init__(obj, method, cache, key)

            def __call__(self, *args, **kwargs):
                return wrapper(self._obj, *args, **kwargs)

            # objtype: backward-compatible @classmethod handling with Python < 3.13
            def cache_clear(self, _objtype=None):
                return cache_clear(self._obj)

    return Descriptor(wrapper, cache_clear)


def _wrapper(method, cache, key, lock=None, cond=None, info=None, weak=False):
    if weak:
        return _weak_wrapper(method, cache, key, lock, cond, info)

    if info is not None:
        if cond is not None and lock is not None:
            wrapper = _condition_info(method, cache, key, lock, cond, info)
        elif cond is not None:
            wrapper = _condition_info(method, cache, key, cond, cond, info)
        elif lock is not None:
            wrapper = _locked_info(method, cache, key, lock, info)
        else:
            wrapper = _unlocked_info(method, cache, key, info)
    else:
        if cond is not None and lock is not None:
            wrapper = _condition(method, cache, key, lock, cond)
        elif cond is not None:
            wrapper = _condition(method, cache, key, cond, cond)
        elif lock is not None:
            wrapper = _locked(method, cache, key, lock)
        else:
            wrapper = _unlocked(method, cache, key)

    # backward-compatible properties for deprecated @classmethod use
    wrapper.cache = cache  # type: ignore
    wrapper.cache_key = key  # type: ignore
    wrapper.cache_lock = lock if lock is not None else cond  # type: ignore
    wrapper.cache_condition = cond  # type: ignore

    # functools.update_wrapper() will not accept descriptor (decorator) as wrapper
    # https://github.com/python/typeshed/issues/9846
    return functools.update_wrapper(wrapper, method)  # type: ignore
