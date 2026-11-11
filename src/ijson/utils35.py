'''
Python3.5+ specific utilities
'''
import collections

from ijson import utils, common, compat


class utf8reader_async(compat.utf8reader):
    """
    Takes a utf8-encoded string asynchronous reader and asynchronously reads
    bytes out of it
    """
    async def read(self, n):
        data = await self.str_reader.read(n)
        return data.encode('utf-8')

async def _get_read(f):
    """Returns an awaitable read function that reads the requested type"""
    if type(await f.read(0)) == bytes:
        return f.read
    return compat._warn_and_return(utf8reader_async(f).read)

class sendable_deque(collections.deque):
    '''Like utils.sendable_list, but for deque objects'''
    send = collections.deque.append

class async_iterable:
    '''
    A utility class that implements an async iterator returning values
    dispatched by a coroutine pipeline after *it* has received values coming
    from an async file-like object.
    '''

    def __init__(self, f, buf_size, *coro_pipeline, budget=None,
                 trim_budget_events=True):
        self.events = sendable_deque()
        self.coro = utils.chain(self.events, *coro_pipeline)
        self.coro_finished = False
        self.f = f
        self.buf_size = buf_size
        self.budget = budget
        self.read = None
        self.closed = False
        self._exception = None
        self.yielded_depth = 0
        self.trim_budget_events = trim_budget_events

    def _pop_event(self):
        event = self.events.popleft()
        if self.trim_budget_events:
            self.yielded_depth = utils._update_depth(
                self.yielded_depth, event
            )
        return event

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.closed:
            raise StopAsyncIteration
        if not self.read:
            self.read = await _get_read(self.f)
        if self.events:
            return self._pop_event()
        if self._exception is not None:
            exception, self._exception = self._exception, None
            raise exception
        if self.coro_finished:
            raise StopAsyncIteration
        while True:
            try:
                if self.budget is None:
                    read_size = self.buf_size
                else:
                    read_size = self.budget.prepare_read(self.buf_size)
                data = await self.read(read_size)
                if self.budget is not None:
                    self.budget.record_read(data)
                self.coro.send(data)
                if self.events:
                    return self._pop_event()
            except StopIteration:
                self.coro_finished = True
                if self.events:
                    return self._pop_event()
                raise StopAsyncIteration
            except BaseException as exception:
                self.coro_finished = True
                try:
                    self.coro.close()
                except Exception:
                    pass
                if (isinstance(exception, common.ParseBudgetExceeded) and
                        self.trim_budget_events):
                    complete = utils.complete_events_prefix(
                        self.events, self.yielded_depth
                    )
                    self.events.clear()
                    self.events.extend(complete)
                if self.events:
                    self._exception = exception
                    return self._pop_event()
                raise

    async def aclose(self):
        '''Stop the async iterator without reading more from the source.'''
        self.coro_finished = True
        self.closed = True
        self.events.clear()
        self._exception = None
        try:
            self.coro.close()
        except Exception:
            pass

    def close(self):
        '''Synchronous close alias for code that treats all iterators alike.'''
        self.coro_finished = True
        self.closed = True
        self.events.clear()
        self._exception = None
        try:
            self.coro.close()
        except Exception:
            pass


def _make_basic_parse_async(backend):
    def basic_parse_async(f, buf_size=64*1024, budget=None, **config):
        return async_iterable(f, buf_size,
            *common._basic_parse_pipeline(backend, config, budget),
            budget=budget
        )
    return basic_parse_async

def _make_parse_async(backend):
    def parse_async(f, buf_size=64*1024, budget=None, **config):
        return async_iterable(f, buf_size,
            *common._parse_pipeline(backend, config, budget),
            budget=budget
        )
    return parse_async

def _make_items_async(backend):
    def items_async(f, prefix, map_type=None, buf_size=64*1024,
                    budget=None, **config):
        return async_iterable(f, buf_size,
            *common._items_pipeline(backend, prefix, map_type, config, budget),
            budget=budget, trim_budget_events=False
        )
    return items_async

def _make_kvitems_async(backend):
    def kvitems_async(f, prefix, map_type=None, buf_size=64*1024,
                      budget=None, **config):
        return async_iterable(f, buf_size,
            *common._kvitems_pipeline(backend, prefix, map_type, config, budget),
            budget=budget, trim_budget_events=False
        )
    return kvitems_async
