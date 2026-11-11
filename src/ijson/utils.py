# -*- coding:utf-8 -*-
from functools import wraps


def coroutine(func):
    '''
    Wraps a generator which is intended to be used as a pure coroutine by
    .send()ing it values. The only thing that the wrapper does is calling
    .next() for the first time which is required by Python generator protocol.
    '''
    @wraps(func)
    def wrapper(*args, **kwargs):
        g = func(*args, **kwargs)
        next(g)
        return g
    return wrapper


def chain(sink, *coro_pipeline):
    '''
    Chains together a sink and a number of coroutines to form a coroutine
    pipeline. The pipeline works by calling send() on the coroutine created with
    the information in `coro_pipeline[-1]`, which sends its results to the
    coroutine created from `coro_pipeline[-2]`, and so on, until the final
    result is sent to `sink`.
    '''
    f = sink
    for coro_func, coro_args, coro_kwargs in coro_pipeline:
        f = coro_func(f, *coro_args, **coro_kwargs)
    return f


class sendable_list(list):
    '''
    A list that mimics a coroutine receiving values.

    Coroutine are sent values via their send() method. This class defines such a
    method so that values sent into it are appended into the list, which can be
    inspected later. As such, this type can be used as an "accumulating sink" in
    a pipeline consisting on many coroutines.
    '''
    send = list.append


def _event_name(item):
    return item[0] if len(item) == 2 else item[1]


def _update_depth(depth, item):
    event = _event_name(item)
    if event in ('start_map', 'start_array'):
        return depth + 1
    if event in ('end_map', 'end_array'):
        return depth - 1
    return depth


def complete_events_prefix(events, initial_depth=0):
    '''Return the prefix of events that contains only complete values.'''
    events = list(events)
    depth = initial_depth
    safe_end = 0
    for index, item in enumerate(events):
        event = _event_name(item)
        if event in ('start_map', 'start_array'):
            depth += 1
        elif event in ('end_map', 'end_array'):
            depth -= 1
        elif depth <= initial_depth:
            safe_end = index + 1
    return events[:safe_end]


def coros2gen(source, *coro_pipeline, trim_budget_events=True):
    '''
    A utility function that returns a generator yielding values dispatched by a
    coroutine pipeline after *it* has received values coming from `source`.
    '''
    events = sendable_list()
    f = chain(events, *coro_pipeline)
    yielded_depth = 0
    try:
        for value in source:
            try:
                f.send(value)
            except Exception as ex:
                from ijson.common import ParseBudgetExceeded
                complete_events = (
                    complete_events_prefix(events, yielded_depth)
                    if (isinstance(ex, ParseBudgetExceeded) and
                        trim_budget_events) else events
                )
                for event in complete_events:
                    yield event
                if isinstance(ex, StopIteration):
                    return
                raise
            for event in events:
                yield event
                if trim_budget_events:
                    yielded_depth = _update_depth(yielded_depth, event)
            del events[:]
    except GeneratorExit:
        try:
            f.close()
        except:
            pass
        close = getattr(source, 'close', None)
        if close is not None:
            try:
                close()
            except:
                pass
        raise
