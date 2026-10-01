# Copyright 2017 Elisey Zanko
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import typing

from tornado import gen

from tenacity import (
    BaseRetrying,
    CircuitBreakerPermit,
    DoAttempt,
    DoSleep,
    RetryCallState,
)
from tenacity._utils import override
from tenacity.circuit import _is_cancellation

if typing.TYPE_CHECKING:
    from tornado.concurrent import Future

_RetValT = typing.TypeVar("_RetValT")


class TornadoRetrying(BaseRetrying):
    sleep: typing.Callable[..., "Future[None]"]

    def __init__(
        self,
        sleep: "typing.Callable[[float], Future[None]]" = gen.sleep,
        **kwargs: typing.Any,
    ) -> None:
        super().__init__(**kwargs)
        self.sleep = sleep

    @gen.coroutine
    @override
    def __call__(  # type: ignore[override]
        self,
        fn: "typing.Callable[..., typing.Generator[typing.Any, typing.Any, _RetValT] | Future[_RetValT]]",
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> "typing.Generator[typing.Any, typing.Any, _RetValT]":
        permit: CircuitBreakerPermit | None = None
        if self.circuit_breaker is not None:
            permit = self.circuit_breaker.acquire()

        retry_state = RetryCallState(retry_object=self, fn=fn, args=args, kwargs=kwargs)
        try:
            self.begin()
            while True:
                do = self.iter(retry_state=retry_state)
                if isinstance(do, DoAttempt):
                    try:
                        result = yield fn(*args, **kwargs)
                    except BaseException:
                        retry_state.set_exception(sys.exc_info())  # type: ignore[arg-type]
                    else:
                        retry_state.set_result(result)
                elif isinstance(do, DoSleep):
                    retry_state.prepare_for_next_attempt()
                    yield self.sleep(do)
                else:
                    if permit is not None and self.retry_error_callback is not None:
                        retry_state.set_result(do)
                        permit.record_retry_state(retry_state, self.failure_predicate)
                    raise gen.Return(do)
        except BaseException as exc:
            if permit is not None:
                if _is_cancellation(exc):
                    permit.record_cancellation()
                elif retry_state.outcome is not None:
                    permit.record_retry_state(retry_state, self.failure_predicate)
                elif not isinstance(exc, Exception):
                    permit.record_cancellation()
                else:
                    retry_state.set_exception(sys.exc_info())  # type: ignore[arg-type]
                    permit.record_retry_state(retry_state, self.failure_predicate)
            raise
