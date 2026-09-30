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

import tenacity
from tenacity import (
    BaseRetrying,
    DoAttempt,
    DoSleep,
    RetryBudgetError,
    RetryCallState,
)
from tenacity._utils import override

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
        self.begin()

        retry_state = RetryCallState(retry_object=self, fn=fn, args=args, kwargs=kwargs)
        while True:
            reservation = retry_state.budget_reservation
            try:
                do = self.iter(retry_state=retry_state)
            except BaseException:
                if reservation is not None:
                    reservation.release()
                raise
            if isinstance(do, DoAttempt):
                budget_lease: tenacity._RetryBudgetAttempt | None = None
                retry_budget = retry_state.budget
                if retry_budget is not None and not retry_state.budget_attempt_started:
                    reservation = retry_state.budget_reservation
                    retry_state.budget_reservation = None
                    try:
                        budget_lease = retry_budget.begin_attempt(
                            retry_state, reservation
                        )
                        retry_state.budget_attempt_started = True
                    except RetryBudgetError as exc:
                        retry_state.stop_reason = exc.reason
                        if reservation is not None and reservation.active:
                            reservation.release()
                        raise
                    reservation = None
                try:
                    try:
                        result = yield fn(*args, **kwargs)
                    except BaseException:
                        retry_state.set_exception(sys.exc_info())  # type: ignore[arg-type]
                    else:
                        retry_state.set_result(result)
                finally:
                    if budget_lease is not None:
                        retry_budget.end_attempt(budget_lease)
                    retry_state.budget_attempt_started = False
            elif isinstance(do, DoSleep):
                reservation = retry_state.budget_reservation
                retry_state.prepare_for_next_attempt()
                retry_state.budget_attempt_started = False
                try:
                    if retry_state.budget is not None:
                        retry_state.budget.sync_sleep(float(do))
                    else:
                        yield self.sleep(do)
                except BaseException:
                    if reservation is not None:
                        reservation.release()
                    raise
            else:
                raise gen.Return(do)
