# This file is a part of Dramatiq.
#
# Copyright (C) 2017,2018 CLEARTYPE SRL <bogdan@cleartype.io>
#
# Dramatiq is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# Dramatiq is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations

import copy
import time
from threading import Lock

from ..backend import (
    STATUS_COMPENSATED,
    STATUS_COMPENSATING,
    STATUS_COMPENSATION_FAILED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_RUNNING,
    CompensationStateBackend,
)


class StubBackend(CompensationStateBackend):
    """A local, in-memory compensation state backend.  For use in unit
    tests and single-process deployments.
    """

    def __init__(self):
        self.mutex = Lock()
        self.states = {}

    def create_run(self, run_id, *, steps, ttl):
        with self.mutex:
            if self._get(run_id) is not None:
                return False

            self._put(run_id, {
                "run_id": run_id,
                "status": STATUS_RUNNING,
                "step_count": len(steps),
                "steps": copy.deepcopy(steps),
                "completed": 0,
                "results": {},
                "failed_step": None,
                "comp_position": None,
                "error": None,
            }, ttl)
            return True

    def get_run(self, run_id):
        with self.mutex:
            state = self._get(run_id)
            if state is None:
                return None
            return copy.deepcopy(state)

    def advance_forward(self, run_id, *, step, result, ttl):
        with self.mutex:
            state = self._get(run_id)
            if state is None or state["status"] != STATUS_RUNNING or state["completed"] != step:
                return False

            state["results"][step] = result
            state["completed"] += 1
            if state["completed"] == state["step_count"]:
                state["status"] = STATUS_COMPLETED
            self._put(run_id, state, ttl)
            return True

    def begin_compensation(self, run_id, *, failed_step, error, ttl):
        with self.mutex:
            state = self._get(run_id)
            if state is None or state["status"] != STATUS_RUNNING or state["completed"] != failed_step:
                return False

            state["failed_step"] = failed_step
            state["error"] = error
            state["comp_position"] = self._next_compensatable(state, failed_step)
            if state["comp_position"] is None:
                state["status"] = STATUS_FAILED
            else:
                state["status"] = STATUS_COMPENSATING
            self._put(run_id, state, ttl)
            return True

    def advance_compensation(self, run_id, *, step, ttl):
        with self.mutex:
            state = self._get(run_id)
            if state is None or state["status"] != STATUS_COMPENSATING or state["comp_position"] != step:
                return False

            state["comp_position"] = self._next_compensatable(state, step)
            if state["comp_position"] is None:
                state["status"] = STATUS_COMPENSATED
            self._put(run_id, state, ttl)
            return True

    def fail_compensation(self, run_id, *, step, error, ttl):
        with self.mutex:
            state = self._get(run_id)
            if state is None or state["status"] != STATUS_COMPENSATING or state["comp_position"] != step:
                return False

            state["status"] = STATUS_COMPENSATION_FAILED
            state["error"] = error
            self._put(run_id, state, ttl)
            return True

    def resume_compensation(self, run_id, *, ttl):
        with self.mutex:
            state = self._get(run_id)
            if state is None or state["status"] != STATUS_COMPENSATION_FAILED:
                return False

            state["status"] = STATUS_COMPENSATING
            self._put(run_id, state, ttl)
            return True

    def _next_compensatable(self, state, before_step):
        for step in range(before_step - 1, -1, -1):
            if state["steps"][step]["compensation"] is not None:
                return step
        return None

    def _get(self, run_id):
        state, expiration = self.states.get(run_id, (None, None))
        if state is not None and time.monotonic() < expiration:
            return state
        return None

    def _put(self, run_id, state, ttl):
        self.states[run_id] = (state, time.monotonic() + ttl / 1000)
