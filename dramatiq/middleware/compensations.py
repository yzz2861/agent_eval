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

from ..logging import get_logger
from .middleware import Middleware

#: The default amount of time in milliseconds compensation run state
#: is kept around for.
DEFAULT_COMPENSATION_TTL = 86400000


class Compensations(Middleware):
    """Middleware that runs compensating pipelines.

    Each step of a compensating_pipeline may declare a compensation
    actor.  When a step fails permanently (that is, only after its
    regular retries have been exhausted), the compensations of the
    steps that already succeeded are enqueued in reverse order, each
    receiving the result of the step it undoes.  Compensation
    messages may themselves be retried like any other message; if a
    compensation fails permanently, the run is marked
    'compensation_failed' and its position is preserved in the state
    backend so that it can be resumed later with the resume method.

    Progress is tracked in a CompensationStateBackend whose atomic
    transitions make the machinery safe against duplicate message
    deliveries.

    Note:
      This middleware must run its post-process hook after the
      Retries middleware so that it can tell permanently-failed
      messages apart from messages that are about to be retried.
      Add it before the Retries middleware:

          broker.add_middleware(Compensations(state_backend=backend), before=Retries)

    Parameters:
      state_backend(CompensationStateBackend): The backend used to
        track run state.
      ttl(int): The max amount of time in milliseconds run state is
        kept around for.  Defaults to 1 day.
    """

    def __init__(self, *, state_backend, ttl=DEFAULT_COMPENSATION_TTL):
        self.logger = get_logger(__name__, type(self))
        self.state_backend = state_backend
        self.ttl = ttl

    @property
    def actor_options(self):
        return {
            "comp_run_id",
            "comp_step",
            "comp_mode",
            "comp_next",
        }

    def after_process_message(self, broker, message, *, result=None, exception=None):
        # Since Compensations may be a default middleware, this import
        # has to happen at runtime in order to avoid a cyclic
        # dependency from broker -> compensations -> message -> broker.
        from ..message import Message

        run_id = message.options.get("comp_run_id")
        if run_id is None:
            return

        step = message.options["comp_step"]
        mode = message.options.get("comp_mode", "forward")

        if exception is None:
            if mode == "compensation":
                if not self.state_backend.advance_compensation(run_id, step=step, ttl=self.ttl):
                    # Duplicate delivery: this compensation was already
                    # recorded.  Don't advance the run a second time.
                    return
                self._enqueue_next_compensation(broker, run_id)
            else:
                if not self.state_backend.advance_forward(run_id, step=step, result=result, ttl=self.ttl):
                    # Duplicate delivery: this step was already
                    # recorded.  Don't enqueue the next step again.
                    return
                next_data = message.options.get("comp_next")
                if next_data is not None:
                    next_message = Message(**next_data)
                    if not next_message.options.get("pipe_ignore"):
                        next_message = next_message.copy(args=next_message.args + (result,))
                    broker.enqueue(next_message, delay=next_message.options.get("delay"))
        elif message.failed:
            # The message's retries have been exhausted (see the
            # Retries middleware, which runs its post-process hook
            # before this one).  Anything else means the message is
            # about to be retried, in which case it's too early to
            # start compensating.
            error = "%s: %s" % (type(exception).__name__, exception)
            if mode == "compensation":
                self.logger.warning("Compensation of step %d in run %s failed permanently.", step, run_id)
                self.state_backend.fail_compensation(run_id, step=step, error=error, ttl=self.ttl)
            else:
                self.logger.warning("Step %d in run %s failed permanently. Compensating.", step, run_id)
                if not self.state_backend.begin_compensation(run_id, failed_step=step, error=error, ttl=self.ttl):
                    return
                self._enqueue_next_compensation(broker, run_id)

    def resume(self, broker, run_id):
        """Resume a run whose compensation failed permanently.

        Re-enqueues the compensation for the step the run is
        currently positioned at.  Runs in any other state are left
        alone.

        Parameters:
          broker(Broker): The broker to enqueue the compensation on.
          run_id(str): The id of the run to resume.

        Returns:
          bool: True if the run was resumed.
        """
        if not self.state_backend.resume_compensation(run_id, ttl=self.ttl):
            return False

        self._enqueue_next_compensation(broker, run_id)
        return True

    def _enqueue_next_compensation(self, broker, run_id):
        from ..message import Message

        state = self.state_backend.get_run(run_id)
        if state is None or state["status"] != "compensating":
            return

        position = state["comp_position"]
        if position is None:
            return

        compensation_data = state["steps"][position]["compensation"]
        compensation_message = Message(**compensation_data)
        compensation_message = compensation_message.copy(
            args=compensation_message.args + (state["results"].get(position),),
            options={
                "comp_run_id": run_id,
                "comp_step": position,
                "comp_mode": "compensation",
            },
        )
        broker.enqueue(compensation_message, delay=compensation_message.options.get("delay"))
