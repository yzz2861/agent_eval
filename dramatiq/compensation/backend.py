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

#: Statuses a compensating pipeline run can be in.
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_COMPENSATING = "compensating"
STATUS_COMPENSATED = "compensated"
STATUS_FAILED = "failed"
STATUS_COMPENSATION_FAILED = "compensation_failed"


class CompensationStateBackend:
    """ABC for compensating pipeline state backends.

    A state backend tracks the progress of individual
    compensating_pipeline runs.  All of the advance_*, begin_*,
    fail_* and resume_* methods must be atomic: they apply their
    state transition iff the run is in the expected position and
    report whether or not the transition was performed.  This is
    what makes the machinery safe against duplicate message
    deliveries: a redelivered message can never advance a step twice
    nor skip past a compensation that hasn't completed yet.

    Run states are represented as dicts with the following keys:

      run_id(str): The unique id of the run.
      status(str): One of running, completed, compensating,
        compensated, failed or compensation_failed.
      step_count(int): The total number of forward steps.
      steps(list): Static per-step data, including each step's
        optional compensation message.
      completed(int): The number of forward steps that have succeeded.
      results(dict): Maps integer step indices to their results.
      failed_step(int|None): The forward step that failed permanently.
      comp_position(int|None): The next step due to be compensated.
      error(str|None): Details about the last permanent failure.
    """

    def create_run(self, run_id, *, steps, ttl):  # pragma: no cover
        """Atomically create the state for a new run iff it doesn't
        already exist.

        Parameters:
          run_id(str): The unique id of the run.
          steps(list[dict]): Per-step data.  Each entry is a dict with
            a 'compensation' key holding a serialized message or None.
          ttl(int): The max amount of time in milliseconds the state
            can live in the backend for.

        Returns:
          bool: True if the run was created.
        """
        raise NotImplementedError

    def get_run(self, run_id):  # pragma: no cover
        """Get the state of a run.

        Parameters:
          run_id(str): The unique id of the run.

        Returns:
          dict|None: A copy of the run state, or None if the run
            doesn't exist or has expired.
        """
        raise NotImplementedError

    def advance_forward(self, run_id, *, step, result, ttl):  # pragma: no cover
        """Atomically record that a forward step succeeded.

        Only advances if the run is still running forward and 'step'
        is the current position, so duplicate deliveries of the same
        message can't advance the run twice.

        Parameters:
          run_id(str): The unique id of the run.
          step(int): The index of the step that succeeded.
          result(object): The result returned by the step's actor.
          ttl(int): The max amount of time in milliseconds the state
            can live in the backend for.

        Returns:
          bool: True if the state was advanced.
        """
        raise NotImplementedError

    def begin_compensation(self, run_id, *, failed_step, error, ttl):  # pragma: no cover
        """Atomically switch a run into compensating mode after one of
        its forward steps failed permanently.

        Only transitions if the run is still running forward and
        'failed_step' is the current position, so duplicate
        deliveries of the failed message can't trigger the
        compensations twice.  Steps without a compensation are
        skipped when computing the compensation position.  If no
        completed step declares a compensation, the run is marked
        'failed' instead of 'compensating'.

        Parameters:
          run_id(str): The unique id of the run.
          failed_step(int): The index of the step that failed.
          error(str): Details about the failure.
          ttl(int): The max amount of time in milliseconds the state
            can live in the backend for.

        Returns:
          bool: True if this call performed the transition.
        """
        raise NotImplementedError

    def advance_compensation(self, run_id, *, step, ttl):  # pragma: no cover
        """Atomically record that a step's compensation succeeded.

        Only advances if the run is compensating and 'step' is the
        current compensation position, so duplicate deliveries can't
        skip past compensations that haven't completed yet.  When no
        compensatable steps remain, the run is marked 'compensated'.

        Parameters:
          run_id(str): The unique id of the run.
          step(int): The index of the step that was compensated.
          ttl(int): The max amount of time in milliseconds the state
            can live in the backend for.

        Returns:
          bool: True if the state was advanced.
        """
        raise NotImplementedError

    def fail_compensation(self, run_id, *, step, error, ttl):  # pragma: no cover
        """Atomically record that a step's compensation failed
        permanently.

        The run is marked 'compensation_failed' and its position is
        preserved so that it can be resumed later; the run is *not*
        marked as fully rolled back.

        Parameters:
          run_id(str): The unique id of the run.
          step(int): The index of the step whose compensation failed.
          error(str): Details about the failure.
          ttl(int): The max amount of time in milliseconds the state
            can live in the backend for.

        Returns:
          bool: True if this call recorded the failure.
        """
        raise NotImplementedError

    def resume_compensation(self, run_id, *, ttl):  # pragma: no cover
        """Atomically move a run whose compensation failed back into
        compensating mode so that it can be resumed from its recorded
        position.

        Parameters:
          run_id(str): The unique id of the run.
          ttl(int): The max amount of time in milliseconds the state
            can live in the backend for.

        Returns:
          bool: True if the run was resumed.
        """
        raise NotImplementedError
