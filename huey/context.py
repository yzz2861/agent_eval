import contextvars


class ContextRegistry(object):
    """
    Tracks the :class:~contextvars.ContextVar objects whose values should
    be propagated along with tasks.

    Only variables explicitly registered here are captured. When a task is
    enqueued, the current value of each registered variable is stored on the
    task as a plain {name: value} dict (the "snapshot"), which is
    serialized along with the task message. The worker then executes the task
    (and its pre/post-execute hooks) inside a fresh context containing exactly
    the snapshot values, restoring the worker's own context afterwards.

    Rules for edge-cases:

    * A registered variable that has no value when the snapshot is captured
      is simply absent from the snapshot, and will be unset (i.e. fall back
      to its default or raise LookupError) when the task runs.
    * Snapshot entries whose names are not registered on the worker (e.g.
      deployments with different registered sets) are ignored.
    * Registered variables missing from the snapshot are treated as unset.
    """
    def __init__(self, context_vars=None):
        self._vars = {}
        if context_vars:
            self.register(*context_vars)

    def __bool__(self):
        return bool(self._vars)

    def register(self, *variables):
        for var in variables:
            if not isinstance(var, contextvars.ContextVar):
                raise TypeError('expected a ContextVar, got %r' % (var,))
            self._vars[var.name] = var

    def unregister(self, name):
        if isinstance(name, contextvars.ContextVar):
            name = name.name
        return self._vars.pop(name, None) is not None

    def capture(self):
        """
        Return a {name: value} snapshot of the registered variables that
        are currently set. Unset variables are recorded as absent.
        """
        snapshot = {}
        for name, var in self._vars.items():
            try:
                snapshot[name] = var.get()
            except LookupError:
                pass
        return snapshot

    def restore(self, snapshot):
        """
        Build a fresh :class:~contextvars.Context containing exactly the
        snapshot values for variables registered here. Entries for unknown
        names are ignored.
        """
        ctx = contextvars.Context()
        for name, value in snapshot.items():
            var = self._vars.get(name)
            if var is not None:
                ctx.run(var.set, value)
        return ctx
