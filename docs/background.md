
Starlette includes a `BackgroundTask` class for in-process background tasks.

A background task should be attached to a response, and will run only once
the response has been sent.

### Background Task

Used to add a single background task to a response.

Signature: `BackgroundTask(func, *args, **kwargs)`

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.background import BackgroundTask


...

async def signup(request):
    data = await request.json()
    username = data['username']
    email = data['email']
    task = BackgroundTask(send_welcome_email, to_address=email)
    message = {'status': 'Signup successful'}
    return JSONResponse(message, background=task)

async def send_welcome_email(to_address):
    ...


routes = [
    Route('/user/signup', endpoint=signup, methods=['POST'])
]

app = Starlette(routes=routes)
```

### BackgroundTasks

Used to add multiple background tasks to a response.

Signature: `BackgroundTasks(tasks=[])`

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.background import BackgroundTasks
from starlette.routing import Route

async def signup(request):
    data = await request.json()
    username = data['username']
    email = data['email']
    tasks = BackgroundTasks()
    tasks.add_task(send_welcome_email, to_address=email)
    tasks.add_task(send_admin_notification, username=username)
    message = {'status': 'Signup successful'}
    return JSONResponse(message, background=tasks)

async def send_welcome_email(to_address):
    ...

async def send_admin_notification(username):
    ...

routes = [
    Route('/user/signup', endpoint=signup, methods=['POST'])
]

app = Starlette(routes=routes)
```

!!! important
    The tasks are executed in order. In case one of the tasks raises
    an exception, the following tasks will not get the opportunity to be executed.

### BackgroundTaskGraph

Used to add multiple background tasks that depend on each other.

Each task is registered under a stable `task_id` and may declare a list of
`dependencies`. A task only runs once all of its dependencies have succeeded,
and independent branches of the graph run concurrently. You can cap the number
of tasks running at the same time with `max_concurrency`.

Signature: `BackgroundTaskGraph(max_concurrency=None)`

```python
from starlette.applications import Starlette
from starlette.background import BackgroundTaskGraph
from starlette.responses import JSONResponse
from starlette.routing import Route

async def export_report(request):
    tasks = BackgroundTaskGraph(max_concurrency=2)
    tasks.add_task('upload', upload_export, request.app.state.storage)
    tasks.add_task('index', write_index, dependencies=['upload'])
    tasks.add_task('notify', send_notification, dependencies=['upload'])
    message = {'status': 'Export started'}
    return JSONResponse(message, background=tasks)

routes = [
    Route('/reports/export', endpoint=export_report, methods=['POST'])
]

app = Starlette(routes=routes)
```

Invalid graphs are rejected eagerly, before the response is sent. Registering
a duplicate `task_id`, depending on an unknown `task_id`, or depending on the
task itself raises a `ValueError` from `add_task`. Since dependencies must be
registered before their dependents, dependency cycles cannot be formed.

If a task raises an exception, its descendants are marked as skipped and do
not run, while unrelated branches still run to completion. Once every
reachable task has settled, a `BackgroundTaskGraphError` is raised that
aggregates the failures. The original exceptions are preserved: the first
failure is chained as `__cause__`, and every failure is available through
the `errors` attribute and the per-task results.

The outcome of every node can be inspected on the graph after it has run.
`graph.results` maps each `task_id` to a `TaskResult` named tuple of
`(task_id, status, error)`, where `status` is one of `TaskStatus.PENDING`,
`TaskStatus.SUCCEEDED`, `TaskStatus.FAILED` or `TaskStatus.SKIPPED`.
`graph.status(task_id)` is a shortcut for reading a single status.

```python
from starlette.background import BackgroundTaskGraph, BackgroundTaskGraphError, TaskStatus

tasks = BackgroundTaskGraph()
tasks.add_task('upload', upload_export)
tasks.add_task('index', write_index, dependencies=['upload'])

try:
    await tasks()
except BackgroundTaskGraphError as exc:
    exc.errors  # {'upload': RuntimeError('upload failed')}

tasks.status('upload')  # TaskStatus.FAILED
tasks.status('index')   # TaskStatus.SKIPPED
```

Synchronous functions keep running in the threadpool, while asynchronous
functions are awaited directly on the event loop, so async tasks are never
blocked behind synchronous ones.
