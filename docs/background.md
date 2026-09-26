
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

Each task is registered under a stable identifier together with the
identifiers it depends on. A task runs once all of its dependencies have
succeeded, and independent tasks run concurrently, optionally bounded by
`max_concurrency`. Dependencies must be registered before the tasks that
use them, so duplicate identifiers, unknown dependencies, and cycles are
all rejected with a `ValueError` while the graph is being built, before
the response is sent.

Signature: `BackgroundTaskGraph(max_concurrency=None)`

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.background import BackgroundTaskGraph
from starlette.routing import Route

async def export_report(request):
    graph = BackgroundTaskGraph(max_concurrency=4)
    graph.add_task("upload", upload_export, path="report.csv")
    graph.add_task("write-index", write_index, depends_on=["upload"])
    graph.add_task("notify", send_notification, depends_on=["upload"])
    message = {"status": "Export scheduled"}
    return JSONResponse(message, background=graph)

async def upload_export(path):
    ...

def write_index():
    ...

def send_notification():
    ...

routes = [
    Route('/report/export', endpoint=export_report, methods=['POST'])
]

app = Starlette(routes=routes)
```

If a task raises an exception, the tasks that depend on it are skipped
with the `TaskStatus.SKIPPED` status, while unrelated branches still run
to completion. Once the graph has been awaited, the outcome of every task
is available through the `results` property, which maps each task
identifier to a `BackgroundTaskResult` holding a `status` (one of
`TaskStatus.SUCCESS`, `TaskStatus.FAILED`, or `TaskStatus.SKIPPED`) and,
for failed tasks, the original `exception`.

```python
from starlette.background import TaskStatus

results = graph.results
assert results["upload"].status is TaskStatus.FAILED
assert isinstance(results["upload"].exception, OSError)
assert results["write-index"].status is TaskStatus.SKIPPED
```
