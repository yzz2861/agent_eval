from unittest.mock import Mock

import pytest
from graphql import OperationType

from ariadne import ExtensionManager, graphql
from ariadne.types import Extension

context = {}
exception = ValueError()


def test_request_started_hook_is_called_by_extension_manager():
    extension = Mock(spec=Extension)
    manager = ExtensionManager([Mock(return_value=extension)], context)
    with manager.request():
        pass

    extension.request_started.assert_called_once_with(context)


def test_request_finished_hook_is_called_by_extension_manager():
    extension = Mock(spec=Extension)
    manager = ExtensionManager([Mock(return_value=extension)], context)
    with manager.request():
        pass

    extension.request_finished.assert_called_once_with(context)


def test_has_errors_hook_is_called_with_errors_list_and_context():
    extension = Mock(spec=Extension)
    manager = ExtensionManager([Mock(return_value=extension)], context)
    manager.has_errors([exception])
    extension.has_errors.assert_called_once_with([exception], context)


def test_operation_started_hook_is_called_by_extension_manager():
    extension = Mock(spec=Extension)
    manager = ExtensionManager([Mock(return_value=extension)], context)
    manager.operation_started(OperationType.MUTATION)
    extension.operation_started.assert_called_once_with(
        context, OperationType.MUTATION
    )


def test_operation_finished_hook_is_called_by_extension_manager():
    extension = Mock(spec=Extension)
    manager = ExtensionManager([Mock(return_value=extension)], context)
    manager.operation_finished(OperationType.MUTATION, [])
    extension.operation_finished.assert_called_once_with(
        context, OperationType.MUTATION, []
    )


def test_operation_started_hook_raises_for_awaitable_in_sync_executor():
    async def async_hook(*_):
        pass

    extension = Mock(spec=Extension, operation_started=async_hook)
    manager = ExtensionManager([Mock(return_value=extension)], context)
    with pytest.raises(RuntimeError, match="operation_started"):
        manager.operation_started(OperationType.MUTATION)


def test_operation_finished_hook_raises_for_awaitable_in_sync_executor():
    async def async_hook(*_):
        pass

    extension = Mock(spec=Extension, operation_finished=async_hook)
    manager = ExtensionManager([Mock(return_value=extension)], context)
    with pytest.raises(RuntimeError, match="operation_finished"):
        manager.operation_finished(OperationType.MUTATION, [])


@pytest.mark.asyncio
async def test_aoperation_started_hook_awaits_awaitables():
    hook = Mock()

    async def async_hook(*_):
        hook()

    extension = Mock(spec=Extension, operation_started=async_hook)
    manager = ExtensionManager([Mock(return_value=extension)], context)
    await manager.aoperation_started(OperationType.QUERY)
    hook.assert_called_once()


@pytest.mark.asyncio
async def test_aoperation_finished_hook_awaits_awaitables():
    hook = Mock()

    async def async_hook(*_):
        hook()

    extension = Mock(spec=Extension, operation_finished=async_hook)
    manager = ExtensionManager([Mock(return_value=extension)], context)
    await manager.aoperation_finished(OperationType.QUERY, None)
    hook.assert_called_once()


def test_extension_format_hook_is_called_with_context():
    extension = Mock(spec=Extension, format=Mock(return_value={"a": 1}))
    manager = ExtensionManager([Mock(return_value=extension)], context)
    manager.format()
    extension.format.assert_called_once_with(context)


def test_extensions_are_formatted():
    extensions = [
        Mock(spec=Extension, format=Mock(return_value={"a": 1})),
        Mock(spec=Extension, format=Mock(return_value={"b": 2})),
    ]
    manager = ExtensionManager([Mock(return_value=ext) for ext in extensions])
    assert manager.format() == {"a": 1, "b": 2}


class BaseExtension(Extension):
    pass


@pytest.mark.asyncio
async def test_default_extension_hooks_dont_interrupt_query_execution(schema):
    _, response = await graphql(
        schema, {"query": "{ status }"}, extensions=[BaseExtension]
    )
    assert response["data"] == {"status": True}
