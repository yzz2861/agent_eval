"""
Tests for StreamingCSVRenderer, CSVStream and StreamingResponse.
"""
from types import SimpleNamespace

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import path

from rest_framework.renderers import (
    CSVStream, JSONRenderer, StreamingCSVRenderer
)
from rest_framework.response import StreamingResponse
from rest_framework.views import APIView

COLUMNS = [
    ('ID', 'id'),
    ('Name', 'user.name'),
    ('Note', 'note'),
]

ROWS = [
    {'id': 1, 'user': {'name': 'Alice'}, 'note': 'line one\nline two'},
    {'id': 2, 'user': {'name': 'Bob'}, 'note': None},
]


def rows_view(request, columns=None, rows=None):
    columns = COLUMNS if columns is None else columns
    rows = ROWS if rows is None else rows
    return StreamingResponse(CSVStream(columns, iter(rows)))


class UserCSVView(APIView):
    renderer_classes = [StreamingCSVRenderer]

    def get(self, request):
        return rows_view(request)


class InvalidColumnsView(APIView):
    renderer_classes = [StreamingCSVRenderer]

    def get(self, request):
        return rows_view(request, columns=[])


class InvalidDataView(APIView):
    renderer_classes = [StreamingCSVRenderer]

    def get(self, request):
        return StreamingResponse({'not': 'a CSVStream'})


class FailingRowsView(APIView):
    renderer_classes = [StreamingCSVRenderer]

    def get(self, request):
        def rows():
            yield ROWS[0]
            raise RuntimeError('database went away')

        return StreamingResponse(CSVStream(COLUMNS, rows()))


class ClosableRows:
    """An infinite row iterable that records whether it was closed."""

    def __init__(self):
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        return ROWS[0]

    def close(self):
        self.closed = True


closable_rows = []


class ClosableRowsView(APIView):
    renderer_classes = [StreamingCSVRenderer]

    def get(self, request):
        rows = ClosableRows()
        closable_rows.append(rows)
        return StreamingResponse(CSVStream(COLUMNS, rows))


class JSONOnlyView(APIView):
    renderer_classes = [JSONRenderer]

    def get(self, request):
        return StreamingResponse({'a': 1})


urlpatterns = [
    path('users', UserCSVView.as_view()),
    path('invalid-columns', InvalidColumnsView.as_view()),
    path('invalid-data', InvalidDataView.as_view()),
    path('failing-rows', FailingRowsView.as_view()),
    path('closable-rows', ClosableRowsView.as_view()),
    path('json-only', JSONOnlyView.as_view()),
]


class CSVStreamValidationTests(SimpleTestCase):
    def test_string_column_uses_path_as_label(self):
        stream = CSVStream(['id', 'user.name'], [])
        assert stream.columns == [('id', 'id'), ('user.name', 'user.name')]

    def test_tuple_and_mapping_columns(self):
        stream = CSVStream([
            ('Name', 'user.name'),
            {'label': 'ID', 'field': 'id'},
        ], [])
        assert stream.columns == [('Name', 'user.name'), ('ID', 'id')]

    def test_empty_columns_raise(self):
        with self.assertRaises(ImproperlyConfigured):
            CSVStream([], [])

    def test_non_iterable_columns_raise(self):
        with self.assertRaises(ImproperlyConfigured):
            CSVStream('id', [])

    def test_invalid_column_definition_raises(self):
        for columns in ([42], [('label',)], [('label', '')],
                        [{'label': 'x'}], [{'field': 'id'}]):
            with self.assertRaises(ImproperlyConfigured, msg=repr(columns)):
                CSVStream(columns, [])


class StreamingCSVRendererTests(SimpleTestCase):
    def render(self, columns, rows, renderer=None):
        renderer = renderer or StreamingCSVRenderer()
        stream = CSVStream(columns, iter(rows))
        return b''.join(renderer.render(stream)).decode('utf-8')

    def test_renders_header_and_rows_in_column_order(self):
        output = self.render(COLUMNS, ROWS)
        assert output == (
            'ID,Name,Note\r\n'
            '1,Alice,"line one\nline two"\r\n'
            '2,Bob,\r\n'
        )

    def test_missing_and_none_values_render_empty(self):
        output = self.render(['a', 'b.c'], [{'a': None}, {}])
        assert output == 'a,b.c\r\n,\r\n,\r\n'

    def test_resolves_attributes_on_objects(self):
        row = SimpleNamespace(id=3, user=SimpleNamespace(name='Cyd'), note='x')
        output = self.render(COLUMNS, [row])
        assert output == 'ID,Name,Note\r\n3,Cyd,x\r\n'

    def test_non_string_values_are_coerced(self):
        output = self.render(['n', 'ok'], [{'n': 1.5, 'ok': True}])
        assert output == 'n,ok\r\n1.5,True\r\n'

    def test_formula_prefixes_are_escaped_by_default(self):
        output = self.render(['v'], [{'v': '=SUM(A1)'}, {'v': '+1'}, {'v': '-2'}, {'v': '@x'}])
        assert output == "v\r\n'=SUM(A1)\r\n'+1\r\n'-2\r\n'@x\r\n"

    def test_formula_escape_may_be_customized(self):
        class CustomRenderer(StreamingCSVRenderer):
            formula_escape = '! '

        output = self.render(['v'], [{'v': '=1'}], renderer=CustomRenderer())
        assert output == 'v\r\n! =1\r\n'

    def test_formula_escape_may_be_a_callable(self):
        class CallableRenderer(StreamingCSVRenderer):
            formula_escape = staticmethod(lambda value: 'SAFE')

        output = self.render(['v'], [{'v': '@cmd'}], renderer=CallableRenderer())
        assert output == 'v\r\nSAFE\r\n'

    def test_formula_escape_may_be_disabled(self):
        class UnsafeRenderer(StreamingCSVRenderer):
            formula_escape = None

        output = self.render(['v'], [{'v': '=1'}], renderer=UnsafeRenderer())
        assert output == 'v\r\n=1\r\n'

    def test_render_requires_a_csv_stream(self):
        with self.assertRaises(ImproperlyConfigured):
            StreamingCSVRenderer().render({'a': 1})

    def test_rows_are_closed_when_streaming_ends(self):
        rows = ClosableRows()
        stream = CSVStream(COLUMNS, rows)
        chunks = StreamingCSVRenderer().render(stream)
        next(chunks)
        chunks.close()
        assert rows.closed

    def test_rows_are_closed_when_rows_raise(self):
        closed = []

        def rows():
            try:
                yield ROWS[0]
                raise RuntimeError('boom')
            finally:
                closed.append(True)

        chunks = StreamingCSVRenderer().render(CSVStream(COLUMNS, rows()))
        next(chunks)
        next(chunks)
        with self.assertRaises(RuntimeError):
            next(chunks)
        assert closed == [True]


@override_settings(ROOT_URLCONF='tests.test_streaming_csv')
class StreamingCSVViewTests(TestCase):
    def test_streams_csv_response(self):
        response = self.client.get('/users', HTTP_ACCEPT='text/csv')
        assert response.status_code == 200
        assert response['Content-Type'] == 'text/csv; charset=utf-8'
        assert response.streaming
        body = b''.join(response.streaming_content).decode('utf-8')
        assert body == (
            'ID,Name,Note\r\n'
            '1,Alice,"line one\nline two"\r\n'
            '2,Bob,\r\n'
        )

    def test_format_query_parameter_negotiates_csv(self):
        response = self.client.get('/users', {'format': 'csv'})
        assert response.status_code == 200
        assert response['Content-Type'] == 'text/csv; charset=utf-8'

    def test_unsupported_accept_header_returns_406(self):
        response = self.client.get('/users', HTTP_ACCEPT='application/json')
        assert response.status_code == 406
        assert response['Content-Type'] == 'text/csv; charset=utf-8'
        body = response.content.decode('utf-8')
        assert body.startswith('Field,Detail\r\n')
        assert 'Could not satisfy the request' in body

    def test_invalid_column_definitions_raise_before_headers(self):
        with self.assertRaises(ImproperlyConfigured):
            self.client.get('/invalid-columns')

    def test_invalid_response_data_raises_before_headers(self):
        with self.assertRaises(ImproperlyConfigured):
            self.client.get('/invalid-data')

    def test_first_row_is_streamed_before_rows_are_exhausted(self):
        response = self.client.get('/closable-rows', HTTP_ACCEPT='text/csv')
        chunks = iter(response.streaming_content)
        assert next(chunks) == b'ID,Name,Note\r\n'
        assert next(chunks) == b'1,Alice,"line one\nline two"\r\n'
        response.close()

    def test_closing_the_response_closes_the_row_iterable(self):
        response = self.client.get('/closable-rows', HTTP_ACCEPT='text/csv')
        next(iter(response.streaming_content))
        response.close()
        assert closable_rows[-1].closed

    def test_mid_stream_errors_are_not_converted_to_json(self):
        response = self.client.get('/failing-rows', HTTP_ACCEPT='text/csv')
        chunks = iter(response.streaming_content)
        received = [next(chunks), next(chunks)]
        with self.assertRaises(RuntimeError):
            next(chunks)
        body = b''.join(received)
        assert body == b'ID,Name,Note\r\n1,Alice,"line one\nline two"\r\n'
        assert b'{' not in body

    def test_streaming_response_supports_buffered_renderers(self):
        response = self.client.get('/json-only', HTTP_ACCEPT='application/json')
        assert response.status_code == 200
        assert response.streaming
        assert b''.join(response.streaming_content) == b'{"a":1}'
