import csv
import io
from types import SimpleNamespace

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.http import StreamingHttpResponse

from rest_framework.permissions import BasePermission
from rest_framework.renderers import StreamingCSVRenderer
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

factory = APIRequestFactory()


def csv_view(data):
    class View(APIView):
        renderer_classes = (StreamingCSVRenderer,)

        def get(self, request):
            return Response(data)

    return View.as_view()


def get_csv(data, accept='text/csv'):
    request = factory.get('/', HTTP_ACCEPT=accept)
    return csv_view(data)(request)


class TestStreamingCSVRenderer:
    def test_streams_csv_with_fixed_column_order(self):
        response = get_csv({
            'columns': [
                'name',
                ('user.email', 'Email'),
                {'path': 'note', 'header': 'Note'},
            ],
            'rows': iter([
                {'note': 'first', 'name': 'alice', 'user': {'email': 'a@example.com'}},
                {'note': 'second', 'name': 'bob', 'user': {'email': 'b@example.com'}},
            ]),
        })

        assert isinstance(response, StreamingHttpResponse)
        assert response.status_code == 200
        assert response['Content-Type'] == 'text/csv; charset=utf-8'
        assert b''.join(response.streaming_content) == (
            b'name,Email,Note\r\n'
            b'alice,a@example.com,first\r\n'
            b'bob,b@example.com,second\r\n'
        )

    def test_none_values_render_as_empty_cells(self):
        response = get_csv({
            'columns': ['name', 'user.email'],
            'rows': iter([{'name': None, 'user': None}]),
        })
        assert b''.join(response.streaming_content) == b'name,user.email\r\n,\r\n'

    def test_embedded_newlines_and_commas_are_quoted(self):
        response = get_csv({
            'columns': ['note'],
            'rows': iter([{'note': 'line1\nline2, "quoted"'}]),
        })
        assert b''.join(response.streaming_content) == (
            b'note\r\n' + b'"line1\nline2, ""quoted"""\r\n'
        )

    def test_object_rows_and_non_string_values(self):
        row = SimpleNamespace(name='alice', score=42)
        response = get_csv({
            'columns': ['name', 'score'],
            'rows': iter([row]),
        })
        assert b''.join(response.streaming_content) == b'name,score\r\nalice,42\r\n'

    def test_columns_may_be_set_on_renderer_subclass(self):
        class MyRenderer(StreamingCSVRenderer):
            columns = [('name', 'Name')]

        class View(APIView):
            renderer_classes = (MyRenderer,)

            def get(self, request):
                return Response(iter([{'name': 'alice'}]))

        response = View.as_view()(factory.get('/', HTTP_ACCEPT='text/csv'))
        assert b''.join(response.streaming_content) == b'Name\r\nalice\r\n'

    def test_view_headers_are_preserved(self):
        class View(APIView):
            renderer_classes = (StreamingCSVRenderer,)

            def get(self, request):
                response = Response({'columns': ['a'], 'rows': iter([])})
                response['Content-Disposition'] = 'attachment; filename="export.csv"'
                return response

        response = View.as_view()(factory.get('/', HTTP_ACCEPT='text/csv'))
        assert response['Content-Disposition'] == 'attachment; filename="export.csv"'
        assert b''.join(response.streaming_content) == b'a\r\n'


class TestFormulaEscaping:
    @pytest.mark.parametrize('value', [
        '=1+1', '+SUM(A1)', '-2', '@mention', '\t=x', '\r=x',
    ])
    def test_dangerous_cells_are_prefixed_by_default(self, value):
        response = get_csv({'columns': ['v'], 'rows': iter([{'v': value}])})
        body = b''.join(response.streaming_content).decode()
        assert list(csv.reader(io.StringIO(body))) == [['v'], ["'" + value]]

    def test_safe_cells_are_not_escaped(self):
        response = get_csv({'columns': ['v'], 'rows': iter([{'v': 'a=b'}])})
        assert b''.join(response.streaming_content) == b'v\r\na=b\r\n'

    def test_escaping_may_be_disabled(self):
        class NoEscapeRenderer(StreamingCSVRenderer):
            formula_escape_strategy = 'none'

        class View(APIView):
            renderer_classes = (NoEscapeRenderer,)

            def get(self, request):
                return Response({'columns': ['v'], 'rows': iter([{'v': '=1+1'}])})

        response = View.as_view()(factory.get('/', HTTP_ACCEPT='text/csv'))
        assert b''.join(response.streaming_content) == b'v\r\n=1+1\r\n'

    def test_custom_escape_prefix(self):
        class CustomPrefixRenderer(StreamingCSVRenderer):
            formula_escape_prefix = '\t'

        class View(APIView):
            renderer_classes = (CustomPrefixRenderer,)

            def get(self, request):
                return Response({'columns': ['v'], 'rows': iter([{'v': '=1+1'}])})

        response = View.as_view()(factory.get('/', HTTP_ACCEPT='text/csv'))
        assert b''.join(response.streaming_content) == b'v\r\n\t=1+1\r\n'

    def test_invalid_escape_strategy_raises_before_streaming(self):
        class BadRenderer(StreamingCSVRenderer):
            formula_escape_strategy = 'strip'

        class View(APIView):
            renderer_classes = (BadRenderer,)

            def get(self, request):
                return Response({'columns': ['v'], 'rows': iter([])})

        with pytest.raises(ImproperlyConfigured):
            View.as_view()(factory.get('/', HTTP_ACCEPT='text/csv'))


class TestEagerValidation:
    @pytest.mark.parametrize('columns', [
        None,
        [],
        [123],
        [''],
        [{'header': 'No path'}],
        [('a', 'b', 'c')],
        [('a', 42)],
    ])
    def test_invalid_columns_raise_before_headers_sent(self, columns):
        data = {'rows': iter([])}
        if columns is not None:
            data['columns'] = columns
        with pytest.raises(ImproperlyConfigured):
            get_csv(data)

    def test_content_negotiation_failure_is_not_streamed(self):
        response = get_csv(
            {'columns': ['a'], 'rows': iter([])},
            accept='application/json',
        )
        assert response.status_code == 406
        assert not isinstance(response, StreamingHttpResponse)

    def test_permission_errors_use_regular_exception_handling(self):
        class DenyAll(BasePermission):
            def has_permission(self, request, view):
                return False

        class View(APIView):
            renderer_classes = (StreamingCSVRenderer,)
            permission_classes = (DenyAll,)

            def get(self, request):
                return Response({'columns': ['a'], 'rows': iter([])})

        response = View.as_view()(factory.get('/', HTTP_ACCEPT='text/csv'))
        assert response.status_code == 403
        assert not isinstance(response, StreamingHttpResponse)

    def test_options_requests_are_not_streamed(self):
        request = factory.options('/', HTTP_ACCEPT='text/csv')
        response = csv_view({'columns': ['a'], 'rows': iter([])})(request)
        response.render()
        assert response.status_code == 200
        assert not isinstance(response, StreamingHttpResponse)


class TestStreamingBehavior:
    def test_first_line_arrives_before_rows_are_exhausted(self):
        pulled = []

        def rows():
            for index in range(3):
                pulled.append(index)
                yield {'name': 'n%d' % index}

        response = get_csv({'columns': ['name'], 'rows': rows()})
        stream = iter(response)

        assert next(stream) == b'name\r\n'
        assert pulled == []
        assert next(stream) == b'n0\r\n'
        assert pulled == [0]

    def test_mid_stream_error_does_not_append_json(self):
        def rows():
            yield {'name': 'alice'}
            raise ValueError('database went away')

        response = get_csv({'columns': ['name'], 'rows': rows()})

        chunks = []
        with pytest.raises(ValueError):
            for chunk in response.streaming_content:
                chunks.append(chunk)

        content = b''.join(chunks)
        assert content == b'name\r\nalice\r\n'
        assert b'detail' not in content

    # `response.close()` fires Django's `request_finished` signal, which
    # touches the database connections, so allow database access here.
    @pytest.mark.django_db
    def test_closing_response_closes_source_iterator(self):
        closed = []

        def rows():
            try:
                yield {'name': 'alice'}
                yield {'name': 'bob'}
            finally:
                closed.append(True)

        response = get_csv({'columns': ['name'], 'rows': rows()})
        stream = iter(response)
        next(stream)
        next(stream)

        response.close()
        assert closed == [True]
