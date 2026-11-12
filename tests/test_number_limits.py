'''
Tests for the configurable number resource limits shared by all backends.
'''

import tracemalloc
from decimal import Decimal

import pytest

from ijson import common, numbers


SMALL_LIMITS = numbers.NumberLimits(
    max_token_length=20,
    max_integer_digits=3,
    max_decimal_places=2,
    max_exponent_abs=5,
    max_significant_digits=4,
)

RAW_LIMITS = numbers.NumberLimits(
    max_token_length=20,
    max_integer_digits=3,
    max_decimal_places=3,
    on_exceed=numbers.OnExceed.raw,
)

UNLIMITED = numbers.NumberLimits(
    max_token_length=None,
    max_integer_digits=None,
    max_decimal_places=None,
    max_exponent_abs=None,
    max_significant_digits=None,
)


def _drain_until_limit(generator):
    '''Collects events preceding a NumberLimitError.'''
    collected = []
    while True:
        try:
            collected.append(next(generator))
        except numbers.NumberLimitError:
            return collected


def _assert_limit_failure(adaptor, routine_name, document, reason, **kwargs):
    with pytest.raises(numbers.NumberLimitError, match=reason):
        getattr(adaptor, routine_name)(document, **kwargs)


def _drain_routine(adaptor, routine_name, document, **kwargs):
    backend = adaptor.backend
    suffix = adaptor._suffix
    if suffix == '_coro':
        from ijson.utils import sendable_list
        events = sendable_list()
        coro = getattr(backend, routine_name + '_coro')(events, **kwargs)
        try:
            for index in range(0, len(document), 64):
                coro.send(document[index:index + 64])
        except numbers.NumberLimitError:
            return list(events)
        coro.close()
        return list(events)
    routine = getattr(backend, routine_name + '_gen')
    if hasattr(document, 'read'):
        stream = document
    else:
        import io as _io
        stream = _io.BytesIO(document)
    return _drain_until_limit(routine(stream, **kwargs))


def _is_async(adaptor):
    return 'async' in adaptor.pytest_parameter_id


def _events_before_failure(adaptor, routine_name, document, **kwargs):
    '''Best-effort collection of events preceding a failure.  Pull-based
    file/iterable adaptors flush buffered events through the generator;
    push coroutines and async helpers surface only the exception.'''
    if _is_async(adaptor):
        with pytest.raises(numbers.NumberLimitError):
            getattr(adaptor, routine_name)(document, **kwargs)
        return None
    return _drain_routine(adaptor, routine_name, document, **kwargs)


class TestNumberLimitsParsing:
    '''End-to-end behaviour exercised through every backend/adaptor.'''

    @pytest.mark.parametrize("token, reason", [
        (b'1234', 'too many integer digits'),
        (b'1.123', 'too many decimal places'),
        (b'1e6', 'exponent too large'),
        (b'1e-6', 'exponent too large'),
        (b'1.2345', 'too many significant digits'),
    ])
    def test_limits_raise_before_number_event(self, adaptor, token, reason):
        limits = SMALL_LIMITS
        if reason == 'too many significant digits':
            # relax the other bounds so the significant-digit one fires
            limits = numbers.NumberLimits(
                max_token_length=20, max_integer_digits=10,
                max_decimal_places=10, max_exponent_abs=10,
                max_significant_digits=4,
            )
        events = _events_before_failure(
            adaptor, 'basic_parse', b'[1, ' + token + b', 3]',
            number_limits=limits
        )
        # re-raise to assert the failure details
        with pytest.raises(numbers.NumberLimitError, match=reason) as exc_info:
            adaptor.basic_parse(b'[1, ' + token + b', 3]',
                                number_limits=limits)
        err = exc_info.value
        assert err.path == 'item'
        assert err.offset is not None
        # only the events completed before the offending number are emitted
        if events is not None:
            assert events == [('start_array', None), ('number', 1)]
        assert isinstance(err, common.JSONError)

    def test_path_and_byte_offset_are_reported(self, adaptor):
        document = b'{"outer": {"inner": 1234567}}'
        with pytest.raises(numbers.NumberLimitError) as exc_info:
            list(adaptor.parse(document, number_limits=numbers.NumberLimits(
                max_integer_digits=3)))
        err = exc_info.value
        assert err.path == 'outer.inner'
        assert document[:err.offset].decode('utf8').endswith('"inner": ')

    def test_utf8_byte_offset(self, adaptor):
        # the two-byte "\u00e9" must be counted as two bytes
        document = '{"\u00e9": 12345}'.encode('utf8')
        with pytest.raises(numbers.NumberLimitError) as exc_info:
            list(adaptor.parse(document, number_limits=numbers.NumberLimits(
                max_integer_digits=3)))
        assert exc_info.value.offset == document.index(b'12345')

    def test_scalar_path_is_empty(self, adaptor):
        with pytest.raises(numbers.NumberLimitError) as exc_info:
            list(adaptor.parse(b'1234', number_limits=numbers.NumberLimits(
                max_integer_digits=3)))
        assert exc_info.value.path == ''
        assert exc_info.value.offset == 0

    def test_limit_failure_is_not_eof(self, adaptor):
        with pytest.raises(numbers.NumberLimitError):
            list(adaptor.basic_parse(b'12345', number_limits=numbers.NumberLimits(
                max_integer_digits=3)))
        # the same exhausted input without a number problem is a different
        # exception class, so limit errors never masquerade as EOF
        with pytest.raises(common.IncompleteJSONError):
            list(adaptor.basic_parse(b'['))

    def test_token_length_cannot_be_bypassed_by_raw_strategy(self, adaptor):
        limits = numbers.NumberLimits(
            max_token_length=10, on_exceed=numbers.OnExceed.raw
        )
        with pytest.raises(numbers.NumberLimitError, match='token too long'):
            list(adaptor.basic_parse(b'12345678901', number_limits=limits))

    def test_raw_strategy_keeps_original_token(self, adaptor):
        events = adaptor.basic_parse(
            b'[1234, 5, 1.2345]', number_limits=RAW_LIMITS
        )
        values = [value for event, value in events if event == 'number']
        assert values == ['1234', 5, '1.2345']
        assert all(type(value) is str for value in values
                   if value in ('1234', '1.2345'))

    def test_raw_strategy_works_through_parse_and_items(self, adaptor):
        parsed = list(adaptor.parse(b'{"a": 1234}', number_limits=RAW_LIMITS))
        assert ('a', 'number', '1234') in parsed
        built = list(adaptor.items(b'{"a": 1234}', '', number_limits=RAW_LIMITS))
        assert built == [{'a': '1234'}]

    def test_number_spanning_chunks_is_validated_once(self, adaptor):
        # chunking must not produce partial/duplicate number events
        kwargs = dict(number_limits=numbers.NumberLimits(max_integer_digits=3))
        if adaptor._suffix != '_coro':
            kwargs['buf_size'] = 3
        _assert_limit_failure(
            adaptor, 'basic_parse', b'[123456, 7]',
            'too many integer digits', **kwargs
        )

    def test_number_spanning_chunks_emits_complete_events_only(self, adaptor):
        kwargs = dict(number_limits=numbers.NumberLimits(max_integer_digits=3))
        if adaptor._suffix != '_coro':
            kwargs['buf_size'] = 3
        events = _events_before_failure(
            adaptor, 'basic_parse', b'[123456, 7]', **kwargs
        )
        if events is not None:
            assert events == [('start_array', None)]

    def test_legal_numbers_are_preserved(self, adaptor):
        document = b'[0, -0, 100, 1.5, -0.001, 1E3, -2.5e+4, 0.000100]'
        numbers_found = [
            value for event, value in adaptor.basic_parse(document)
            if event == 'number'
        ]
        assert numbers_found == [
            0, 0, 100, Decimal('1.5'), Decimal('-0.001'),
            Decimal('1E+3'), Decimal('-2.5E+4'), Decimal('0.000100'),
        ]

    def test_legal_decimal_keeps_exact_digits(self, adaptor):
        token = b'1.' + b'2' * 50
        value = [v for e, v in adaptor.basic_parse(token) if e == 'number'][0]
        assert value == Decimal(token.decode())
        assert value.as_tuple().digits[-1] == 2

    def test_negative_zero(self, adaptor):
        exact = [v for e, v in adaptor.basic_parse(b'-0') if e == 'number'][0]
        assert exact == 0 and type(exact) is int
        decimal_zero = [v for e, v in adaptor.basic_parse(b'-0.0')
                        if e == 'number'][0]
        assert decimal_zero == Decimal('-0.0')
        assert decimal_zero.is_signed()

    @pytest.mark.parametrize("token", [
        b'0.1', b'1.0000000000000001', b'123.456', b'1e308',
        b'9007199254740993',
    ])
    def test_float_conversion_matches_python_float(self, adaptor, token):
        value = [v for e, v in adaptor.basic_parse(token, use_float=True)
                 if e == 'number'][0]
        expected = float(token) if (b'.' in token or b'e' in token
                                    or b'E' in token) else int(token)
        assert value == expected
        assert type(value) is type(expected)

    def test_float_overflow_is_a_json_error(self, adaptor):
        limits = numbers.NumberLimits(max_exponent_abs=None)
        with pytest.raises(common.JSONError, match='float overflow'):
            list(adaptor.basic_parse(b'1e400', use_float=True,
                                      number_limits=limits))

    def test_huge_negative_exponent_fails_before_decimal_expansion(self, adaptor):
        tracemalloc.start()
        try:
            with pytest.raises(numbers.NumberLimitError, match='exponent too large'):
                list(adaptor.basic_parse(b'1e-999999999'))
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        # the failure happens before any GB-sized Decimal expansion
        assert peak < 10 * 1024 * 1024

    def test_long_integer_is_bounded_in_memory(self, adaptor):
        # a tight token-length bound keeps the wall-clock cost of the
        # byte-by-byte push/coroutine adaptors low while still proving the
        # parser stops early and its memory stays bounded
        limits = numbers.NumberLimits(max_token_length=1024)
        document = b'[' + b'1' * 4096 + b']'
        tracemalloc.start()
        try:
            kwargs = dict(buf_size=64) if adaptor._suffix != '_coro' else {}
            with pytest.raises(numbers.NumberLimitError):
                list(adaptor.basic_parse(document, number_limits=limits,
                                         **kwargs))
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < 10 * 1024 * 1024

    def test_events_emitted_are_complete_only(self, adaptor):
        events = _events_before_failure(
            adaptor, 'basic_parse', b'{"ok": 1, "bad": [2, 1234567]}',
            number_limits=numbers.NumberLimits(max_integer_digits=3)
        )
        # no partial ('number', ...) pair for the bad value
        if events is not None:
            assert ('number', 1) in events
            assert not any(value == '1234567' for event, value in events)
            assert events[-1] == ('number', 2)

    def test_explicitly_disabled_limits_keep_legacy_behaviour(self, adaptor):
        document = b'[12345, 1.5]'
        values = [v for e, v in adaptor.basic_parse(
            document, number_limits=UNLIMITED) if e == 'number']
        assert values == [12345, Decimal('1.5')]


class TestNumberLimitsConfiguration:
    def test_defaults_are_enabled(self):
        limits = numbers.resolve_number_limits()
        assert limits is numbers.DEFAULT_NUMBER_LIMITS
        assert limits.max_integer_digits == numbers.DEFAULT_MAX_INTEGER_DIGITS
        assert limits.on_exceed is numbers.OnExceed.error

    def test_instance_is_returned_untouched(self):
        limits = numbers.NumberLimits(max_integer_digits=2)
        assert numbers.resolve_number_limits(limits) is limits

    def test_mapping_and_overrides(self):
        limits = numbers.resolve_number_limits(
            {'max_integer_digits': 2}, max_decimal_places=7
        )
        assert limits.max_integer_digits == 2
        assert limits.max_decimal_places == 7

    def test_invalid_values_are_rejected(self):
        with pytest.raises(ValueError):
            numbers.NumberLimits(max_integer_digits=-1)
        with pytest.raises(ValueError):
            numbers.NumberLimits(on_exceed='silently-float')

    @pytest.mark.parametrize("token, expected_digits", [
        ('0', 1), ('-0', 1), ('0.00', 1), ('1000', 1),
        ('1.200', 2), ('0.0001234', 4), ('12345', 5), ('1.23e10', 3),
    ])
    def test_significant_digit_count(self, token, expected_digits):
        _, int_digits, frac_digits, _ = numbers._parse_token(token)
        assert numbers._significant_digits(token, int_digits, frac_digits) \
            == expected_digits


class TestBackendParity:
    '''All available backends must agree on boundary values.'''

    def test_boundary_values_are_identical_across_backends(self, backend):
        # values sitting exactly on the default integer boundary
        inside = '9' * numbers.DEFAULT_MAX_INTEGER_DIGITS
        outside = '1' + '0' * numbers.DEFAULT_MAX_INTEGER_DIGITS
        document = ('[%s, %s]' % (inside, outside)).encode()
        with pytest.raises(numbers.NumberLimitError):
            # the boundary-violating second value must stop the parse
            list(backend.basic_parse(document))
        # a document with only the in-bound value converts exactly
        values = [v for e, v in backend.basic_parse(b'[%s]' % inside.encode())
                  if e == 'number']
        assert values == [int(inside)]
        with pytest.raises(numbers.NumberLimitError):
            list(backend.basic_parse(b'[%s]' % outside.encode()))

    def test_float_boundary_parity(self, backend):
        document = b'[1.5, 1e10, 0.0001]'
        values = [v for e, v in backend.basic_parse(document, use_float=True)
                  if e == 'number']
        assert values == [1.5, 1e10, 0.0001]
        assert all(type(v) is float for v in values)
