'''
Numeric token validation, conversion and resource limits.

All ijson backends funnel the JSON number tokens they find through the
functions in this module.  The centralisation serves two purposes:

* every backend applies the same resource limits, so a document that is
  rejected (or preserved as a raw token) by one backend is treated the same
  way by all the others; and
* every backend produces the same converted values (``int``/``Decimal`` or
  ``int``/``float``), which avoids the subtle rounding differences that
  appear when a C library converts a number to ``double`` itself while the
  pure Python backend converts the original token.
'''

from dataclasses import dataclass
import decimal
import enum


class OnExceed(enum.Enum):
    '''What to do when a number token does not fit within the configured
    :class:`NumberLimits` (unless the token itself is too long to keep,
    see :class:`NumberLimits`).'''

    #: Raise :class:`NumberLimitError` before any ``number`` event is emitted.
    error = 'error'
    #: Emit the original token as a ``str`` value in the ``number`` event
    #: instead of converting it.
    raw = 'raw'


#: Default maximum length, in characters, of a whole number token.  This is
#: also the amount of memory the pure-Python lexer is willing to accumulate
#: for a single token; it therefore cannot be bypassed with ``on_exceed=raw``.
DEFAULT_MAX_TOKEN_LENGTH = 100_000

#: Default maximum amount of integer digits in a number token.
DEFAULT_MAX_INTEGER_DIGITS = 10_000

#: Default maximum amount of fractional digits in a number token.
DEFAULT_MAX_DECIMAL_PLACES = 10_000

#: Default maximum absolute value of a number exponent.
DEFAULT_MAX_EXPONENT_ABS = 10_000

#: Default maximum amount of significant digits of the converted value.
DEFAULT_MAX_SIGNIFICANT_DIGITS = 10_000


class NumberLimitError(Exception):
    '''
    Raised when a JSON number exceeds the configured :class:`NumberLimits`.

    The failure happens while the token is being validated, i.e. before any
    ``number`` event is produced, so no half-emitted event ever reaches the
    caller.  ``path`` is filled in by the path-tracking layer (and might be
    ``None`` at the ``basic_parse`` level), while ``offset`` is the byte
    position of the token in the input stream when the backend can compute
    it exactly.
    '''

    def __init__(self, reason, token=None, offset=None, path=None,
                 limit=None, value=None):
        self.reason = reason
        self.token = token
        self.offset = offset
        self.path = path
        self.limit = limit
        self.value = value
        super().__init__(self._format_message())

    def _format_message(self):
        msg = 'Number limit exceeded (%s)' % self.reason
        details = []
        if self.path:
            details.append('path=%s' % self.path)
        if self.offset is not None:
            details.append('offset=%d' % self.offset)
        if self.limit is not None:
            details.append('limit=%s' % self.limit)
        if self.value is not None:
            details.append('value=%s' % self.value)
        if details:
            msg += ': ' + ', '.join(details)
        if self.token is not None:
            shown = self.token
            if len(shown) > 32:
                shown = shown[:29] + '...'
            msg += ', token=%r' % shown
        return msg

    def set_path(self, path):
        '''Attach the JSON path to this error and refresh its message.'''
        self.path = path
        self.args = (self._format_message(),)
        return self


@dataclass(frozen=True)
class NumberLimits:
    '''
    Resource bounds applied to JSON number tokens before they are converted
    into Python values.

    Each bound is compared against the *original* token, so the checks run
    before any potentially expensive conversion (``int`` on a huge digit
    string, ``Decimal`` exponent expansion, ``float`` overflow handling, ...)
    takes place.  A value of ``None`` disables the individual bound.

    - ``max_token_length``: maximum length, in characters, of the whole
      token (sign, integer part, fraction and exponent included).  Tokens
      longer than this are always rejected, even when ``on_exceed`` is
      :attr:`OnExceed.raw`, because keeping them would itself defeat the
      purpose of the limit.
    - ``max_integer_digits``: maximum amount of digits in the integer part,
      ignoring a leading sign and leading zeros.
    - ``max_decimal_places``: maximum amount of digits in the fractional
      part.
    - ``max_exponent_abs``: maximum absolute value of the exponent.
    - ``max_significant_digits``: maximum amount of significant digits of
      the (un-rounded) value represented by the token.
    - ``on_exceed``: :attr:`OnExceed.error` (the default) makes the parser
      raise :class:`NumberLimitError`; :attr:`OnExceed.raw` keeps the
      original token as a ``str`` value of the ``number`` event.
    '''

    max_token_length: object = DEFAULT_MAX_TOKEN_LENGTH
    max_integer_digits: object = DEFAULT_MAX_INTEGER_DIGITS
    max_decimal_places: object = DEFAULT_MAX_DECIMAL_PLACES
    max_exponent_abs: object = DEFAULT_MAX_EXPONENT_ABS
    max_significant_digits: object = DEFAULT_MAX_SIGNIFICANT_DIGITS
    on_exceed: object = OnExceed.error

    def __post_init__(self):
        for name in ('max_token_length', 'max_integer_digits',
                     'max_decimal_places', 'max_exponent_abs',
                     'max_significant_digits'):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise ValueError('%s must be a non-negative int or None, got %r'
                                 % (name, value))
        if not isinstance(self.on_exceed, OnExceed):
            try:
                object.__setattr__(self, 'on_exceed', OnExceed(self.on_exceed))
            except ValueError:
                raise ValueError(
                    'on_exceed must be an OnExceed value, got %r' % (self.on_exceed,)
                )


#: Bounds enabled by default on every backend.
DEFAULT_NUMBER_LIMITS = NumberLimits()


def resolve_number_limits(number_limits=None, **overrides):
    '''
    Returns a normalised :class:`NumberLimits` instance.

    ``number_limits`` may be ``None`` (the default limits are used), an
    already-built :class:`NumberLimits` instance (returned untouched), or a
    mapping/``kwargs`` collection with individual fields.  Individual keyword
    overrides take precedence over the values found in ``number_limits``.
    '''
    if number_limits is None:
        base = DEFAULT_NUMBER_LIMITS
    elif isinstance(number_limits, NumberLimits):
        base = number_limits
    elif isinstance(number_limits, dict):
        base = NumberLimits(**{
            key: value for key, value in number_limits.items()
            if value is not None
        })
    else:
        raise TypeError(
            'number_limits must be a NumberLimits instance, a mapping or None, '
            'got %r' % type(number_limits)
        )
    overrides = {key: value for key, value in overrides.items()
                 if value is not None}
    if not overrides:
        return base
    return NumberLimits(**{**base.__dict__, **overrides})


def check_token_length(token, limits, offset=None, path=None):
    '''
    Guard used by the streaming lexers while a token is being accumulated.

    Only the overall token length is available at that point, which is also
    the one bound that cannot be side-stepped with ``on_exceed=raw``: a raw
    token of unbounded length would consume the same amount of memory the
    limit is meant to prevent.
    '''
    max_length = limits.max_token_length
    if max_length is not None and len(token) > max_length:
        raise NumberLimitError(
            'token too long', token=None, offset=offset, path=path,
            limit=max_length, value=len(token)
        )


def _parse_token(token):
    '''Splits a number token into its structural pieces in a single linear
    scan.  The lexers only hand out syntactically valid number tokens, so the
    parsing is deliberately simple and allocation-free beyond the result.'''
    end = len(token)
    index = 0
    negative = False
    if index < end and token[index] == '-':
        negative = True
        index += 1

    int_start = index
    while index < end and token[index].isdigit():
        index += 1
    int_digits = index - int_start

    frac_digits = 0
    if index < end and token[index] == '.':
        index += 1
        frac_start = index
        while index < end and token[index].isdigit():
            index += 1
        frac_digits = index - frac_start

    exponent = None
    if index < end and token[index] in 'eE':
        index += 1
        exp_negative = False
        if index < end and token[index] in '+-':
            exp_negative = token[index] == '-'
            index += 1
        exp_start = index
        while index < end and token[index].isdigit():
            index += 1
        exponent_digits = token[exp_start:index].lstrip('0') or '0'
        exponent = ('-' if exp_negative else '') + exponent_digits

    return negative, int_digits, frac_digits, exponent


def _exponent_too_big(exponent, max_abs):
    # ``exponent`` is a signed string of digits; compare it without calling
    # int() on an arbitrarily long digit string
    if exponent is None:
        return False
    negative = exponent.startswith('-')
    digits = exponent[1:] if negative else exponent
    limit = str(max_abs)
    if len(digits) != len(limit):
        return len(digits) > len(limit)
    return digits > limit


def check_number_token(token, limits, offset=None, path=None):
    '''Validates a complete number token against ``limits``.  Returns the
    token untouched when it fits, or (when ``on_exceed`` is
    :attr:`OnExceed.raw`) when it does not fit but is short enough to be
    kept.  Raises :class:`NumberLimitError` otherwise.'''
    check_token_length(token, limits)

    negative, int_digits, frac_digits, exponent = _parse_token(token)

    def fail(reason, limit, value):
        raise NumberLimitError(reason, token=token, offset=offset, path=path,
                               limit=limit, value=value)

    if limits.max_integer_digits is not None and int_digits > limits.max_integer_digits:
        if limits.on_exceed is OnExceed.raw:
            return token
        fail('too many integer digits', limits.max_integer_digits, int_digits)

    if limits.max_decimal_places is not None and frac_digits > limits.max_decimal_places:
        if limits.on_exceed is OnExceed.raw:
            return token
        fail('too many decimal places', limits.max_decimal_places, frac_digits)

    if exponent is not None and limits.max_exponent_abs is not None and \
            _exponent_too_big(exponent, limits.max_exponent_abs):
        if limits.on_exceed is OnExceed.raw:
            return token
        # report the exponent as a string; converting a million-digit
        # exponent to int would defeat the purpose of the bound
        fail('exponent too large', limits.max_exponent_abs, exponent)

    if limits.max_significant_digits is not None:
        significant = _significant_digits(token, int_digits, frac_digits)
        if significant > limits.max_significant_digits:
            if limits.on_exceed is OnExceed.raw:
                return token
            fail('too many significant digits',
                 limits.max_significant_digits, significant)

    return None


def _significant_digits(token, int_digits, frac_digits):
    # Significant digits = digits from the first non-zero to the last
    # non-zero digit of the token; an all-zero token has one significant
    # digit (e.g. negative zero).
    mantissa = token
    for marker in ('e', 'E'):
        exp_pos = mantissa.find(marker)
        if exp_pos != -1:
            mantissa = mantissa[:exp_pos]
            break
    digits = mantissa.lstrip('-').replace('.', '')
    stripped = digits.lstrip('0')
    if not stripped:
        return 1
    significant = len(stripped.rstrip('0'))
    if significant == 0:
        return 1
    return significant


def convert_number(token, use_float=False, limits=DEFAULT_NUMBER_LIMITS,
                   offset=None, path=None):
    '''
    Validates and converts a JSON number token in a backend-independent way.

    Returns either the converted value (``int``/``Decimal`` in exact mode,
    ``int``/``float`` in float mode) or the original token as a ``str`` when
    the configured limits are exceeded and ``on_exceed`` is
    :attr:`OnExceed.raw`.

    All bounds are checked before the conversion runs, so neither a giant
    ``int`` conversion nor an exponent-driven ``Decimal`` expansion can
    exhaust the available memory.
    '''
    raw = check_number_token(token, limits, offset=offset, path=path)
    if raw is not None:
        return raw

    if use_float:
        if '.' not in token and 'e' not in token and 'E' not in token:
            value = int(token)
        else:
            value = float(token)
            if value == float('inf') or value == float('-inf'):
                # Keep the JSONError semantics shared by all backends for
                # values that cannot be represented as a finite double
                from ijson import common
                raise common.JSONError('float overflow: %s' % token)
        return value

    if '.' not in token and 'e' not in token and 'E' not in token:
        return int(token)
    return decimal.Decimal(token)
