import math
import json
import threading
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation, localcontext

from jmespath import exceptions
from jmespath.compat import string_type as STRING_TYPE
from jmespath.compat import get_methods


# python types -> jmespath types
TYPES_MAP = {
    'bool': 'boolean',
    'list': 'array',
    'dict': 'object',
    'NoneType': 'null',
    'unicode': 'string',
    'str': 'string',
    'float': 'number',
    'int': 'number',
    'long': 'number',
    'OrderedDict': 'object',
    '_Projection': 'array',
    '_Expression': 'expref',
}


# jmespath types -> python types
REVERSE_TYPES_MAP = {
    'boolean': ('bool',),
    'array': ('list', '_Projection'),
    'object': ('dict', 'OrderedDict',),
    'null': ('NoneType',),
    'string': ('unicode', 'str'),
    'number': ('float', 'int', 'long'),
    'expref': ('_Expression',),
}


def signature(*arguments):
    def _record_signature(func):
        func.signature = arguments
        return func
    return _record_signature


class FunctionRegistry(type):
    def __init__(cls, name, bases, attrs):
        cls._populate_function_table()
        super(FunctionRegistry, cls).__init__(name, bases, attrs)

    def _populate_function_table(cls):
        function_table = {}
        # Any method with a @signature decorator that also
        # starts with "_func_" is registered as a function.
        # _func_max_by -> max_by function.
        for name, method in get_methods(cls):
            if not name.startswith('_func_'):
                continue
            signature = getattr(method, 'signature', None)
            if signature is not None:
                function_table[name[6:]] = {
                    'function': method,
                    'signature': signature,
                }
        cls.FUNCTION_TABLE = function_table


class Functions(metaclass=FunctionRegistry):

    FUNCTION_TABLE = {
    }

    def __init__(self, decimal_mode=False, decimal_context=None):
        self.decimal_mode = decimal_mode
        self.decimal_context = decimal_context
        self._decimal_state = threading.local()

    @property
    def _active_decimal_mode(self):
        state = getattr(self, '_decimal_state', None)
        if state is None:
            state = threading.local()
            self._decimal_state = state
        return getattr(state, 'mode', getattr(self, 'decimal_mode', False))

    @contextmanager
    def _decimal_runtime(self, decimal_mode=False, decimal_context=None):
        state = getattr(self, '_decimal_state', None)
        if state is None:
            state = threading.local()
            self._decimal_state = state
        old_mode = getattr(self._decimal_state, 'mode', None)
        self._decimal_state.mode = decimal_mode
        try:
            if decimal_mode and decimal_context is not None:
                with localcontext(decimal_context):
                    yield
            else:
                yield
        finally:
            if old_mode is None:
                del self._decimal_state.mode
            else:
                self._decimal_state.mode = old_mode

    def call_function(self, function_name, resolved_args,
                      decimal_mode=None, decimal_context=None):
        try:
            spec = self.FUNCTION_TABLE[function_name]
        except KeyError:
            raise exceptions.UnknownFunctionError(
                "Unknown function: %s()" % function_name)
        function = spec['function']
        signature = spec['signature']
        if decimal_mode is None:
            decimal_mode = self._active_decimal_mode
        if decimal_context is None:
            decimal_context = getattr(self, 'decimal_context', None)
        with self._decimal_runtime(decimal_mode, decimal_context):
            if decimal_mode:
                try:
                    resolved_args = self._decimal_arguments(
                        resolved_args, signature)
                except exceptions.JMESPathTypeError as e:
                    if not e.function_name:
                        e.function_name = function_name
                    raise
                except ValueError:
                    raise exceptions.JMESPathTypeError(
                        function_name, resolved_args[0], 'number',
                        signature[0]['types'])
            self._validate_arguments(
                resolved_args, signature, function_name)
            return function(self, *resolved_args)

    def _decimal_arguments(self, args, signature):
        converted = []
        variadic = bool(signature and signature[-1].get('variadic'))
        for i, arg in enumerate(args):
            if i < len(signature) or variadic:
                arg = self._decimal_argument(
                    arg, signature[min(i, len(signature) - 1)]['types'])
            converted.append(arg)
        return converted

    def _decimal_argument(self, arg, types):
        if not types or 'number' not in types and not any(
                t.startswith('array-number') for t in types):
            return arg
        if isinstance(arg, list):
            converted = []
            for element in arg:
                try:
                    converted.append(self._decimal_number(element))
                except ValueError:
                    raise exceptions.JMESPathTypeError(
                        '', element, 'number', ['array-number'])
            return converted
        return self._decimal_number(arg)

    def _decimal_number(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, Decimal):
            decimal_value = value
        elif isinstance(value, float):
            decimal_value = Decimal(str(value))
        elif isinstance(value, int):
            return value
        else:
            return value
        if not decimal_value.is_finite():
            raise ValueError('Non-finite number: %s' % value)
        return decimal_value

    def _validate_arguments(self, args, signature, function_name):
        if signature and signature[-1].get('variadic'):
            if len(args) < len(signature):
                raise exceptions.VariadictArityError(
                    len(signature), len(args), function_name)
        elif len(args) != len(signature):
            raise exceptions.ArityError(
                len(signature), len(args), function_name)
        return self._type_check(args, signature, function_name)

    def _type_check(self, actual, signature, function_name):
        variadic = bool(signature and signature[-1].get('variadic'))
        for i in range(len(actual)):
            signature_index = min(i, len(signature) - 1)
            allowed_types = signature[signature_index]['types']
            if allowed_types:
                self._type_check_single(
                    actual[i], allowed_types, function_name)

    def _type_check_single(self, current, types, function_name):
        # Type checking involves checking the top level type,
        # and in the case of arrays, potentially checking the types
        # of each element.
        allowed_types, allowed_subtypes = self._get_allowed_pytypes(types)
        # We're not using isinstance() on purpose.
        # The type model for jmespath does not map
        # 1-1 with python types (booleans are considered
        # integers in python for example).
        actual_typename = type(current).__name__
        if actual_typename not in allowed_types:
            raise exceptions.JMESPathTypeError(
                function_name, current,
                self._convert_to_jmespath_type(actual_typename), types)
        # If we're dealing with a list type, we can have
        # additional restrictions on the type of the list
        # elements (for example a function can require a
        # list of numbers or a list of strings).
        # Arrays are the only types that can have subtypes.
        if allowed_subtypes:
            self._subtype_check(current, allowed_subtypes,
                                types, function_name)

    def _get_allowed_pytypes(self, types):
        allowed_types = []
        allowed_subtypes = []
        for t in types:
            type_ = t.split('-', 1)
            if len(type_) == 2:
                type_, subtype = type_
                pytypes = list(REVERSE_TYPES_MAP[subtype])
                if subtype == 'number' and self._active_decimal_mode:
                    pytypes.append('Decimal')
                allowed_subtypes.append(pytypes)
            else:
                type_ = type_[0]
            pytypes = list(REVERSE_TYPES_MAP[type_])
            if type_ == 'number' and self._active_decimal_mode:
                pytypes.append('Decimal')
            allowed_types.extend(pytypes)
        return allowed_types, allowed_subtypes

    def _subtype_check(self, current, allowed_subtypes, types, function_name):
        if len(allowed_subtypes) == 1:
            # The easy case, we know up front what type
            # we need to validate.
            allowed_subtypes = allowed_subtypes[0]
            for element in current:
                actual_typename = type(element).__name__
                if actual_typename not in allowed_subtypes:
                    raise exceptions.JMESPathTypeError(
                        function_name, element, actual_typename, types)
        elif len(allowed_subtypes) > 1 and current:
            # Dynamic type validation.  Based on the first
            # type we see, we validate that the remaining types
            # match.
            first = type(current[0]).__name__
            for subtypes in allowed_subtypes:
                if first in subtypes:
                    allowed = subtypes
                    break
            else:
                raise exceptions.JMESPathTypeError(
                    function_name, current[0], first, types)
            for element in current:
                actual_typename = type(element).__name__
                if actual_typename not in allowed:
                    raise exceptions.JMESPathTypeError(
                        function_name, element, actual_typename, types)

    @signature({'types': ['number']})
    def _func_abs(self, arg):
        return abs(arg)

    @signature({'types': ['array-number']})
    def _func_avg(self, arg):
        if arg:
            if self._active_decimal_mode:
                return sum(arg, Decimal(0)) / Decimal(len(arg))
            return sum(arg) / len(arg)
        else:
            return None

    @signature({'types': [], 'variadic': True})
    def _func_not_null(self, *arguments):
        for argument in arguments:
            if argument is not None:
                return argument

    @signature({'types': []})
    def _func_to_array(self, arg):
        if isinstance(arg, list):
            return arg
        else:
            return [arg]

    @signature({'types': []})
    def _func_to_string(self, arg):
        if isinstance(arg, STRING_TYPE):
            return arg
        else:
            return json.dumps(arg, separators=(',', ':'),
                              default=str)

    @signature({'types': []})
    def _func_to_number(self, arg):
        decimal_mode = self._active_decimal_mode
        if isinstance(arg, (list, dict, bool)):
            return None
        elif arg is None:
            return None
        elif decimal_mode and isinstance(arg, Decimal):
            return arg if arg.is_finite() else None
        elif isinstance(arg, (int, float)):
            if decimal_mode:
                try:
                    return self._decimal_number(arg)
                except ValueError:
                    return None
            return arg
        else:
            try:
                if decimal_mode:
                    decimal_value = Decimal(arg)
                    return decimal_value if decimal_value.is_finite() else None
                return int(arg)
            except (ValueError, ArithmeticError, InvalidOperation):
                pass
            try:
                if decimal_mode:
                    return self._decimal_number(float(arg))
                return float(arg)
            except (ValueError, ArithmeticError):
                return None

    @signature({'types': ['array', 'string']}, {'types': []})
    def _func_contains(self, subject, search):
        return search in subject

    @signature({'types': ['string', 'array', 'object']})
    def _func_length(self, arg):
        return len(arg)

    @signature({'types': ['string']}, {'types': ['string']})
    def _func_ends_with(self, search, suffix):
        return search.endswith(suffix)

    @signature({'types': ['string']}, {'types': ['string']})
    def _func_starts_with(self, search, suffix):
        return search.startswith(suffix)

    @signature({'types': ['array', 'string']})
    def _func_reverse(self, arg):
        if isinstance(arg, STRING_TYPE):
            return arg[::-1]
        else:
            return list(reversed(arg))

    @signature({"types": ['number']})
    def _func_ceil(self, arg):
        return math.ceil(arg)

    @signature({"types": ['number']})
    def _func_floor(self, arg):
        return math.floor(arg)

    @signature({"types": ['string']}, {"types": ['array-string']})
    def _func_join(self, separator, array):
        return separator.join(array)

    @signature({'types': ['expref']}, {'types': ['array']})
    def _func_map(self, expref, arg):
        result = []
        for element in arg:
            result.append(expref.visit(expref.expression, element))
        return result

    @signature({"types": ['array-number', 'array-string']})
    def _func_max(self, arg):
        if arg:
            return max(arg)
        else:
            return None

    @signature({"types": ["object"], "variadic": True})
    def _func_merge(self, *arguments):
        merged = {}
        for arg in arguments:
            merged.update(arg)
        return merged

    @signature({"types": ['array-number', 'array-string']})
    def _func_min(self, arg):
        if arg:
            return min(arg)
        else:
            return None

    @signature({"types": ['array-string', 'array-number']})
    def _func_sort(self, arg):
        return list(sorted(arg))

    @signature({"types": ['array-number']})
    def _func_sum(self, arg):
        return sum(arg)

    @signature({"types": ['object']})
    def _func_keys(self, arg):
        # To be consistent with .values()
        # should we also return the indices of a list?
        return list(arg.keys())

    @signature({"types": ['object']})
    def _func_values(self, arg):
        return list(arg.values())

    @signature({'types': []})
    def _func_type(self, arg):
        if isinstance(arg, STRING_TYPE):
            return "string"
        elif isinstance(arg, bool):
            return "boolean"
        elif isinstance(arg, list):
            return "array"
        elif isinstance(arg, dict):
            return "object"
        elif isinstance(arg, Decimal):
            if self._active_decimal_mode:
                return "number"
        elif isinstance(arg, (float, int)):
            return "number"
        elif arg is None:
            return "null"

    @signature({'types': ['array']}, {'types': ['expref']})
    def _func_sort_by(self, array, expref):
        if not array:
            return array
        # sort_by allows for the expref to be either a number of
        # a string, so we have some special logic to handle this.
        # We evaluate the first array element and verify that it's
        # either a string of a number.  We then create a key function
        # that validates that type, which requires that remaining array
        # elements resolve to the same type as the first element.
        required_type = self._convert_to_jmespath_type(
            type(expref.visit(expref.expression, array[0])).__name__)
        if required_type not in ['number', 'string']:
            raise exceptions.JMESPathTypeError(
                'sort_by', array[0], required_type, ['string', 'number'])
        keyfunc = self._create_key_func(expref,
                                        [required_type],
                                        'sort_by')
        return list(sorted(array, key=keyfunc))

    @signature({'types': ['array']}, {'types': ['expref']})
    def _func_min_by(self, array, expref):
        keyfunc = self._create_key_func(expref,
                                        ['number', 'string'],
                                        'min_by')
        if array:
            return min(array, key=keyfunc)
        else:
            return None

    @signature({'types': ['array']}, {'types': ['expref']})
    def _func_max_by(self, array, expref):
        keyfunc = self._create_key_func(expref,
                                        ['number', 'string'],
                                        'max_by')
        if array:
            return max(array, key=keyfunc)
        else:
            return None

    def _create_key_func(self, expref, allowed_types, function_name):
        def keyfunc(x):
            result = expref.visit(expref.expression, x)
            if self._active_decimal_mode and 'number' in allowed_types:
                try:
                    result = self._decimal_number(result)
                except ValueError:
                    raise exceptions.JMESPathTypeError(
                        function_name, result, 'number', allowed_types)
            actual_typename = type(result).__name__
            jmespath_type = self._convert_to_jmespath_type(actual_typename)
            # allowed_types is in term of jmespath types, not python types.
            if jmespath_type not in allowed_types:
                raise exceptions.JMESPathTypeError(
                    function_name, result, jmespath_type, allowed_types)
            return result
        return keyfunc

    def _convert_to_jmespath_type(self, pyobject):
        if pyobject == 'Decimal' and self._active_decimal_mode:
            return 'number'
        return TYPES_MAP.get(pyobject, 'unknown')
