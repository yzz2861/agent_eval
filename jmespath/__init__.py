from jmespath import parser
from jmespath.visitor import Options

__version__ = '1.1.0'


def compile(expression, options=None):
    decimal_mode = options is not None and options.decimal_mode
    return parser.Parser(decimal_mode=decimal_mode).parse(expression)


def search(expression, data, options=None):
    decimal_mode = options is not None and options.decimal_mode
    return parser.Parser(decimal_mode=decimal_mode).parse(
        expression, decimal_mode=decimal_mode).search(data, options=options)
