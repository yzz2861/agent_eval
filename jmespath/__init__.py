from jmespath import parser
from jmespath.visitor import Options

__version__ = '1.1.0'


def compile(expression, decimal_mode=False):
    return parser.Parser(decimal_mode=decimal_mode).parse(expression)


def search(expression, data, options=None, decimal_mode=False):
    if options is not None and getattr(
            options, 'decimal_mode', False):
        decimal_mode = True
    parsed = parser.Parser(decimal_mode=decimal_mode).parse(expression)
    if options is None:
        options = Options(decimal_mode=decimal_mode)
    return parsed.search(data, options=options)
