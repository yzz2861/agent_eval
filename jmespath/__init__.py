from jmespath import parser
from jmespath.visitor import Options

__version__ = '1.1.0'


def compile(expression, options=None):
    enable_let = getattr(options, 'enable_let', False) if options else False
    return parser.Parser(enable_let=enable_let).parse(expression)


def search(expression, data, options=None):
    enable_let = getattr(options, 'enable_let', False) if options else False
    return parser.Parser(enable_let=enable_let).parse(
        expression).search(data, options=options)
