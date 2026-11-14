"""Compile-time resource limits and expansion budgets.

A single :class:`CompileLimits` object is shared between the parser and
the compiler so that resource accounting survives all compilation
stages (parsing, parameterization expansion and code generation).

"""

from .errors import CompileError


# Stages reported on limit violations.
PARSE_STAGE = 'parse'
IMPORT_STAGE = 'import'
EXPANSION_STAGE = 'parameterization-expansion'


DEFAULT_MAX_MODULE_IMPORTS = 1024
DEFAULT_MAX_PARAMETER_SUBSTITUTIONS = 50000
DEFAULT_MAX_GENERATED_TYPES = 50000
DEFAULT_MAX_NODES = 1000000
DEFAULT_MAX_EXPANSION_DEPTH = 512


class CompileLimits(object):
    """Resource limits shared by all compilation stages.

    Give ``None`` for an individual limit to disable it.

    """

    def __init__(self,
                 max_module_imports=DEFAULT_MAX_MODULE_IMPORTS,
                 max_parameter_substitutions=(
                     DEFAULT_MAX_PARAMETER_SUBSTITUTIONS),
                 max_generated_types=DEFAULT_MAX_GENERATED_TYPES,
                 max_nodes=DEFAULT_MAX_NODES,
                 max_expansion_depth=DEFAULT_MAX_EXPANSION_DEPTH):
        self.max_module_imports = max_module_imports
        self.max_parameter_substitutions = max_parameter_substitutions
        self.max_generated_types = max_generated_types
        self.max_nodes = max_nodes
        self.max_expansion_depth = max_expansion_depth

        # Number of parameterized type references expanded.
        self.parameter_substitutions = 0

        # Number of type descriptors created while expanding types.
        self.generated_types = 0

        # Deepest parameterized expansion reached.
        self.expansion_depth_seen = 0

        # Total number of dict/list/scalar nodes accounted for.
        self.total_nodes = 0

        # Node usage tracked independently per compilation stage so
        # that parse-time and expansion-time nodes are not summed.
        self.stage_nodes = {}

    def check(self, limit_name, value, stage, location, what):
        limit = getattr(self, limit_name)

        if limit is not None and value > limit:
            raise LimitExceeded(what,
                                value,
                                limit,
                                stage,
                                location)

    def count_nodes(self, nodes, stage, location=None):
        if self.max_nodes is None:
            return

        self.total_nodes += nodes
        stage_total = self.stage_nodes.get(stage, 0) + nodes
        self.stage_nodes[stage] = stage_total
        self.check('max_nodes',
                   stage_total,
                   stage,
                   location,
                   'total schema nodes')

    def substitution(self, location=None):
        self.parameter_substitutions += 1
        self.check('max_parameter_substitutions',
                   self.parameter_substitutions,
                   EXPANSION_STAGE,
                   location,
                   'parameter substitutions')

    def generated_type(self, location=None):
        self.generated_types += 1
        self.check('max_generated_types',
                   self.generated_types,
                   EXPANSION_STAGE,
                   location,
                   'generated types')

    def expansion_depth(self, depth, location=None):
        if depth > self.expansion_depth_seen:
            self.expansion_depth_seen = depth

        self.check('max_expansion_depth',
                   depth,
                   EXPANSION_STAGE,
                   location,
                   'parameterized type expansion depth')

    def module_imports(self, count, location=None):
        self.check('max_module_imports',
                   count,
                   IMPORT_STAGE,
                   location,
                   'module imports')

    def as_dict(self):
        return {
            'max_module_imports': self.max_module_imports,
            'max_parameter_substitutions': self.max_parameter_substitutions,
            'max_generated_types': self.max_generated_types,
            'max_nodes': self.max_nodes,
            'max_expansion_depth': self.max_expansion_depth,
            'parameter_substitutions': self.parameter_substitutions,
            'generated_types': self.generated_types,
            'expansion_depth': self.expansion_depth_seen,
            'total_nodes': self.total_nodes
        }

    def __repr__(self):
        return 'CompileLimits({})'.format(
            ', '.join('{}={}'.format(key, value)
                      for key, value in sorted(self.as_dict().items())))


class LimitExceeded(CompileError):
    """Raised when a quota is exceeded. Kept as a :class:`CompileError`
    subclass so existing callers catching compile errors keep working.

    """

    def __init__(self, what, value, limit, stage, location=None):
        location_text = ''

        if location:
            location_text = ' at {}'.format(format_location(location))

        message = (
            '{} limit of {} exceeded ({} observed){} during stage '
            "'{}'.".format(what, limit, value, location_text, stage))
        super(LimitExceeded, self).__init__(message)
        self.what = what
        self.value = value
        self.limit = limit
        self.stage = stage
        self.location = location


class ParameterizationCycleError(CompileError):
    """Raised when expanding a parameterized type references itself
    without going through a named type reference.

    Legitimate recursive ASN.1 types keep a named reference after
    expansion and never trigger this error.

    """

    def __init__(self, type_name, chain, location=None):
        cycle = ' -> '.join(chain + [type_name])
        message = (
            "Circular parameterized type expansion detected: '{}'.".format(
                cycle))
        super(ParameterizationCycleError, self).__init__(message)
        self.type_name = type_name
        self.chain = list(chain)
        self.stage = EXPANSION_STAGE
        self.location = location


def format_location(location):
    """Format a schema location as a human readable string.

    Locations are dictionaries with optional ``module``, ``type`` and
    ``line`` keys.

    """
    if isinstance(location, str):
        return location

    parts = []

    if isinstance(location, dict):
        if location.get('module'):
            parts.append("module '{}'".format(location['module']))

        if location.get('type'):
            parts.append("type '{}'".format(location['type']))

        if location.get('line'):
            parts.append('line {}'.format(location['line']))

    return '/'.join(parts) if parts else str(location)
