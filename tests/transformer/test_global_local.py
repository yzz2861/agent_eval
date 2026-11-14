from RestrictedPython import compile_restricted_exec
from tests.helper import restricted_exec


GLOBAL_EXAMPLE = """
def x():
    global a
    a = 11
x()
"""


def test_Global():
    glb = {'a': None}
    restricted_exec(GLOBAL_EXAMPLE, glb)
    assert glb['a'] == 11


# Example from:
# https://www.smallsurething.com/a-quick-guide-to-nonlocal-in-python-3/
NONLOCAL_EXAMPLE = """
def outside():
    msg = "Outside!"
    def inside():
        nonlocal msg
        msg = "Inside!"
        print(msg)
    inside()
    print(msg)
outside()
"""


def test_Nonlocal():
    result = compile_restricted_exec(NONLOCAL_EXAMPLE)
    assert result.errors == (
        'Line 5, col 8: policy "RestrictingNodeTransformer" rejected node '
        'Nonlocal: this node type is explicitly forbidden and cannot be '
        'enabled',)
    assert result.code is None
