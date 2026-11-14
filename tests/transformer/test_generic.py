import ast

from RestrictedPython import RestrictingNodeTransformer


def test_RestrictingNodeTransformer__generic_visit__1():
    """It rejects unknown ast nodes through the explicit default policy."""
    class MyFancyNode(ast.AST):
        pass

    transformer = RestrictingNodeTransformer()
    transformer.visit(MyFancyNode())
    assert transformer.errors == [
        'Line None, col None: policy "RestrictingNodeTransformer" rejected '
        'node MyFancyNode: this node type is not known to '
        'RestrictedPython and has not passed a security review']
    assert transformer.warnings == [
        'Line None, col None: MyFancyNode statement is not known to policy '
        '"RestrictingNodeTransformer"']


def test_RestrictingNodeTransformer__generic_visit__policy_name():
    """Policy errors identify the policy which rejected the node."""
    class MyPolicy(RestrictingNodeTransformer):
        policy_name = 'MyCustomPolicy'

    class MyFancyNode(ast.AST):
        pass

    transformer = MyPolicy()
    transformer.visit(MyFancyNode())
    assert transformer.errors == [
        'Line None, col None: policy "MyCustomPolicy" rejected node '
        'MyFancyNode: this node type is not known to RestrictedPython and '
        'has not passed a security review']
