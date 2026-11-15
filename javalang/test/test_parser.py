import unittest

from .. import parse, tree
from .. import parser, tokenizer


class RecursionBudgetTest(unittest.TestCase):
    """Maliciously deep input must fail with a positioned syntax error instead
    of crashing the host interpreter with a RecursionError."""

    def assert_depth_error(self, source):
        with self.assertRaises(parser.JavaSyntaxError) as ctx:
            parse.parse(source)
        error = ctx.exception
        self.assertIsNotNone(error.at)
        self.assertIsNotNone(error.at.position)
        self.assertEqual(len(error.at.position), 2)
        return error

    def test_deep_nested_generics_are_rejected(self):
        source = "class A { " + "A<" * 2000 + "A" + ">" * 2000 + " x; }"
        error = self.assert_depth_error(source)
        self.assertIsInstance(error, parser.JavaRecursionLimitError)
        self.assertIn("type nesting", error.description)

    def test_deep_type_arguments_via_parse_type(self):
        source = "A<" * 2000 + "A" + ">" * 2000
        with self.assertRaises(parser.JavaRecursionLimitError):
            parse.parse_type(source)

    def test_deep_array_dimension_chain_is_rejected(self):
        source = "class A { int " + "[]" * 2000 + " x; }"
        error = self.assert_depth_error(source)
        self.assertIn("Array declaration depth", error.description)

    def test_deep_parenthesized_expression_is_rejected(self):
        source = (
            "class A { void m() { int x = "
            + "(" * 2000 + "1" + ")" * 2000 + "; } }"
        )
        error = self.assert_depth_error(source)
        self.assertIsInstance(error, parser.JavaRecursionLimitError)

    def test_deep_assignment_chain_is_rejected(self):
        source = (
            "class A { void m() { int x = "
            + "1 = " * 2000 + "2" + "; } }"
        )
        error = self.assert_depth_error(source)
        self.assertIn("expression nesting", error.description)

    def test_deep_array_initializer_is_rejected(self):
        source = "class A { int[] x = {" + "{ " * 2000 + "1" + " }" * 2000 + "}; }"
        error = self.assert_depth_error(source)
        self.assertIn("expression nesting", error.description)

    def test_deep_nested_annotations_are_rejected(self):
        source = "class A { " + "@A(" * 2000 + "1" + ")" * 2000 + " int x; }"
        error = self.assert_depth_error(source)
        self.assertIn("annotation nesting", error.description)

    def test_deep_nested_class_declarations_are_rejected(self):
        source = (
            "class A { " + "class B { " * 2000
            + "int x;" + " }" * 2000 + " }"
        )
        error = self.assert_depth_error(source)
        self.assertIn("declaration nesting", error.description)

    def test_deep_nested_interfaces_are_rejected(self):
        source = (
            "class A { " + "interface I { " * 2000
            + "int X = 1;" + " }" * 2000 + " }"
        )
        error = self.assert_depth_error(source)
        self.assertIsInstance(error, parser.JavaRecursionLimitError)

    def test_deep_lambda_chain_is_rejected(self):
        source = (
            "class A { void m() { Runnable r = "
            + "() -> " * 2000 + "1; } }"
        )
        error = self.assert_depth_error(source)
        self.assertIsInstance(error, parser.JavaRecursionLimitError)

    def test_error_reports_token_line_and_column(self):
        source = "class A {\n    " + "A<" * 2000 + "A" + ">" * 2000 + " x;\n}"
        error = self.assert_depth_error(source)
        line, column = error.at.position
        self.assertEqual(line, 2)
        self.assertGreater(column, 0)

    def test_no_recursion_error_escapes(self):
        # The depth budget is calibrated to trip well before the host
        # interpreter reaches its default recursion limit, so every attack
        # shape surfaces as a syntax error rather than a RecursionError.
        sources = [
            "A<" * 2000 + "A" + ">" * 2000,
            "class A { int " + "[]" * 2000 + " x; }",
            "class A { void m(){ int x = " + "(" * 2000 + "1" + ")" * 2000 + "; } }",
            "class A { " + "class B { " * 2000 + "int x;" + " }" * 2000 + " }",
            "class A { " + "@A(" * 2000 + "1" + ")" * 2000 + " int x; }",
        ]
        for source in sources:
            with self.assertRaises(parser.JavaSyntaxError):
                parse.parse(source)

    def test_depth_failure_leaves_no_half_tree(self):
        source = "class A { " + "A<" * 2000 + "A" + ">" * 2000 + " x; }"
        result = "untouched"
        try:
            result = parse.parse(source)
        except parser.JavaSyntaxError:
            pass
        self.assertEqual(result, "untouched")

    def test_depth_counters_reset_after_failure(self):
        source = "class A { " + "A<" * 2000 + "A" + ">" * 2000 + " x; }"
        p = parser.Parser(tokenizer.tokenize(source))
        with self.assertRaises(parser.JavaSyntaxError):
            p.parse()
        self.assertEqual(p._parse_depth, 0)
        self.assertEqual(p._type_depth, 0)
        self.assertEqual(p._expression_depth, 0)
        self.assertEqual(p._annotation_depth, 0)
        self.assertEqual(p._declaration_depth, 0)

    def test_parser_instance_is_reusable_after_failure(self):
        bad = "class A { " + "A<" * 2000 + "A" + ">" * 2000 + " x; }"
        p = parser.Parser(tokenizer.tokenize(bad))
        with self.assertRaises(parser.JavaSyntaxError):
            p.parse()
        good = parser.Parser(tokenizer.tokenize("class A { int x; }"))
        unit = good.parse()
        self.assertEqual(len(unit.types), 1)

    def test_depth_error_is_a_syntax_error(self):
        self.assertTrue(issubclass(parser.JavaRecursionLimitError,
                               parser.JavaSyntaxError))


class DeepButValidSourceTest(unittest.TestCase):
    """Deep but in-budget sources keep their original AST shape."""

    def test_deep_generic_type_ast_is_preserved(self):
        depth = 40
        type_text = "Map<" * depth + "String" + ", String>" * depth
        unit = parse.parse("class A { %s x; }" % type_text)
        node = unit.types[0].fields[0].type
        observed = 0
        while node is not None:
            observed += 1
            if getattr(node, "arguments", None):
                node = node.arguments[0].type
            else:
                node = None
        self.assertEqual(observed, depth + 1)

    def test_long_array_chain_ast_is_preserved(self):
        unit = parse.parse("class A { int " + "[]" * 50 + " x; }")
        dimensions = unit.types[0].fields[0].type.dimensions
        self.assertEqual(len(dimensions), 50)

    def test_nested_parenthesized_expression_ast_is_preserved(self):
        expression = "(" * 30 + "1" + ")" * 30
        unit = parse.parse(
            "class A { void m() { int x = %s; } }" % expression)
        literals = [node for _, node in unit.filter(tree.Literal)]
        self.assertEqual(len(literals), 1)
        self.assertEqual(literals[0].value, "1")

    def test_nested_annotations_ast_is_preserved(self):
        source = "class A { " + "@Nest(" * 40 + "1" + ")" * 40 + " int x; }"
        unit = parse.parse(source)
        self.assertEqual(len(list(unit.filter(tree.Annotation))), 40)

    def test_nested_class_declarations_ast_is_preserved(self):
        source = (
            "class A { " + "class B { " * 30
            + "int x;" + " }" * 30 + " }"
        )
        unit = parse.parse(source)
        self.assertEqual(len(list(unit.filter(tree.ClassDeclaration))), 31)

    def test_nested_lambda_ast_is_preserved(self):
        source = "class A { void m() { Runnable r = " + "() -> " * 30 + "1; } }"
        unit = parse.parse(source)
        self.assertEqual(len(list(unit.filter(tree.LambdaExpression))), 30)

    def test_nested_array_initializer_ast_is_preserved(self):
        source = "class A { int[] x = " + "{ " * 40 + "1" + " }" * 40 + "; }"
        unit = parse.parse(source)
        self.assertEqual(len(list(unit.filter(tree.ArrayInitializer))), 40)

    def test_normal_source_still_parses(self):
        nl = chr(10)
        source = (
            "class Sample<T extends Number> {" + nl +
            "    @Override" + nl +
            "    public <R> R convert(java.util.Map<String, Integer> input) {" + nl +
            "        Runnable r = () -> { System.out.println(input); };" + nl +
            "        int[] values = new int[] {1, 2, 3};" + nl +
            "        return null;" + nl +
            "    }" + nl +
            "}"
        )
        unit = parse.parse(source)
        self.assertEqual(unit.types[0].name, "Sample")
        self.assertEqual(len(list(unit.filter(tree.LambdaExpression))), 1)
        self.assertEqual(len(list(unit.filter(tree.Annotation))), 1)

if __name__ == "__main__":
    unittest.main()
