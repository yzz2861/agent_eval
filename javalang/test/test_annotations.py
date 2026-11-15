import unittest

from .. import ast as ast_accessors
from .. import ast, parse, parser, tree


ANNOTATION_DECLARATION = """
@interface MyAnno {
    String value() default "default";
    int count() default 0;
    String[] tags() default {};
    Class<? extends Number> type() default Integer.class;
    Nested nested() default @Nested(x = 1);

    @interface Nested {
        int x() default 0;
    }
}
"""


USAGE_SOURCE = """
@Deprecated
@Single("v")
@Normal(value = "n")
public class Use {
    @FieldAnno
    private String name;

    @MethodAnno
    public void run(@ParamAnno int x) {
    }
}
"""

REPEATED_SOURCE = """
public class Repeat {
    @Tag("a") @Tag("b")
    private int value;
}
"""

ARRAY_SOURCE = """
public class WithArray {
    @Anno(tags = {"a", "b", "c"})
    private int value;
}
"""

NESTED_SOURCE = """
public class WithNested {
    @Outer(inner = @Inner(x = 1), list = { @A, @B(2) })
    private int value;
}
"""

UNKNOWN_SOURCE = """
@CompletelyUnknown
public class Unknown {
}
"""


def parse_types(source):
    return parse.parse(source).types


class AnnotationDeclarationTest(unittest.TestCase):
    def test_annotation_declaration_is_distinct_node(self):
        decl = parse_types(ANNOTATION_DECLARATION)[0]
        self.assertIsInstance(decl, tree.AnnotationDeclaration)
        self.assertNotIsInstance(decl, tree.Annotation)
        self.assertEqual(decl.name, "MyAnno")

    def test_annotation_methods_keep_default_values(self):
        decl = parse_types(ANNOTATION_DECLARATION)[0]
        methods = {m.name: m for m in decl.body
                   if isinstance(m, tree.AnnotationMethod)}
        self.assertEqual(methods["value"].return_type.name, "String")
        self.assertEqual(methods["value"].default.value,
                         '"default"')
        self.assertEqual(ast_accessors.annotation_default(methods["count"]).value, "0")
        self.assertTrue(ast.is_array_value(methods["tags"].default))
        self.assertIsInstance(methods["nested"].default, tree.Annotation)

    def test_nested_annotation_declaration(self):
        decl = parse_types(ANNOTATION_DECLARATION)[0]
        nested = [d for d in decl.body
                  if isinstance(d, tree.AnnotationDeclaration)]
        self.assertEqual(len(nested), 1)
        self.assertEqual(nested[0].name, "Nested")


class AnnotationUsageTest(unittest.TestCase):

    def test_marker_single_and_normal_annotations(self):
        cu = parse.parse(USAGE_SOURCE)
        clazz = cu.types[0]
        annotations = clazz.annotations

        self.assertEqual(len(annotations), 3)
        self.assertIsInstance(annotations[0], tree.MarkerAnnotation)
        self.assertIsInstance(annotations[1], tree.SingleElementAnnotation)
        self.assertIsInstance(annotations[2], tree.NormalAnnotation)
        self.assertTrue(all(isinstance(a, tree.Annotation) for a in annotations))

        self.assertEqual(annotations[0].name, "Deprecated")
        self.assertIsNone(annotations[0].element)

        self.assertEqual(annotations[1].name, "Single")
        self.assertEqual(ast_accessors.annotation_value(annotations[1]).value, '"v"')

        normal = annotations[2]
        self.assertEqual(normal.name, "Normal")
        pair = normal.element[0]
        self.assertEqual(pair.name, "value")
        self.assertEqual(pair.value.value, '"n"')

    def test_field_method_parameter_annotations(self):
        cu = parse.parse(USAGE_SOURCE)
        clazz = cu.types[0]
        field = clazz.fields[0]
        self.assertEqual(field.annotations[0].name, "FieldAnno")

        method = clazz.methods[0]
        self.assertEqual(method.annotations[0].name, "MethodAnno")
        parameter = method.parameters[0]
        self.assertEqual(parameter.annotations[0].name, "ParamAnno")

    def test_unknown_annotation_is_node_not_string(self):
        cu = parse.parse(UNKNOWN_SOURCE)
        clazz = cu.types[0]
        annotation = clazz.annotations[0]
        self.assertIsInstance(annotation, tree.Annotation)
        self.assertEqual(annotation.name, "CompletelyUnknown")
        for path, node in cu:
            self.assertNotIsInstance(node, str)


class RepeatedAnnotationTest(unittest.TestCase):

    def test_repeated_annotations_kept_in_order(self):
        cu = parse.parse(REPEATED_SOURCE)
        annotations = cu.types[0].fields[0].annotations
        self.assertEqual(len(annotations), 2)
        names = [a.name for a in annotations]
        self.assertEqual(names, ["Tag", "Tag"])
        self.assertEqual(annotations[0].element.value, '"a"')
        self.assertEqual(annotations[1].element.value, '"b"')
        for annotation in annotations:
            self.assertIsInstance(annotation, tree.SingleElementAnnotation)

    def test_repeated_annotation_token_ranges_distinct(self):
        cu = parse.parse(REPEATED_SOURCE)
        ranges = [ast_accessors.annotation_token_range(a)
                  for a in cu.types[0].fields[0].annotations]
        self.assertEqual(ranges[0][0], (3, 5))
        self.assertEqual(ranges[1][0], (3, 15))
        self.assertNotEqual(ranges[0][1], ranges[1][0])

    def test_mixed_repeated_and_other_annotation(self):
        source = "class C {  @Tag(1) @Tag(2) @Other int x; }"
        cu = parse.parse(source)
        field = cu.types[0].fields[0]
        self.assertEqual(len(field.annotations), 3)
        self.assertEqual([a.name for a in field.annotations],
                         ["Tag", "Tag", "Other"])
        self.assertIsInstance(field.annotations[2], tree.MarkerAnnotation)


class ArrayValueTest(unittest.TestCase):

    def test_array_value_modeled_as_element_array_value(self):
        cu = parse.parse(ARRAY_SOURCE)
        annotation = cu.types[0].fields[0].annotations[0]
        pair = annotation.element[0]
        self.assertEqual(pair.name, "tags")
        array_value = pair.value
        self.assertIsInstance(array_value, tree.ElementArrayValue)
        self.assertEqual([v.value for v in array_value.values],
                         ['"a"', '"b"', '"c"'])
        self.assertEqual(ast_accessors.annotation_array_values(annotation, "tags"),
                         array_value.values)

    def test_empty_array_value(self):
        source = "class C { @Anno(tags = {}) int x; }"
        cu = parse.parse(source)
        annotation = cu.types[0].fields[0].annotations[0]
        array_value = annotation.element[0].value
        self.assertIsInstance(array_value, tree.ElementArrayValue)
        self.assertEqual(array_value.values, [])

    def test_nested_array_value(self):
        source = "class C { @Anno(v = { @N(1), @N(2) }) int x; }"
        cu = parse.parse(source)
        annotation = cu.types[0].fields[0].annotations[0]
        array_value = annotation.element[0].value
        self.assertEqual(len(array_value.values), 2)
        self.assertTrue(all(isinstance(v, tree.Annotation)
                            for v in array_value.values))


class NestedAnnotationTest(unittest.TestCase):

    def test_nested_annotation_is_kept_as_node(self):
        cu = parse.parse(NESTED_SOURCE)
        outer = cu.types[0].fields[0].annotations[0]
        inner = ast_accessors.annotation_value(outer, "inner")
        self.assertIsInstance(inner, tree.NormalAnnotation)
        self.assertEqual(inner.name, "Inner")
        self.assertEqual(inner.element[0].value.value, "1")
        self.assertEqual(ast_accessors.annotation_name(inner), "Inner")

    def test_array_of_annotations_accessor(self):
        cu = parse.parse(NESTED_SOURCE)
        outer = cu.types[0].fields[0].annotations[0]
        values = ast_accessors.annotation_value(outer, "list")
        self.assertIsInstance(values, tree.ElementArrayValue)
        self.assertEqual([a.name for a in values.values], ["A", "B"])


class ErrorReportingTest(unittest.TestCase):

    def test_error_names_annotation_and_token_range(self):
        source = "class C { @Broken( value = ) int x; }"
        with self.assertRaises(parser.JavaSyntaxError) as context:
            parse.parse(source)
        error = context.exception
        self.assertIn("Broken", error.description)
        self.assertIn("line 1", error.description)
        self.assertIn("column 28", error.description)
        self.assertEqual(error.at.value, ")")

    def test_missing_annotation_name_reports_error(self):
        source = "class C { @ int x; }"
        with self.assertRaises(parser.JavaSyntaxError) as context:
            parse.parse(source)
        self.assertIn("annotation", context.exception.description.lower())

    def test_annotation_position_and_range(self):
        cu = parse.parse(USAGE_SOURCE)
        annotation = cu.types[0].annotations[1]
        self.assertEqual(annotation.position, (3, 1))
        token_range = ast_accessors.annotation_token_range(annotation)
        self.assertEqual(token_range[0], (3, 1))
        self.assertEqual(token_range[1], (3, 12))

    def test_declaration_has_no_token_range_but_has_position(self):
        decl = parse_types(ANNOTATION_DECLARATION)[0]
        self.assertIsInstance(decl, tree.AnnotationDeclaration)
        self.assertEqual(decl.position, (2, 1))
        self.assertFalse(ast_accessors.is_annotation_usage(decl))


def main():
    unittest.main()


if __name__ == "__main__":
    main()
