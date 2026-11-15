import unittest
from .. import tokenizer


class TestTokenizer(unittest.TestCase):

    def test_tokenizer_annotation(self):
        # Given
        code = "    @Override"

        # When
        tokens = list(tokenizer.tokenize(code))

        # Then
        self.assertEqual(len(tokens), 2)
        self.assertEqual(tokens[0].value, "@")
        self.assertEqual(tokens[1].value, "Override")
        self.assertEqual(type(tokens[0]), tokenizer.Annotation)
        self.assertEqual(type(tokens[1]), tokenizer.Identifier)

    def test_tokenizer_javadoc(self):
        # Given
        code = "/**\n" \
               " * See {@link BlockTokenSecretManager#setKeys(ExportedBlockKeys)}\n" \
               " */"

        # When
        tokens = list(tokenizer.tokenize(code))

        # Then
        self.assertEqual(len(tokens), 0)

    def test_tokenize_ignore_errors(self):
        # Given
        # character '#' was supposed to trigger an error of unknown token with a single line of javadoc
        code = " * See {@link BlockTokenSecretManager#setKeys(ExportedBlockKeys)}"

        # When
        tokens = list(tokenizer.tokenize(code, ignore_errors=True))

        # Then
        self.assertEqual(len(tokens), 11)

    def test_tokenize_line_comment_eof(self):
        # Given
        code = "  // This line comment at the end of the file has no newline"

        # When
        tokens = list(tokenizer.tokenize(code))

        # Then
        self.assertEqual(len(tokens), 0)

    def test_tokenize_comment_line_with_period(self):
        # Given
        code = "   * all of the servlets resistant to cross-site scripting attacks."

        # When
        tokens = list(tokenizer.tokenize(code))

        # Then
        self.assertEqual(len(tokens), 13)

    def test_tokenize_integer_at_end(self):
        # Given
        code = "nextKey = new BlockKey(serialNo, System.currentTimeMillis() + 3"

        # When
        tokens = list(tokenizer.tokenize(code, ignore_errors=True))

        # Then
        self.assertEqual(len(tokens), 14)

    def test_tokenize_float_at_end(self):
        # Given
        code = "nextKey = new BlockKey(serialNo, System.currentTimeMillis() + 3.0"

        # When
        tokens = list(tokenizer.tokenize(code, ignore_errors=True))

        # Then
        self.assertEqual(len(tokens), 14)

    def test_tokenize_hex_integer_at_end(self):
        # Given
        code = "nextKey = new BlockKey(serialNo, System.currentTimeMillis() + 0x3"

        # When
        tokens = list(tokenizer.tokenize(code, ignore_errors=True))

        # Then
        self.assertEqual(len(tokens), 14)

    def test_tokenize_token_position_after_comment(self):
        # Given
        code = """
public int function() {
    int a = 10;
    // some comment
    int b = 10;
}
        """

        # When
        tokens = list(tokenizer.tokenize(code))

        # Then
        # both token 6 and 11 are the "int" tokens of line 2 and 4
        self.assertEqual(tokens[6].position[1], 5)
        self.assertEqual(tokens[6].position[1], tokens[11].position[1])

    def test_tokenize_hex_float_integer_at_end(self):
        # Given
        code = "nextKey = new BlockKey(serialNo, System.currentTimeMillis() + 0x3.2p2"

        # When
        tokens = list(tokenizer.tokenize(code, ignore_errors=True))

        # Then
        self.assertEqual(len(tokens), 14)

    def test_string_delim_within_comment(self):

        # Given
        code = "* Returns 0 if it can't find the end \
                if (*itr == '\r') { \
                        int status;"

        # When
        tokens = list(tokenizer.tokenize(code, ignore_errors=True))

        # Then
        self.assertEqual(len(tokens), 8)

    def test_inline_comment_position(self):
        # Columns
        #                11111111112
        #       12345678901234567890
        code = "int /* comment */ j;"
        tokens = list(tokenizer.tokenize(code))

        int_token = tokens[0]
        j_token = tokens[1]
        semi_token = tokens[2]

        self.assertEqual(int_token.position.line, 1)
        self.assertEqual(int_token.position.column, 1)

        self.assertEqual(j_token.position.line, 1)
        self.assertEqual(j_token.position.column, 19)

        self.assertEqual(semi_token.position.line, 1)
        self.assertEqual(semi_token.position.column, 20)

    def test_multiline_inline_comment(self):
        code = """int /*
hello
world
*/ j;"""

        tokens = list(tokenizer.tokenize(code))
        token_int = tokens[0]
        token_j = tokens[1]

        self.assertEqual(token_int.position.line, 1)
        self.assertEqual(token_int.position.column, 1)

        self.assertEqual(token_j.position.line, 4)
        self.assertEqual(token_j.position.column, 4)

    def test_multiline_inline_comment_end_of_input(self):
        code = """int /*
hello
world
*/"""

        tokens = list(tokenizer.tokenize(code))
        token_int = tokens[0]

        self.assertEqual(token_int.position.line, 1)
        self.assertEqual(token_int.position.column, 1)

    def test_column_starts_at_one(self):
        code = """int j;
int k;
"""
        token = list(tokenizer.tokenize(code))
        self.assertEqual(token[0].position.column, 1)
        self.assertEqual(token[3].position.column, 1)

    def test_unicode_escape_positions_use_original_source(self):
        # \u0061 is six characters in the source but one character after
        # Unicode escape translation. The following token must still point at
        # its original column (10), not column 5 in the translated text.
        code = u"\\u0061bc int x;"

        tokens = list(tokenizer.tokenize(code))

        self.assertEqual(tokens[0].value, u"abc")
        self.assertEqual(tokens[0].position, tokenizer.Position(1, 1))
        self.assertEqual(tokens[1].value, u"int")
        self.assertEqual(tokens[1].position, tokenizer.Position(1, 10))

    def test_u2028_escape_does_not_shift_later_columns(self):
        # A Unicode escape is a single logical character, but its source
        # representation is six characters wide. Positions after it must use
        # the original source width. U+2028 is an invalid input character
        # outside literals/comments, so tokenization is continued with
        # ignore_errors.
        code = u"int a;\\u2028 int b;"
        lexer = tokenizer.JavaTokenizer(code, ignore_errors=True)

        tokens = list(lexer.tokenize())
        int_tokens = [t for t in tokens if t.value == u"int"]

        self.assertEqual([t.position for t in int_tokens],
                         [tokenizer.Position(1, 1),
                          tokenizer.Position(1, 14)])
        self.assertEqual(lexer.errors[0].position,
                         tokenizer.Position(1, 7))

    def test_split_unicode_escape_is_not_translated_twice(self):
        # The escape produces a backslash. The produced backslash must not
        # participate in another Unicode escape: u005a remains a literal
        # identifier suffix instead of becoming Z.
        code = u"\\u005cu005a"
        lexer = tokenizer.JavaTokenizer(code, ignore_errors=True)

        tokens = list(lexer.tokenize())
        identifiers = [t.value for t in tokens
                       if isinstance(t, tokenizer.Identifier)]

        self.assertEqual(identifiers, [u"u005a"])
        self.assertEqual(len(lexer.errors), 1)

    def test_escaped_backslash_does_not_start_unicode_escape(self):
        # Two raw backslashes are a legal escaped backslash in a string; the
        # second one is not eligible to start a Unicode escape.
        code = u"\"\\\\u005a\""

        tokens = list(tokenizer.tokenize(code))

        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0].value, u"\"\\\\u005a\"")
        self.assertEqual(tokens[0].position, tokenizer.Position(1, 1))

    def test_invalid_unicode_escape_reports_location_and_recovers(self):
        code = u"class A {\n    \\u12\n    int ok;\n}"
        lexer = tokenizer.JavaTokenizer(code, ignore_errors=True)

        tokens = list(lexer.tokenize())
        int_token = [t for t in tokens
                     if isinstance(t, tokenizer.BasicType)
                     and t.value == u"int"][0]

        self.assertEqual(int_token.position, tokenizer.Position(3, 5))
        self.assertEqual(len(lexer.errors), 1)
        self.assertEqual(lexer.errors[0].position,
                         tokenizer.Position(2, 9))
        self.assertEqual(lexer.errors[0].token_position,
                         tokenizer.Position(2, 5))

    def test_unterminated_block_comment_reports_and_recovers(self):
        code = u"int a; /* unterminated\nint b;\n"
        lexer = tokenizer.JavaTokenizer(code, ignore_errors=True)

        tokens = list(lexer.tokenize())
        int_tokens = [t for t in tokens if t.value == u"int"]

        self.assertEqual([t.position for t in int_tokens],
                         [tokenizer.Position(1, 1),
                          tokenizer.Position(2, 1)])
        self.assertEqual(len(lexer.errors), 1)
        self.assertEqual(lexer.errors[0].position,
                         tokenizer.Position(1, 8))
        self.assertEqual(lexer.errors[0].token_position,
                         tokenizer.Position(1, 8))

    def test_crlf_and_cr_are_single_line_terminators(self):
        code = u"int a;\r\nint b;\rint c;\nint d;"

        tokens = list(tokenizer.tokenize(code))
        int_tokens = [t for t in tokens if t.value == u"int"]

        self.assertEqual([t.position for t in int_tokens],
                         [tokenizer.Position(1, 1),
                          tokenizer.Position(2, 1),
                          tokenizer.Position(3, 1),
                          tokenizer.Position(4, 1)])

    def test_line_comment_ends_at_carriage_return(self):
        code = u"// comment\rint x;"

        tokens = list(tokenizer.tokenize(code))
        int_tokens = [t for t in tokens if t.value == u"int"]

        self.assertEqual(int_tokens[0].position, tokenizer.Position(2, 1))

    def test_leading_bom_is_ignored_for_positions(self):
        for code in (u"\ufeffint x;", b"\xef\xbb\xbfint x;"):
            tokens = list(tokenizer.tokenize(code))
            self.assertEqual(tokens[0].position, tokenizer.Position(1, 1))
            self.assertEqual(tokens[1].position, tokenizer.Position(1, 5))

    def test_token_position_after_very_long_line(self):
        code = u" " * 100000 + u"int x;"

        tokens = list(tokenizer.tokenize(code))

        self.assertEqual(tokens[0].position, tokenizer.Position(1, 100001))
        self.assertEqual(tokens[1].position, tokenizer.Position(1, 100005))

    def test_token_position_after_very_long_comment(self):
        code = u"/*" + u"x" * 100000 + u"*/\nint x;"

        tokens = list(tokenizer.tokenize(code))
        int_token = [t for t in tokens if t.value == u"int"][0]

        self.assertEqual(int_token.position, tokenizer.Position(2, 1))

if __name__=="__main__":
    unittest.main()
