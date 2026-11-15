import re
import sys
import unittest

sys.path.insert(0, "..")
from pycparser.c_lexer import CLexer, SourceLocation, Token


def require_token(tok: Token | None) -> Token:
    # In tests we know token() should produce a token here; this helper asserts
    # that and narrows Optional[Token] to Token, avoiding repeated casts/guards.
    assert tok is not None
    return tok


def token_list(clex):
    return list(iter(clex.token, None))


def token_types(clex):
    return [i.type for i in token_list(clex)]


class TestCLexerNoErrors(unittest.TestCase):
    """Test lexing of strings that are not supposed to cause
    errors. Therefore, the error_func passed to the lexer
    raises an exception.
    """

    def error_func(self, msg, line, column):
        self.fail(msg)

    def setUp(self):
        self.clex = CLexer(self.error_func)

    def assertTokensTypes(self, str, types):
        self.clex.input(str)
        self.assertEqual(token_types(self.clex), types)

    def test_trivial_tokens(self):
        self.assertTokensTypes("1", ["INT_CONST_DEC"])
        self.assertTokensTypes("-", ["MINUS"])
        self.assertTokensTypes("volatile", ["VOLATILE"])
        self.assertTokensTypes("...", ["ELLIPSIS"])
        self.assertTokensTypes("++", ["PLUSPLUS"])
        self.assertTokensTypes("case int", ["CASE", "INT"])
        self.assertTokensTypes("caseint", ["ID"])
        self.assertTokensTypes("$dollar cent$", ["ID", "ID"])
        self.assertTokensTypes("i ^= 1;", ["ID", "XOREQUAL", "INT_CONST_DEC", "SEMI"])

    def test_form_feed_and_vertical_tab_whitespace(self):
        self.clex.input("\fint\vx;\n \t\f\vy;")
        self.assertEqual(
            [(t.type, t.value, t.lineno, t.column) for t in token_list(self.clex)],
            [
                ("INT", "int", 1, 2),
                ("ID", "x", 1, 6),
                ("SEMI", ";", 1, 7),
                ("ID", "y", 2, 5),
                ("SEMI", ";", 2, 6),
            ],
        )
        self.assertTokensTypes(" \t\f\v", [])

    def test_form_feed_and_vertical_tab_in_literals(self):
        self.clex.input("\"a\fb\" '\v'")
        self.assertEqual(
            [(t.type, t.value, t.lineno, t.column) for t in token_list(self.clex)],
            [
                ("STRING_LITERAL", '"a\fb"', 1, 1),
                ("CHAR_CONST", "'\v'", 1, 7),
            ],
        )

    def test_typedef_names_are_identifiers(self):
        self.assertTokensTypes(
            "typedef int T; T value;",
            ["TYPEDEF", "INT", "ID", "SEMI", "ID", "ID", "SEMI"],
        )

    def test_token_filenames(self):
        self.clex.input(
            'int a;\n#line 7 "included.h"\n#pragma once\n#line 1 ""\nint b;',
            filename="main.c",
        )
        tokens = token_list(self.clex)
        self.assertEqual(
            [tok.filename for tok in tokens],
            ["main.c"] * 3 + ["included.h"] * 2 + [""] * 3,
        )
        self.assertEqual(tokens[3].type, "PPPRAGMA")
        self.assertEqual(tokens[4].type, "PPPRAGMASTR")
        self.assertIs(tokens[3].filename, tokens[4].filename)

        self.clex.input("int c;", filename="next.c")
        self.assertEqual(require_token(self.clex.token()).filename, "next.c")
        self.assertEqual(tokens[0].filename, "main.c")

    def test_integer_constants(self):
        self.assertTokensTypes("12", ["INT_CONST_DEC"])
        self.assertTokensTypes("12u", ["INT_CONST_DEC"])
        self.assertTokensTypes("12l", ["INT_CONST_DEC"])
        self.assertTokensTypes("199872Ul", ["INT_CONST_DEC"])
        self.assertTokensTypes("199872lU", ["INT_CONST_DEC"])
        self.assertTokensTypes("199872LL", ["INT_CONST_DEC"])
        self.assertTokensTypes("199872ull", ["INT_CONST_DEC"])
        self.assertTokensTypes("199872llu", ["INT_CONST_DEC"])
        self.assertTokensTypes("1009843200000uLL", ["INT_CONST_DEC"])
        self.assertTokensTypes("1009843200000LLu", ["INT_CONST_DEC"])

        self.assertTokensTypes("077", ["INT_CONST_OCT"])
        self.assertTokensTypes("0123456L", ["INT_CONST_OCT"])

        self.assertTokensTypes("0xf7", ["INT_CONST_HEX"])
        self.assertTokensTypes("0b110", ["INT_CONST_BIN"])
        self.assertTokensTypes("0x01202AAbbf7Ul", ["INT_CONST_HEX"])
        self.assertTokensTypes("'12'", ["INT_CONST_CHAR"])
        self.assertTokensTypes("'123'", ["INT_CONST_CHAR"])
        self.assertTokensTypes("'1AB4'", ["INT_CONST_CHAR"])
        self.assertTokensTypes(r"'1A\n4'", ["INT_CONST_CHAR"])

        # no 0 before x, so ID catches it
        self.assertTokensTypes("xf7", ["ID"])

        # - is MINUS, the rest a constnant
        self.assertTokensTypes("-1", ["MINUS", "INT_CONST_DEC"])

    def test_integer_digit_separators(self):
        self.assertTokensTypes("1'000'000", ["INT_CONST_DEC"])
        self.assertTokensTypes("0'7'7", ["INT_CONST_OCT"])
        self.assertTokensTypes("0xAB'CD", ["INT_CONST_HEX"])
        self.assertTokensTypes("0B1010'0101", ["INT_CONST_BIN"])
        self.assertTokensTypes("1'000uLL", ["INT_CONST_DEC"])
        self.assertTokensTypes("0XFF'FFwbU", ["INT_CONST_HEX"])

        self.clex.input("1'000+2'000\n0xAB'CD")
        self.assertEqual(
            token_list(self.clex),
            [
                Token("INT_CONST_DEC", "1'000", 1, 1, filename=""),
                Token("PLUS", "+", 1, 6, filename=""),
                Token("INT_CONST_DEC", "2'000", 1, 7, filename=""),
                Token("INT_CONST_HEX", "0xAB'CD", 2, 1, filename=""),
            ],
        )

    def test_floating_digit_separators(self):
        self.assertTokensTypes("1'234.56'78", ["FLOAT_CONST"])
        self.assertTokensTypes(".1'25", ["FLOAT_CONST"])
        self.assertTokensTypes("1'000.", ["FLOAT_CONST"])
        self.assertTokensTypes("1'2e+3'4", ["FLOAT_CONST"])
        self.assertTokensTypes("0'8.0", ["FLOAT_CONST"])
        self.assertTokensTypes("0xAB'CD.EF'01p+1'0", ["HEX_FLOAT_CONST"])
        self.assertTokensTypes("0x.A'Bp-1'0", ["HEX_FLOAT_CONST"])
        self.assertTokensTypes("0xA'B.p1'0", ["HEX_FLOAT_CONST"])
        self.assertTokensTypes("0xA'Bp1'0", ["HEX_FLOAT_CONST"])

        self.clex.input("1'2.3'4e-5'6DF")
        self.assertEqual(
            token_list(self.clex),
            [
                Token("FLOAT_CONST", "1'2.3'4e-5'6DF", 1, 1, filename=""),
            ],
        )

    def test_digit_separators_and_quotes(self):
        self.clex.input("'1'2 1'2 \"1'2\"")
        self.assertEqual(
            token_list(self.clex),
            [
                Token("CHAR_CONST", "'1'", 1, 1, filename=""),
                Token("INT_CONST_DEC", "2", 1, 4, filename=""),
                Token("INT_CONST_DEC", "1'2", 1, 6, filename=""),
                Token("STRING_LITERAL", '"1\'2"', 1, 10, filename=""),
            ],
        )

    def test_line_directive_digit_separators(self):
        self.clex.input('#line 1' + chr(39) + '000 "file.c"\nvalue')
        token = require_token(self.clex.token())
        self.assertEqual(token.type, "ID")
        self.assertEqual(token.value, "value")
        # Logical position follows the #line remap; physical position
        # still points at line 2 of the text actually being scanned.
        self.assertEqual(
            token.logical,
            SourceLocation(filename="file.c", lineno=1000, column=1),
        )
        self.assertEqual(
            token.physical,
            SourceLocation(filename="", lineno=2, column=1),
        )
        self.assertEqual(self.clex.filename, "file.c")

        self.clex.input("#line 0'010\nvalue")
        token = require_token(self.clex.token())
        self.assertEqual(token.lineno, 10)
        self.assertEqual(token.filename, "")
        self.assertEqual(token.physical, SourceLocation("", 2, 1))

    def test_bitint_constants(self):
        # Numeric regexes are shared, so even the legacy lexer recognizes
        # these suffixes. The parser enforces C23.
        self.assertTokensTypes("42wb", ["INT_CONST_DEC"])
        self.assertTokensTypes("42WB", ["INT_CONST_DEC"])
        self.assertTokensTypes("42uwb", ["INT_CONST_DEC"])
        self.assertTokensTypes("42uWB", ["INT_CONST_DEC"])
        self.assertTokensTypes("42Uwb", ["INT_CONST_DEC"])
        self.assertTokensTypes("42UWB", ["INT_CONST_DEC"])
        self.assertTokensTypes("42wbu", ["INT_CONST_DEC"])
        self.assertTokensTypes("42wbU", ["INT_CONST_DEC"])
        self.assertTokensTypes("42WBu", ["INT_CONST_DEC"])
        self.assertTokensTypes("42WBU", ["INT_CONST_DEC"])
        self.assertTokensTypes("0wb", ["INT_CONST_OCT"])
        self.assertTokensTypes("077uwb", ["INT_CONST_OCT"])
        self.assertTokensTypes("0XffWB", ["INT_CONST_HEX"])
        self.assertTokensTypes("0b101wbu", ["INT_CONST_BIN"])

        self.clex.input("42wb+0xffUWB")
        self.assertEqual(
            token_list(self.clex),
            [
                Token("INT_CONST_DEC", "42wb", 1, 1, filename=""),
                Token("PLUS", "+", 1, 5, filename=""),
                Token("INT_CONST_HEX", "0xffUWB", 1, 6, filename=""),
            ],
        )

    def test_special_names(self):
        self.assertTokensTypes("sizeof offsetof", ["SIZEOF", "OFFSETOF"])

    def test_new_keywords(self):
        self.assertTokensTypes("_Bool", ["_BOOL"])
        self.assertTokensTypes("_Atomic", ["_ATOMIC"])
        self.assertTokensTypes("_Alignas _Alignof", ["_ALIGNAS", "_ALIGNOF"])
        self.assertTokensTypes("_Generic", ["_GENERIC"])
        self.assertTokensTypes("_Generic_value _generic", ["ID", "ID"])

    def test_c23_keywords(self):
        source = (
            "bool alignas alignof static_assert thread_local true false nullptr "
            "constexpr typeof typeof_unqual _BitInt _Decimal32 _Decimal64 "
            "_Decimal128 _Imaginary bool_value True nullptr_t"
        )
        c23 = CLexer(self.error_func, dialect="c23")
        expected = [
            "_BOOL",
            "_ALIGNAS",
            "_ALIGNOF",
            "_STATIC_ASSERT",
            "_THREAD_LOCAL",
            "BOOL_CONST",
            "BOOL_CONST",
            "NULLPTR",
            "CONSTEXPR",
            "TYPEOF",
            "TYPEOF_UNQUAL",
            "_BITINT",
            "_DECIMAL32",
            "_DECIMAL64",
            "_DECIMAL128",
            "_IMAGINARY",
            "ID",
            "ID",
            "ID",
        ]
        # input() must preserve the dialect, and selecting it must not affect
        # another lexer's keyword map.
        for _ in range(2):
            self.assertTokensTypes(source, ["ID"] * len(source.split()))
            c23.input(source)
            tokens = token_list(c23)
            self.assertEqual([tok.type for tok in tokens], expected)
            self.assertEqual([tok.value for tok in tokens], source.split())

    def test_invalid_dialect(self):
        with self.assertRaisesRegex(ValueError, "Unknown dialect"):
            CLexer(
                self.error_func,
                dialect="c99",  # ty: ignore[invalid-argument-type]
            )

    def test_floating_constants(self):
        self.assertTokensTypes("1.5f", ["FLOAT_CONST"])
        self.assertTokensTypes("01.5", ["FLOAT_CONST"])
        self.assertTokensTypes(".15L", ["FLOAT_CONST"])
        self.assertTokensTypes("0.", ["FLOAT_CONST"])

        # but just a period is a period
        self.assertTokensTypes(".", ["PERIOD"])

        self.assertTokensTypes("3.3e-3", ["FLOAT_CONST"])
        self.assertTokensTypes(".7e25L", ["FLOAT_CONST"])
        self.assertTokensTypes("6.e+125f", ["FLOAT_CONST"])
        self.assertTokensTypes("666e666", ["FLOAT_CONST"])
        self.assertTokensTypes("00666e+3", ["FLOAT_CONST"])

        # but this is a hex integer + 3
        self.assertTokensTypes("0x0666e+3", ["INT_CONST_HEX", "PLUS", "INT_CONST_DEC"])

    def test_c23_decimal_floating_constants(self):
        c23 = CLexer(self.error_func, dialect="c23")
        c23.input("1.25df\n2.50dd\n.3dl\n4e+2DF\n5e-1DD\n6.DL")
        self.assertEqual(
            token_list(c23),
            [
                Token("FLOAT_CONST", "1.25df", 1, 1, filename=""),
                Token("FLOAT_CONST", "2.50dd", 2, 1, filename=""),
                Token("FLOAT_CONST", ".3dl", 3, 1, filename=""),
                Token("FLOAT_CONST", "4e+2DF", 4, 1, filename=""),
                Token("FLOAT_CONST", "5e-1DD", 5, 1, filename=""),
                Token("FLOAT_CONST", "6.DL", 6, 1, filename=""),
            ],
        )

        c23.input("1.25df+2.50dd")
        self.assertEqual(
            token_list(c23),
            [
                Token("FLOAT_CONST", "1.25df", 1, 1, filename=""),
                Token("PLUS", "+", 1, 7, filename=""),
                Token("FLOAT_CONST", "2.50dd", 1, 8, filename=""),
            ],
        )

    def test_decimal_literals_in_legacy_lexer(self):
        # Literal recognition is shared; the parser enforces the dialect.
        self.clex.input("1.25df 2.dd 3e1DL")
        self.assertEqual(
            token_list(self.clex),
            [
                Token("FLOAT_CONST", "1.25df", 1, 1, filename=""),
                Token("FLOAT_CONST", "2.dd", 1, 8, filename=""),
                Token("FLOAT_CONST", "3e1DL", 1, 13, filename=""),
            ],
        )

        self.clex.input(".5DD")
        self.assertEqual(
            token_list(self.clex), [Token("FLOAT_CONST", ".5DD", 1, 1, filename="")]
        )

    def test_c23_binary_floating_constants(self):
        c23 = CLexer(self.error_func, dialect="c23")
        c23.input("1.5\n1.5f\n.5L\n0x1.fp+2F\n0x1p0dd")
        self.assertEqual(
            token_list(c23),
            [
                Token("FLOAT_CONST", "1.5", 1, 1, filename=""),
                Token("FLOAT_CONST", "1.5f", 2, 1, filename=""),
                Token("FLOAT_CONST", ".5L", 3, 1, filename=""),
                Token("HEX_FLOAT_CONST", "0x1.fp+2F", 4, 1, filename=""),
                Token("HEX_FLOAT_CONST", "0x1p0", 5, 1, filename=""),
                Token("ID", "dd", 5, 6, filename=""),
            ],
        )

    def test_hexadecimal_floating_constants(self):
        self.assertTokensTypes("0xDE.488641p0", ["HEX_FLOAT_CONST"])
        self.assertTokensTypes("0x.488641p0", ["HEX_FLOAT_CONST"])
        self.assertTokensTypes("0X12.P0", ["HEX_FLOAT_CONST"])

    def test_char_constants(self):
        self.assertTokensTypes(r"""'x'""", ["CHAR_CONST"])
        self.assertTokensTypes(r"""L'x'""", ["WCHAR_CONST"])
        self.assertTokensTypes(r"""u8'x'""", ["U8CHAR_CONST"])
        self.assertTokensTypes(r"""u'x'""", ["U16CHAR_CONST"])
        self.assertTokensTypes(r"""U'x'""", ["U32CHAR_CONST"])
        self.assertTokensTypes(r"""'\t'""", ["CHAR_CONST"])
        self.assertTokensTypes(r"""'\''""", ["CHAR_CONST"])
        self.assertTokensTypes(r"""'\?'""", ["CHAR_CONST"])
        self.assertTokensTypes(r"""'\0'""", ["CHAR_CONST"])
        self.assertTokensTypes(r"""'\012'""", ["CHAR_CONST"])
        self.assertTokensTypes(r"""'\x2f'""", ["CHAR_CONST"])
        self.assertTokensTypes(r"""'\x2f12'""", ["CHAR_CONST"])
        self.assertTokensTypes(r"""L'\xaf'""", ["WCHAR_CONST"])

    def test_unicode_char_constants(self):
        for prefix, token_type in (
            ("", "CHAR_CONST"),
            ("L", "WCHAR_CONST"),
            ("u8", "U8CHAR_CONST"),
            ("u", "U16CHAR_CONST"),
            ("U", "U32CHAR_CONST"),
        ):
            for escape in (r"\u00e9", r"\u03A9", r"\U000000E9", r"\U0001F600"):
                literal = f"{prefix}'{escape}'"
                with self.subTest(literal=literal):
                    self.clex.input(f"\n  {literal};")
                    self.assertEqual(
                        token_list(self.clex),
                        [
                            Token(token_type, literal, 2, 3, filename=""),
                            Token("SEMI", ";", 2, 3 + len(literal), filename=""),
                        ],
                    )

    def test_unicode_multicharacter_constants(self):
        # Unicode escapes have fixed width: a following hex digit is a separate
        # character, unlike the variable-width hexadecimal escape \x.
        for literal in (
            r"'\u00e9a'",
            r"'\U0001F6000'",
            r"'a\u00e9'",
            r"'\u00e9\U0001F600'",
            r"'\u00e9\u00f1\u03a9\u03b1'",
        ):
            with self.subTest(literal=literal):
                self.assertTokensTypes(literal, ["INT_CONST_CHAR"])
        # Keep the lexer's existing permissiveness for other escape spellings.
        self.assertTokensTypes(
            r"'\u' '\U' '\u123'", ["CHAR_CONST", "CHAR_CONST", "INT_CONST_CHAR"]
        )

    def test_string_literal(self):
        self.assertTokensTypes('"a string"', ["STRING_LITERAL"])
        self.assertTokensTypes('L"ing"', ["WSTRING_LITERAL"])
        self.assertTokensTypes('u8"ing"', ["U8STRING_LITERAL"])
        self.assertTokensTypes('u"ing"', ["U16STRING_LITERAL"])
        self.assertTokensTypes('U"ing"', ["U32STRING_LITERAL"])
        self.assertTokensTypes('"i am a string too \t"', ["STRING_LITERAL"])
        self.assertTokensTypes(
            r'''"esc\ape \"\'\? \0234 chars \rule"''', ["STRING_LITERAL"]
        )
        self.assertTokensTypes(
            r'''"hello 'joe' wanna give it a \"go\"?"''', ["STRING_LITERAL"]
        )
        self.assertTokensTypes(
            '"\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123"',
            ["STRING_LITERAL"],
        )
        # Note: a-zA-Z and '.-~^_!=&;,' are allowed as escape chars to support #line
        # directives with Windows paths as filenames (..\..\dir\file)
        self.assertTokensTypes(r'"\x"', ["STRING_LITERAL"])
        self.assertTokensTypes(
            r'"\a\b\c\d\e\f\g\h\i\j\k\l\m\n\o\p\q\r\s\t\u\v\w\x\y\z\A\B\C\D\E\F\G\H\I\J\K\L\M\N\O\P\Q\R\S\T\U\V\W\X\Y\Z"',
            ["STRING_LITERAL"],
        )
        self.assertTokensTypes(r'"C:\x\fa\x1e\xited"', ["STRING_LITERAL"])
        # The lexer is permissive and allows decimal escapes (not just octal)
        self.assertTokensTypes(r'"jx\9"', ["STRING_LITERAL"])
        self.assertTokensTypes(r'"fo\9999999"', ["STRING_LITERAL"])

    def test_mess(self):
        self.assertTokensTypes(
            r"[{}]()", ["LBRACKET", "LBRACE", "RBRACE", "RBRACKET", "LPAREN", "RPAREN"]
        )

        self.assertTokensTypes(
            r"()||!C&~Z?J",
            [
                "LPAREN",
                "RPAREN",
                "LOR",
                "LNOT",
                "ID",
                "AND",
                "NOT",
                "ID",
                "CONDOP",
                "ID",
            ],
        )

        self.assertTokensTypes(
            r"+-*/%|||&&&^><>=<===!=",
            [
                "PLUS",
                "MINUS",
                "TIMES",
                "DIVIDE",
                "MOD",
                "LOR",
                "OR",
                "LAND",
                "AND",
                "XOR",
                "GT",
                "LT",
                "GE",
                "LE",
                "EQ",
                "NE",
            ],
        )

        self.assertTokensTypes(
            r"++--->?.,;:",
            [
                "PLUSPLUS",
                "MINUSMINUS",
                "ARROW",
                "CONDOP",
                "PERIOD",
                "COMMA",
                "SEMI",
                "COLON",
            ],
        )

    def test_exprs(self):
        self.assertTokensTypes("bb-cc", ["ID", "MINUS", "ID"])

        self.assertTokensTypes("foo & 0xFF", ["ID", "AND", "INT_CONST_HEX"])

        self.assertTokensTypes(
            "(2+k) * 62",
            [
                "LPAREN",
                "INT_CONST_DEC",
                "PLUS",
                "ID",
                "RPAREN",
                "TIMES",
                "INT_CONST_DEC",
            ],
        )

        self.assertTokensTypes("x | y >> z", ["ID", "OR", "ID", "RSHIFT", "ID"])

        self.assertTokensTypes(
            "x <<= z << 5", ["ID", "LSHIFTEQUAL", "ID", "LSHIFT", "INT_CONST_DEC"]
        )

        self.assertTokensTypes(
            "x = y > 0 ? y : -6",
            [
                "ID",
                "EQUALS",
                "ID",
                "GT",
                "INT_CONST_OCT",
                "CONDOP",
                "ID",
                "COLON",
                "MINUS",
                "INT_CONST_DEC",
            ],
        )

        self.assertTokensTypes("a+++b", ["ID", "PLUSPLUS", "PLUS", "ID"])

    def test_statements(self):
        self.assertTokensTypes(
            "for (int i = 0; i < n; ++i)",
            [
                "FOR",
                "LPAREN",
                "INT",
                "ID",
                "EQUALS",
                "INT_CONST_OCT",
                "SEMI",
                "ID",
                "LT",
                "ID",
                "SEMI",
                "PLUSPLUS",
                "ID",
                "RPAREN",
            ],
        )

        self.assertTokensTypes(
            "self: goto self;", ["ID", "COLON", "GOTO", "ID", "SEMI"]
        )

        self.assertTokensTypes(
            """ switch (typ)
                {
                    case TYPE_ID:
                        m = 5;
                        break;
                    default:
                        m = 8;
                }""",
            [
                "SWITCH",
                "LPAREN",
                "ID",
                "RPAREN",
                "LBRACE",
                "CASE",
                "ID",
                "COLON",
                "ID",
                "EQUALS",
                "INT_CONST_DEC",
                "SEMI",
                "BREAK",
                "SEMI",
                "DEFAULT",
                "COLON",
                "ID",
                "EQUALS",
                "INT_CONST_DEC",
                "SEMI",
                "RBRACE",
            ],
        )

    def test_preprocessor_line(self):
        self.assertTokensTypes("#abracadabra", ["PPHASH", "ID"])

        str = r"""
        546
        #line 66 "kwas\df.h"
        id 4
        dsf
        # 9
        armo
        #line 10 "..\~..\test.h"
        tok1
        #line 99999 "include/me.h"
        tok2
        """

        # ~ self.clex.filename
        self.clex.input(str)

        t1 = require_token(self.clex.token())
        self.assertEqual(t1.type, "INT_CONST_DEC")
        self.assertEqual(t1.lineno, 2)

        t2 = require_token(self.clex.token())
        self.assertEqual(t2.type, "ID")
        self.assertEqual(t2.value, "id")
        self.assertEqual(t2.lineno, 66)
        self.assertEqual(self.clex.filename, r"kwas\df.h")

        for i in range(3):
            t = require_token(self.clex.token())

        self.assertEqual(t.type, "ID")
        self.assertEqual(t.value, "armo")
        self.assertEqual(t.lineno, 9)
        self.assertEqual(self.clex.filename, r"kwas\df.h")

        t4 = require_token(self.clex.token())
        self.assertEqual(t4.type, "ID")
        self.assertEqual(t4.value, "tok1")
        self.assertEqual(t4.lineno, 10)
        self.assertEqual(self.clex.filename, r"..\~..\test.h")

        t5 = require_token(self.clex.token())
        self.assertEqual(t5.type, "ID")
        self.assertEqual(t5.value, "tok2")
        self.assertEqual(t5.lineno, 99999)
        self.assertEqual(self.clex.filename, r"include/me.h")

    def test_preprocessor_line_funny(self):
        str = r"""
        #line 10 "..\6\joe.h"
        10
        """
        self.clex.input(str)

        t1 = require_token(self.clex.token())
        self.assertEqual(t1.type, "INT_CONST_DEC")
        self.assertEqual(t1.lineno, 10)
        self.assertEqual(self.clex.filename, r"..\6\joe.h")

    def test_preprocessor_pragma(self):
        str = """
        42
        #pragma
        #pragma helo me
        #pragma once
        # pragma omp parallel private(th_id)
        #\tpragma {pack: 2, smack: 3}
        #pragma <includeme.h> "nowit.h"
        #pragma "string"
        #pragma somestring="some_other_string"
        #pragma id 124124 and numbers 0235495
        _Pragma("something else")
        59
        """
        # Check that pragmas are tokenized, including trailing string
        self.clex.input(str)

        t1 = require_token(self.clex.token())
        self.assertEqual(t1.type, "INT_CONST_DEC")

        t2 = require_token(self.clex.token())
        self.assertEqual(t2.type, "PPPRAGMA")

        t3 = require_token(self.clex.token())
        self.assertEqual(t3.type, "PPPRAGMA")

        t4 = require_token(self.clex.token())
        self.assertEqual(t4.type, "PPPRAGMASTR")
        self.assertEqual(t4.value, "helo me")

        for i in range(3):
            self.clex.token()

        t5 = require_token(self.clex.token())
        self.assertEqual(t5.type, "PPPRAGMASTR")
        self.assertEqual(t5.value, "omp parallel private(th_id)")

        for i in range(5):
            ta = require_token(self.clex.token())
            self.assertEqual(ta.type, "PPPRAGMA")
            tb = require_token(self.clex.token())
            self.assertEqual(tb.type, "PPPRAGMASTR")

        t6a = require_token(self.clex.token())
        t6l = require_token(self.clex.token())
        t6b = require_token(self.clex.token())
        t6r = require_token(self.clex.token())
        self.assertEqual(t6a.type, "_PRAGMA")
        self.assertEqual(t6l.type, "LPAREN")
        self.assertEqual(t6b.type, "STRING_LITERAL")
        self.assertEqual(t6b.value, '"something else"')
        self.assertEqual(t6r.type, "RPAREN")

        t7 = require_token(self.clex.token())
        self.assertEqual(t7.type, "INT_CONST_DEC")
        self.assertEqual(t7.lineno, 13)


# Keeps all the errors the lexer spits in one place, to allow
# easier modification if the error syntax changes.
#
ERR_ILLEGAL_CHAR = "Illegal character"
ERR_OCTAL = "Invalid octal constant"
ERR_UNMATCHED_QUOTE = "Unmatched '"
ERR_INVALID_CCONST = "Invalid char constant"
ERR_STRING_ESCAPE = "String contains invalid escape"

ERR_FILENAME_BEFORE_LINE = "filename before line"
ERR_LINENUM_MISSING = "line number missing"
ERR_INVALID_LINE_DIRECTIVE = "invalid #line directive"
ERR_COMMENT = "Comments are not supported"


class TestCLexerErrors(unittest.TestCase):
    """Test lexing of erroneous strings.
    Works by passing an error function that saves the error
    in an attribute for later perusal.
    """

    def error_func(self, msg, line, column):
        self.error = msg

    def setUp(self):
        self.clex = CLexer(self.error_func)
        self.error = ""

    def assertLexerError(self, str, error_like):
        # feed the string to the lexer
        self.clex.input(str)

        # Pulls all tokens from the string. Errors will
        # be written into self.error by the error_func
        # callback
        #
        token_types(self.clex)

        # compare the error to the expected
        self.assertTrue(
            re.search(error_like, self.error),
            f"\nExpected error matching: {error_like}\nGot: {self.error}",
        )

        # clear last error, for the sake of subsequent invocations
        self.error = ""

    def test_trivial_tokens(self):
        self.assertLexerError("@", ERR_ILLEGAL_CHAR)
        self.assertLexerError("`", ERR_ILLEGAL_CHAR)
        self.assertLexerError("\\", ERR_ILLEGAL_CHAR)

    def test_integer_constants(self):
        self.assertLexerError("029", ERR_OCTAL)
        self.assertLexerError("012345678", ERR_OCTAL)
        self.assertLexerError("0'8", ERR_OCTAL)
        self.assertLexerError("0'7'9", ERR_OCTAL)

    def test_char_constants(self):
        self.assertLexerError("'", ERR_UNMATCHED_QUOTE)
        self.assertLexerError("'b\n", ERR_UNMATCHED_QUOTE)
        self.assertLexerError("'\\xaa\n'", ERR_UNMATCHED_QUOTE)

        self.assertLexerError(r"'123\12a'", ERR_INVALID_CCONST)
        self.assertLexerError(r"'123\xabg'", ERR_INVALID_CCONST)
        self.assertLexerError("''", ERR_INVALID_CCONST)
        self.assertLexerError("'abcjx'", ERR_INVALID_CCONST)
        self.assertLexerError(r"'\*'", ERR_INVALID_CCONST)

    def test_unicode_escape_backtracking(self):
        # Long malformed constants must not permit exponential backtracking
        # between Unicode escapes and the permissive simple-escape pattern.
        escapes = r"\u00e9\U0001F600" * 30
        self.assertLexerError("'" + escapes, ERR_UNMATCHED_QUOTE)
        self.assertLexerError("'" + escapes + "\n", ERR_UNMATCHED_QUOTE)
        self.assertLexerError("'" + escapes + "'", ERR_INVALID_CCONST)

    def test_string_literals(self):
        self.assertLexerError(r'"jx\`"', ERR_STRING_ESCAPE)
        self.assertLexerError(r'"hekllo\* on ix"', ERR_STRING_ESCAPE)
        self.assertLexerError(r'L"hekllo\* on ix"', ERR_STRING_ESCAPE)
        # Should not suffer from slow backtracking
        self.assertLexerError(
            r'"\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\`\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123"',
            ERR_STRING_ESCAPE,
        )
        self.assertLexerError(
            r'"\xf1\x23\xf1\x23\xf1\x23\xf1\x23\xf1\x23\xf1\x23\xf1\x23\xf1\x23\xf1\x23\x23\`\xf1\x23\xf1\x23\xf1\x23\xf1\x23\xf1\x23\xf1\x23\xf1\x23\xf1\x23\xf1\x23\xf1\x23"',
            ERR_STRING_ESCAPE,
        )
        # Should not suffer from slow backtracking when there's no end quote
        self.assertLexerError(
            r'"\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\`\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\123\12\123456',
            ERR_ILLEGAL_CHAR,
        )
        self.assertLexerError(
            r'"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\`\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x2\x23456',
            ERR_ILLEGAL_CHAR,
        )

    def test_preprocessor(self):
        self.assertLexerError('#line "ka"', ERR_FILENAME_BEFORE_LINE)
        self.assertLexerError("#line df", ERR_INVALID_LINE_DIRECTIVE)
        self.assertLexerError("#line \n", ERR_LINENUM_MISSING)
        # Integer suffixes are not valid in #line directives (issue #587).
        self.assertLexerError("#line 0u", ERR_INVALID_LINE_DIRECTIVE)
        self.assertLexerError("#line 1U", ERR_INVALID_LINE_DIRECTIVE)
        self.assertLexerError("#line 10uLL", ERR_INVALID_LINE_DIRECTIVE)
        self.assertLexerError("#line 1'000u", ERR_INVALID_LINE_DIRECTIVE)
        self.assertLexerError("#line 1''000", ERR_INVALID_LINE_DIRECTIVE)
        # a compatible preprocessor must remove comments.
        self.assertLexerError("//", ERR_COMMENT)
        self.assertLexerError("/*", ERR_COMMENT)


class TestCLexerFastPaths(unittest.TestCase):
    """The lexer skips the master regex based on the first character of a
    token. These tests check that the character sets match the regex rules.
    """

    SUFFIXES = ("", "x", "1", "'", '"', "'x'", '"x"', '8"x"', "8'x'", "*", "/", ".5")

    def test_regex_first_chars(self):
        from pycparser import c_lexer

        chars = [chr(code) for code in range(0x300)]
        chars += ["\u00e9", "\u65e5", "\U0001f389"]
        for char in chars:
            if char in c_lexer._regex_first_chars:
                continue
            for suffix in self.SUFFIXES:
                self.assertIsNone(
                    c_lexer._regex_master.match(char + suffix), repr(char + suffix)
                )

    def test_identifier_only_first_chars(self):
        from pycparser import c_lexer

        # These characters must start an identifier and no competing token. The
        # positive check catches invalid starts such as '@', which match no
        # token rule and would therefore pass all the negative checks.
        for char in c_lexer._identifier_only_first_chars:
            self.assertIsNotNone(
                c_lexer._identifier_pattern.fullmatch(char), repr(char)
            )
            for rule in c_lexer._regex_rules:
                if rule.tok_type == "ID":
                    continue
                for suffix in self.SUFFIXES:
                    self.assertIsNone(
                        re.match(rule.regex_pattern, char + suffix),
                        f"{rule.tok_type} {char + suffix!r}",
                    )


class TestCLexerLineMarkersAndIncludes(unittest.TestCase):
    """Unified position model: line markers, file stack, includes."""

    def setUp(self):
        self.errors = []

    def error_func(self, msg, line, column, **kwargs):
        self.errors.append(
            (msg, kwargs.get("location"), kwargs.get("physical"))
        )

    def tokens(self, text, include_func=None, filename="main.c"):
        clex = CLexer(self.error_func, include_func=include_func)
        clex.input(text, filename=filename)
        return token_list(clex), clex

    def test_nested_line_markers_push_and_pop(self):
        text = (
            "# 1 \"main.c\"\n"
            "int outer;\n"
            "# 1 \"inner.h\" 1\n"
            "int inner;\n"
            "# 3 \"main.c\" 2\n"
            "int back;\n"
        )
        toks, clex = self.tokens(text)
        names = [(t.value, t.logical.filename) for t in toks if t.type == "ID"]
        self.assertEqual(
            names,
            [("outer", "main.c"), ("inner", "inner.h"), ("back", "main.c")],
        )
        # Physical positions stay in the single scanned buffer.
        inner_tok = next(t for t in toks if t.value == "inner")
        self.assertEqual(inner_tok.logical.filename, "inner.h")
        self.assertEqual(inner_tok.physical.filename, "main.c")
        self.assertEqual(inner_tok.physical.lineno, 4)
        self.assertEqual(self.errors, [])

    def test_consecutive_entry_markers_do_not_replay_tokens(self):
        text = "#line 5 \"x.h\"\n# 9 \"y.c\" 1\nint a;\n"
        toks, _ = self.tokens(text, filename="")
        self.assertEqual([t.value for t in toks if t.type == "ID"], ["a"])
        only = next(t for t in toks if t.type == "ID")
        self.assertEqual(only.logical, SourceLocation("y.c", 9, 5))

    def test_plain_line_directive_keeps_single_frame(self):
        toks, clex = self.tokens("#line 42 \"remap.c\"\nint v;\n")
        self.assertEqual(len(clex._file_stack), 1)
        ident = next(t for t in toks if t.type == "ID")
        self.assertEqual(ident.logical, SourceLocation("remap.c", 42, 5))
        self.assertEqual(ident.physical.filename, "main.c")

    def test_nested_include_merges_buffers(self):
        files = {
            "a.h": "int from_a;\n",
            "b.h": "#include \"a.h\"\nint from_b;\n",
        }
        toks, clex = self.tokens(
            "#include \"b.h\"\nint root;\n", include_func=files.get
        )
        ids = [(t.value, t.logical.filename) for t in toks if t.type == "ID"]
        self.assertEqual(
            ids,
            [("from_a", "a.h"), ("from_b", "b.h"), ("root", "main.c")],
        )
        root_tok = next(t for t in toks if t.value == "root")
        self.assertEqual(root_tok.logical.filename, "main.c")
        self.assertEqual(root_tok.physical.filename, "main.c")

    def test_include_angle_brackets(self):
        requested = []
        def resolver(name):
            requested.append(name)
            return "int angle;\n"
        toks, _ = self.tokens("#include <system/h.h>\n", include_func=resolver)
        self.assertEqual(requested, ["system/h.h"])
        self.assertIn(("angle", "system/h.h"),
                      [(t.value, t.logical.filename) for t in toks])

    def test_missing_include_keeps_following_tokens(self):
        toks, _ = self.tokens(
            "#include \"missing.h\"\nint kept;\n", include_func=lambda n: None
        )
        self.assertEqual(
            [(t.type, t.value) for t in toks],
            [("INT", "int"), ("ID", "kept"), ("SEMI", ";")],
        )
        self.assertIn("include file not found", self.errors[0][0])
        self.assertEqual(self.errors[0][1].filename, "main.c")
        self.assertEqual(self.errors[0][2].filename, "main.c")

    def test_bad_encoding_include_reports_and_continues(self):
        def resolver(name):
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad byte")
        toks, _ = self.tokens("#include \"x.h\"\nint y;\n", include_func=resolver)
        self.assertEqual([t.value for t in toks if t.type == "ID"], ["y"])
        self.assertIn("bad encoding", self.errors[0][0])

    def test_oserror_include_reports_and_continues(self):
        def resolver(name):
            raise FileNotFoundError(name)
        toks, _ = self.tokens("#include \"z.h\"\nint z;\n", include_func=resolver)
        self.assertEqual([t.value for t in toks if t.type == "ID"], ["z"])
        self.assertIn("cannot include", self.errors[0][0])

    def test_missing_quote_include_emits_pphash_without_loop(self):
        toks, _ = self.tokens(
            "#include \"noend\nint kept2;\n", include_func=lambda n: n
        )
        self.assertEqual(toks[0].type, "PPHASH")
        self.assertEqual(toks[0].value, "#")
        self.assertIn("kept2", [t.value for t in toks])
        self.assertTrue(self.errors)

    def test_include_without_callback_emits_pphash(self):
        toks, _ = self.tokens("#include \"h.h\"\nint nocb;\n")
        self.assertEqual(toks[0].type, "PPHASH")
        self.assertIn("nocb", [t.value for t in toks])
        self.assertIn("include callback not set", self.errors[0][0])

    def test_garbage_include_does_not_swallow_tokens(self):
        toks, _ = self.tokens("#include 123\nint g;\n", include_func=lambda n: n)
        self.assertEqual(toks[0].type, "PPHASH")
        self.assertIn(("INT_CONST_DEC", "123"), [(t.type, t.value) for t in toks])

    def test_legacy_three_arg_error_callback_still_works(self):
        legacy_errors = []
        clex = CLexer(lambda msg, line, column: legacy_errors.append((msg, line, column)))
        clex.input("@")
        token_list(clex)
        self.assertEqual(legacy_errors[0][0], "Illegal character " + repr("@"))
        self.assertEqual(legacy_errors[0][1], 1)

    def test_logical_and_physical_locations_diverge_after_line(self):
        toks, _ = self.tokens("int a;\n#line 99 \"far.c\"\nint b;\n")
        b_tok = next(t for t in toks if t.value == "b")
        self.assertEqual(b_tok.logical, SourceLocation("far.c", 99, 5))
        self.assertEqual(b_tok.physical, SourceLocation("main.c", 3, 5))


if __name__ == "__main__":
    unittest.main()
