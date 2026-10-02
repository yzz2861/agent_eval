# frozen-string-literal: true
require_relative "spec_helper"

describe "Sequel.strict_lit" do
  before do
    @db = Sequel.mock
  end

  def lit(sql, *args)
    @db.literal(Sequel.strict_lit(sql, *args))
  end

  it "returns a StrictPlaceholderLiteralString expression" do
    expr = Sequel.strict_lit("a = :a", :a => 1)
    expr.must_be_kind_of Sequel::SQL::StrictPlaceholderLiteralString
    expr.must_be_kind_of Sequel::SQL::PlaceholderLiteralString
  end

  it "binds named parameters in code areas and supports repeated names" do
    expr = Sequel.strict_lit("a = :name AND b = :name OR c = :other",
      :name => "x", :other => 7)
    expr.args.must_equal ["x", "x", 7]
    @db.literal(expr).must_equal "a = 'x' AND b = 'x' OR c = 7"
  end

  it "binds positional ? parameters in order" do
    lit("a = ? AND b = ?", 1, 2).must_equal "a = 1 AND b = 2"
  end

  it "ignores colons and question marks in single quoted strings" do
    lit("x = 'a:b?c' AND y = ?", 9).must_equal "x = 'a:b?c' AND y = 9"
  end

  it "handles doubled single quotes in strings" do
    lit("name = 'O''Brien :notparam' AND id = :id", :id => 3).
      must_equal "name = 'O''Brien :notparam' AND id = 3"
  end

  it "ignores colons and question marks in double quoted identifiers" do
    lit('SELECT "weird:name?" FROM t WHERE x = :x', :x => 1).
      must_equal 'SELECT "weird:name?" FROM t WHERE x = 1'
  end

  it "ignores colons and question marks in backtick quoted identifiers" do
    lit("SELECT `weird:name?` WHERE x = :x", :x => 1).
      must_equal "SELECT `weird:name?` WHERE x = 1"
  end

  it "ignores placeholders in -- line comments" do
    sql = "SELECT :x -- :notparam ?nope\nFROM t"
    lit(sql, :x => 5).must_equal "SELECT 5 -- :notparam ?nope\nFROM t"
  end

  it "ignores placeholders in C-style block comments, including nested ones" do
    sql = "SELECT :x /* :a /* ?nested */ :b */"
    lit(sql, :x => 5).must_equal "SELECT 5 /* :a /* ?nested */ :b */"
  end

  it "does not treat the :: type cast operator as a parameter" do
    lit("'42'::integer + :n", :n => 8).must_equal "'42'::integer + 8"
    lit("price::float = 10").must_equal "price::float = 10"
  end

  it "supports PostgreSQL dollar quoted strings with tags" do
    sql = "SELECT $func$ SELECT :x ? $func$ AS s, :y"
    lit(sql, :y => 2).must_equal "SELECT $func$ SELECT :x ? $func$ AS s, 2"
  end

  it "supports PostgreSQL anonymous dollar quotes" do
    sql = "SELECT $$ :x 'nested quote' $$ || :y"
    lit(sql, :y => 1).must_equal "SELECT $$ :x 'nested quote' $$ || 1"
  end

  it "supports E/B/X/N/U& prefixed string literals" do
    lit("E'line\\n :x'").must_equal "E'line\\n :x'"
    lit("X'1ff'").must_equal "X'1ff'"
    lit("u&'d:01'").must_equal "u&'d:01'"
    lit("n'text:?'").must_equal "n'text:?'"
  end

  it "respects backslash escaping in E-prefixed strings" do
    # The escaped quote does not terminate the literal.
    lit("E'x\\'y :z' AND :a", :a => 1).must_equal "E'x\\'y :z' AND 1"
  end

  it "does not treat jsonb/hstore multi-character ? operators as placeholders" do
    lit("j ?| ARRAY[?]", 1).must_equal "j ?| ARRAY[1]"
    lit("j ?& ARRAY[?]", 1).must_equal "j ?& ARRAY[1]"
    lit("j ?~ ?", "pat").must_equal "j ?~ 'pat'"
  end

  it "treats the single-character jsonb ? operator written without whitespace as an operator" do
    lit("j?'key'").must_equal "j?'key'"
  end

  it "supports SQLite numbered ?NNN placeholders with repeated numbers" do
    lit("?1 + ?2 + ?1", 3, 4).must_equal "3 + 4 + 3"
  end

  it "raises for gaps in numbered placeholders" do
    err = lambda { Sequel.strict_lit("?1 + ?3", 1, 2) }.must_raise(Sequel::Error)
    err.message.must_include "contiguous 1-based sequence"
  end

  it "does not scan dollar tags inside single quoted strings" do
    lit("'$x$ :y' = :z", :z => 1).must_equal "'$x$ :y' = 1"
  end

  it "escapes malicious string parameter values as bound literals" do
    evil = "a'); DROP TABLE users; --"
    result = lit("name = ?", evil)
    result.must_equal "name = 'a''); DROP TABLE users; --'"
    # The injected quote is doubled inside one single SQL string literal.
    result.scan("'a'')").length.must_equal 1
  end

  it "escapes malicious named parameter values" do
    evil = "' OR 1=1 --"
    lit("WHERE p = :p", :p => evil).must_equal "WHERE p = ''' OR 1=1 --'"
  end

  it "supports complex values used as bind arguments" do
    lit("id IN ?", [1, 2, 3]).must_equal "id IN (1, 2, 3)"
    lit("v = ?", nil).must_equal "v = NULL"
  end

  it "validates templates with no placeholders and no args" do
    expr = Sequel.strict_lit("SELECT 1")
    @db.literal(expr).must_equal "SELECT 1"
  end

  it "raises at creation time for a missing named argument with position" do
    err = lambda { Sequel.strict_lit("SELECT\n:a", :b => 1) }.must_raise(Sequel::Error)
    err.message.must_include "missing value for named placeholder :a"
    err.message.must_include "line 2 column 1"
  end

  it "raises for unused named arguments" do
    err = lambda { Sequel.strict_lit("a = :a", :a => 1, :b => 2) }.must_raise(Sequel::Error)
    err.message.must_include "unused named argument(s) :b"
  end

  it "raises for too many positional arguments" do
    err = lambda { Sequel.strict_lit("a = ?", 1, 2) }.must_raise(Sequel::Error)
    err.message.must_include "too many positional arguments"
    err.message.must_include "line 1 column 5"
  end

  it "raises for missing positional arguments" do
    err = lambda { Sequel.strict_lit("a = ? AND b = ?", 1) }.must_raise(Sequel::Error)
    err.message.must_include "missing positional argument"
    err.message.must_include "line 1 column 15"
  end

  it "raises when named and positional placeholders are mixed" do
    lambda { Sequel.strict_lit("a = ? AND b = :b", 1) }.must_raise(Sequel::Error)
    err = lambda { Sequel.strict_lit("a = ? AND b = :b", :b => 1) }.must_raise(Sequel::Error)
    err.message.must_include "positional placeholder"
  end

  it "raises with the opening position for an unterminated string" do
    err = lambda { Sequel.strict_lit("SELECT 'oops") }.must_raise(Sequel::Error)
    err.message.must_include "unterminated string literal"
    err.message.must_include "line 1 column 8"
  end

  it "raises with the opening position for an unterminated quoted identifier" do
    err = lambda { Sequel.strict_lit('SELECT "oops') }.must_raise(Sequel::Error)
    err.message.must_include "unterminated quoted identifier"
    err.message.must_include "line 1 column 8"
  end

  it "raises with the opening position for an unterminated backtick identifier" do
    err = lambda { Sequel.strict_lit("SELECT `oops") }.must_raise(Sequel::Error)
    err.message.must_include "unterminated backtick quoted identifier"
  end

  it "raises with the opening position for an unterminated dollar quote" do
    err = lambda { Sequel.strict_lit("SELECT $tag$ oops") }.must_raise(Sequel::Error)
    err.message.must_include "unterminated dollar quoted string ($tag$...$tag$)"
  end

  it "raises with the opening position for an unterminated block comment" do
    err = lambda { Sequel.strict_lit("SELECT /* oops") }.must_raise(Sequel::Error)
    err.message.must_include "unterminated block comment"
    err.message.must_include "line 1 column 8"
  end

  it "reports multi-line positions correctly" do
    sql = "SELECT 1\n-- c\nSELECT 'oops"
    err = lambda { Sequel.strict_lit(sql) }.must_raise(Sequel::Error)
    err.message.must_include "line 3 column 8"
  end

  it "leaves the loose Sequel.lit behavior unchanged" do
    # Loose parser historically treats :ids inside templates by regex over
    # hash keys, ignoring quotes/comments, and silently leaves unknown :names.
    @db.literal(Sequel.lit('price < :price AND id in :ids', :price => 100)).
      must_equal "price < 100 AND id in :ids"
    @db.literal(Sequel.lit('price::float = 10', {})).
      must_equal "price::float = 10"
  end

  it "keeps strict and loose entries as distinct classes" do
    Sequel.lit("a = :a", :a => 1).class.must_equal Sequel::SQL::PlaceholderLiteralString
    Sequel.strict_lit("a = :a", :a => 1).class.
      must_equal Sequel::SQL::StrictPlaceholderLiteralString
  end

  it "supports with_parens for use in filter clauses" do
    expr = Sequel.strict_lit("a = :a", :a => 1).with_parens
    @db[:t].where(expr).select_sql.must_equal "SELECT * FROM t WHERE (a = 1)"
  end

  it "works in full SELECT statements with comments and casts" do
    sql = <<~SQL
      SELECT /* binding :bad */
        'literal:bad?'::text AS s,
        id::bigint AS id
      FROM items
      WHERE name = :name
    SQL
    expr = Sequel.strict_lit(sql, :name => "bob")
    @db.literal(expr).must_include "'literal:bad?'::text"
    @db.literal(expr).must_include "name = 'bob'"
  end
end
