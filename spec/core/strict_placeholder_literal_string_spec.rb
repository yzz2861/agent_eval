# frozen_string_literal: true
require_relative "spec_helper"

describe Sequel::SQL::StrictPlaceholderLiteralString do
  before do
    @db = Sequel.mock
  end

  it "ignores placeholders in strings, identifiers, dollar quotes, and comments" do
    sql = <<-SQL.gsub(/^\s{6}/, '')
      SELECT value::text, '?' AS "name:literal", `id?`, [name?],
             json_col['key?'] AS json_value, array_col[1],
             $tag$:named ? $nested$:ignored?$nested$ $tag$,
             $body$:ignored?$body$, $$:also_ignored?$$
      -- :line_comment ?
      WHERE id = :id /* :block_comment ? */ AND name = :name
    SQL
    expression = Sequel.lit_strict(sql.chomp, :id=>7, :name=>"O'Brien")

    @db.literal(expression).must_equal(<<-SQL.gsub(/^\s{6}/, '').chomp)
      SELECT value::text, '?' AS "name:literal", `id?`, [name?],
             json_col['key?'] AS json_value, array_col[1],
             $tag$:named ? $nested$:ignored?$nested$ $tag$,
             $body$:ignored?$body$, $$:also_ignored?$$
      -- :line_comment ?
      WHERE id = 7 /* :block_comment ? */ AND name = 'O''Brien'
    SQL
  end

  it "supports repeated named placeholders and ordered binding arguments" do
    sql = "SELECT * FROM t WHERE name = :name OR parent = :name AND id = :id"
    expression = Sequel.lit_strict(sql, :name=>:$name, :id=>:$id)
    argument_mapper = Sequel::Dataset.send(
      :prepared_statements_module,
      :prepare_bind,
      [Sequel::Dataset::UnnumberedArgumentMapper]
    )
    mapper_module = Module.new
    mapper_module.define_method(:prepared_statement_modules){[argument_mapper]}
    dataset = @db[:t].filter(expression).with_extend(mapper_module)

    prepared = dataset.prepare(:select, :strict_fragment)
    prepared.opts[:prepared_args].must_equal [:name, :name, :id]
    bound = prepared.bind(:name=>"O'Brien", :id=>7)
    bound.send(:map_to_prepared_args, bound.opts[:bind_vars]).must_equal ["O'Brien", "O'Brien", 7]
    prepared.prepared_sql.must_equal "SELECT * FROM t WHERE (SELECT * FROM t WHERE name = ? OR parent = ? AND id = ?)"
  end

  it "supports positional placeholders outside of quoted text and comments" do
    expression = Sequel.lit_strict(
      %(SELECT CAST(x AS integer), '?', "?" -- ?\nWHERE id = ? AND parent = ?),
      7,
      3
    )

    @db.literal(expression).must_equal "SELECT CAST(x AS integer), '?', \"?\" -- ?\nWHERE id = 7 AND parent = 3"
  end

  it "supports casted positional placeholders but not question marks in array slices" do
    @db.literal(Sequel.lit_strict("SELECT ?::text, x[1:?]", 7)).must_equal "SELECT 7::text, x[1:?]"
  end

  it "does not treat PostgreSQL JSON question-mark operators as placeholders" do
    expression = Sequel.lit_strict("data ?? ? OR data ?| ARRAY['x'] OR id = ?", "key", 7)

    @db.literal(expression).must_equal "data ?? 'key' OR data ?| ARRAY['x'] OR id = 7"
  end

  it "accepts empty templates and string hash keys" do
    @db.literal(Sequel.lit_strict("")).must_equal ""
    @db.literal(Sequel.lit_strict("id = :id", "id"=>7)).must_equal "id = 7"
  end

  it "raises before execution when a named placeholder is missing or extra" do
    error = proc{Sequel.lit_strict("WHERE id = :id AND name = :name", :id=>7)}.must_raise(Sequel::Error)
    error.message.must_equal "missing value for named placeholder :name at line 1, column 27"

    error = proc{Sequel.lit_strict("WHERE id = :id", :id=>7, :extra=>1)}.must_raise(Sequel::Error)
    error.message.must_equal "extra value for named placeholder :extra"
  end

  it "raises before execution when positional placeholders do not match" do
    error = proc{Sequel.lit_strict("WHERE id = ?\nAND name = ?", 7)}.must_raise(Sequel::Error)
    error.message.must_equal "missing value for positional placeholder #2 at line 2, column 12"

    error = proc{Sequel.lit_strict("WHERE id = ?", 7, 1)}.must_raise(Sequel::Error)
    error.message.must_equal "2 positional placeholder arguments provided but 1 placeholders found"
  end

  it "reports the position of unterminated literals and comments before execution" do
    [
      ["SELECT 'ab", "unterminated string starting at line 1, column 8"],
      ["SELECT E'\\n--\nSELECT x", "unterminated string starting at line 1, column 8"],
      ["SELECT $$body", "unterminated dollar-quoted string starting at line 1, column 8"],
      ["SELECT $tag$body", "unterminated dollar-quoted string starting at line 1, column 8"],
      ["SELECT \"ab", "unterminated quoted identifier starting at line 1, column 8"],
      ["SELECT `ab", "unterminated quoted identifier starting at line 1, column 8"],
      ["SELECT [ab", "unterminated bracket-quoted identifier starting at line 1, column 8"],
      ["SELECT value[ab", "unterminated array subscript starting at line 1, column 13"],
      ["SELECT /* ab\n * cd", "unterminated block comment starting at line 1, column 8"]
    ].each do |sql, message|
      error = proc{Sequel.lit_strict(sql)}.must_raise(Sequel::Error)
      error.message.must_equal message
    end
  end

  it "does not change loose placeholder interpretation" do
    loose = Sequel.lit("':named' AND :named", :named=>"value")
    strict = Sequel.lit_strict("':named' AND :named", :named=>"value")

    @db.literal(loose).must_equal "''value'' AND 'value'"
    @db.literal(strict).must_equal "':named' AND 'value'"
  end
end
