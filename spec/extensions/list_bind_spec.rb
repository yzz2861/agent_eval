# frozen_string_literal: true
require_relative "spec_helper"

describe "Sequel.list_bind" do
  before do
    Sequel.extension :list_bind
  end

  it "returns a frozen list bind marker" do
    marker = Sequel.list_bind(:ids)
    marker.must_be_kind_of Sequel::SQL::ListBind
    marker.name.must_equal :ids
    marker.must_be :frozen?
    marker.inspect.must_include "ListBind"
  end
end

describe "list_bind extension (mock adapter)" do
  before do
    Sequel.extension :list_bind
    @db = Sequel.mock
    @db.extension(:list_bind)
    @ds = @db[:items].extension(:list_bind)
  end

  it "does not change the meaning of plain arrays" do
    @ds.where(id: [1, 2, 3]).sql.must_equal "SELECT * FROM items WHERE (id IN (1, 2, 3))"
    @ds.exclude(id: [1, 2, 3]).sql.must_equal "SELECT * FROM items WHERE (id NOT IN (1, 2, 3))"
  end

  it "raises when a marker is used outside an IN context" do
    proc{@ds.where(Sequel.list_bind(:ids)).sql}.must_raise Sequel::Error
  end

  it "requires a symbol-like name" do
    proc{Sequel.list_bind(1)}.must_raise Sequel::Error
    Sequel.list_bind('ids').name.must_equal :ids
  end
end

describe "list_bind extension (unnumbered placeholders)" do
  before do
    Sequel.extension :list_bind
    @db = Sequel.mock
    @db.extension(:list_bind)
    @ds = @db[:items].with_extend do
      def execute(sql, opts={}, &block)
        super(sql, opts.merge(:arguments=>bind_arguments), &block)
      end
      def execute_dui(sql, opts={}, &block)
        super(sql, opts.merge(:arguments=>bind_arguments), &block)
      end
      def execute_insert(sql, opts={}, &block)
        super(sql, opts.merge(:arguments=>bind_arguments), &block)
      end
      def prepared_statement_modules
        [Sequel::Dataset::UnnumberedArgumentMapper]
      end
      def bound_variable_modules
        [Sequel::Dataset::UnnumberedArgumentMapper]
      end
      def emulate_prepared_statements?
        false
      end
    end
  end

  it "expands placeholders and binds list values in order" do
    ps = @ds.where(id: Sequel.list_bind(:ids)).prepare(:select, :by_ids)
    ps.call(ids: [1, 2, 3])
    @db.sqls.must_equal ["SELECT * FROM items WHERE (id IN (?, ?, ?)) -- args: [1, 2, 3]"]
  end

  it "rebuilds SQL for different list lengths" do
    ps = @ds.where(id: Sequel.list_bind(:ids)).prepare(:select, :lens)
    ps.call(ids: [1, 2])
    ps.call(ids: [3])
    ps.call(ids: [4, 5, 6])
    @db.sqls.must_equal [
      "SELECT * FROM items WHERE (id IN (?, ?)) -- args: [1, 2]",
      "SELECT * FROM items WHERE (id IN (?)) -- args: [3]",
      "SELECT * FROM items WHERE (id IN (?, ?, ?)) -- args: [4, 5, 6]",
    ]
  end

  it "renders an empty IN list as (1 = 0) with no arguments" do
    ps = @ds.where(id: Sequel.list_bind(:ids)).prepare(:select, :empty_in)
    ps.call(ids: [])
    @db.sqls.must_equal ["SELECT * FROM items WHERE (1 = 0) -- args: []"]
  end

  it "renders an empty NOT IN list as (1 = 1) with no arguments" do
    ps = @ds.exclude(id: Sequel.list_bind(:ids)).prepare(:select, :empty_not_in)
    ps.call(ids: [])
    @db.sqls.must_equal ["SELECT * FROM items WHERE (1 = 1) -- args: []"]
  end

  it "binds NULL elements rather than expanding them into the string" do
    ps = @ds.where(id: Sequel.list_bind(:ids)).prepare(:select, :nulls)
    ps.call(ids: [1, nil, 2])
    @db.sqls.must_equal ["SELECT * FROM items WHERE (id IN (?, ?, ?)) -- args: [1, nil, 2]"]
  end

  it "keeps NULL elements bound for NOT IN" do
    ps = @ds.exclude(id: Sequel.list_bind(:ids)).prepare(:select, :nulls_not)
    ps.call(ids: [1, nil])
    @db.sqls.must_equal ["SELECT * FROM items WHERE (id NOT IN (?, ?)) -- args: [1, nil]"]
  end

  it "expands every occurrence of a repeated parameter in document order" do
    ps = @ds.where(id: Sequel.list_bind(:ids)).
      or(Sequel[:id] => Sequel.list_bind(:ids)).prepare(:select, :rep)
    ps.call(ids: [1, 2])
    @db.sqls.must_equal [
      "SELECT * FROM items WHERE ((id IN (?, ?)) OR (id IN (?, ?))) -- args: [1, 2, 1, 2]",
    ]
  end

  it "supports composite key tuple lists with flattened arguments" do
    ps = @ds.where([:a, :b] => Sequel.list_bind(:pairs)).prepare(:select, :pairs)
    ps.call(pairs: [[1, 2], [3, 4]])
    @db.sqls.must_equal [
      "SELECT * FROM items WHERE ((a, b) IN ((?, ?), (?, ?))) -- args: [1, 2, 3, 4]",
    ]
  end

  it "supports NOT IN tuple lists" do
    ps = @ds.exclude([:a, :b] => Sequel.list_bind(:pairs)).prepare(:select, :npairs)
    ps.call(pairs: [[1, 2], [3, 4]])
    @db.sqls.must_equal [
      "SELECT * FROM items WHERE ((a, b) NOT IN ((?, ?), (?, ?))) -- args: [1, 2, 3, 4]",
    ]
  end

  it "keeps scalar and list bind arguments aligned regardless of position" do
    ps = @ds.where(Sequel[:name] => :$name).
      where(Sequel[:id] => Sequel.list_bind(:ids)).
      where(Sequel[:grp] => Sequel.list_bind(:groups)).
      prepare(:select, :mix)
    ps.call(name: 'x', ids: [1, 2], groups: [9])
    @db.sqls.must_equal [
      "SELECT * FROM items WHERE ((name = ?) AND (id IN (?, ?)) AND (grp IN (?))) -- args: [\"x\", 1, 2, 9]",
    ]
  end

  it "supports one-shot calls without a named prepared statement" do
    @ds.where(id: Sequel.list_bind(:ids)).call(:select, ids: [7, 8])
    @db.sqls.must_equal ["SELECT * FROM items WHERE (id IN (?, ?)) -- args: [7, 8]"]
  end

  it "supports DB.call by prepared statement name" do
    @ds.where(id: Sequel.list_bind(:ids)).prepare(:select, :named_ps)
    @db.call(:named_ps, ids: [1])
    @db.sqls.must_equal ["SELECT * FROM items WHERE (id IN (?)) -- args: [1]"]
  end

  it "raises when a list parameter is missing" do
    ps = @ds.where(id: Sequel.list_bind(:ids)).prepare(:select, :missing)
    proc{ps.call(other: [1])}.must_raise Sequel::Error
  end

  it "raises when a list parameter is not an array" do
    ps = @ds.where(id: Sequel.list_bind(:ids)).prepare(:select, :notarray)
    proc{ps.call(ids: 5)}.must_raise Sequel::Error
  end

  it "raises for mixed scalar and tuple values" do
    ps = @ds.where(id: Sequel.list_bind(:ids)).prepare(:select, :mixed)
    proc{ps.call(ids: [1, [2]])}.must_raise Sequel::Error
  end

  it "raises for tuples of inconsistent sizes" do
    ps = @ds.where([:a, :b] => Sequel.list_bind(:pairs)).prepare(:select, :badtuple)
    proc{ps.call(pairs: [[1, 2], [3]])}.must_raise Sequel::Error
  end

  it "raises when tuple size does not match column count" do
    ps = @ds.where([:a] => Sequel.list_bind(:pairs)).prepare(:select, :badarity)
    proc{ps.call(pairs: [[1, 2]])}.must_raise Sequel::Error
  end

  it "caches length-specific statements with a bounded LRU" do
    ps = @ds.where(id: Sequel.list_bind(:ids)).prepare(:select, :bounded)
    ps.call(ids: [1])
    ps.call(ids: [1, 2])
    cache = @db.instance_variable_get(:@list_bind_caches)[:bounded]
    cache.keys.must_equal [[1], [2]]

    3.upto(12){|i| ps.call(ids: Array.new(i, &:succ))}
    cache.size.must_equal 8
    cache.keys.must_equal [[5], [6], [7], [8], [9], [10], [11], [12]]

    # Recalling an evicted length and a recent length updates LRU order
    ps.call(ids: [1, 2, 3, 4, 5])
    cache.keys.last.must_equal [5]
  end

  it "reuses cached SQL while binding fresh values" do
    ps = @ds.where(id: Sequel.list_bind(:ids)).prepare(:select, :reuse)
    ps.call(ids: [1, 2])
    ps.call(ids: [3, 4])
    @db.sqls.must_equal [
      "SELECT * FROM items WHERE (id IN (?, ?)) -- args: [1, 2]",
      "SELECT * FROM items WHERE (id IN (?, ?)) -- args: [3, 4]",
    ]
  end
end
