# frozen_string_literal: true
require_relative "spec_helper"

Sequel.extension :query_identity_map

describe "query_identity_map extension" do
  before do
    @db = Sequel.sqlite
    @db.create_table(:artists) do
      primary_key :id
      String :name
      String :summary
    end
    @db.create_table(:nodes) do
      primary_key :id
      Integer :parent_id
      String :label
      String :summary
    end
    @db.create_table(:tags) do
      Integer :artist_id
      Integer :tag_id
      String :name
    end
    @db[:tags].insert(:artist_id=>1, :tag_id=>2, :name=>"x")
    @db[:artists].insert(:id=>1, :name=>"Initial", :summary=>"S1")
    @db[:nodes].insert(:id=>3, :parent_id=>nil, :label=>"three", :summary=>"node3")
    @db[:nodes].insert(:id=>2, :parent_id=>3, :label=>"two", :summary=>"node2")
    @db[:nodes].insert(:id=>1, :parent_id=>2, :label=>"one", :summary=>"node1")

    @base = Class.new(Sequel::Model(@db))
    @base.plugin :query_identity_map
    @artist = Class.new(@base) { set_dataset :artists }
    @node = Class.new(@base) do
      set_dataset :nodes
      many_to_one :parent, :class=>self
      one_to_many :children, :key=>:parent_id, :class=>self
    end
    @tag = Class.new(@base) { set_dataset :tags }
    @tag.set_primary_key [:artist_id, :tag_id]
    @tag.columns :artist_id, :tag_id, :name
  end

  after do
    @db.disconnect
  end

  it "returns the same object for different projections and fills missing columns" do
    a1 = a2 = nil
    @artist.identity_map do
      a1 = @artist.select(:id).first
      a1.name = "Changed"
      a2 = @artist.select(:id, :name, :summary).first
    end

    a1.must_be_same_as a2
    a1.name.must_equal "Changed"
    a1.summary.must_equal "S1"
    a1.changed_columns.must_equal [:name]
  end

  it "fills missing columns but keeps values already present even if the database changed" do
    a1 = a2 = nil
    @artist.identity_map do
      a1 = @artist.select(:id, :name).first
      @db[:artists].where(:id=>1).update(:name=>"Updated")
      a2 = @artist.select(:id, :name, :summary).first
    end

    a1.must_be_same_as a2
    a1.name.must_equal "Initial"
    a1.summary.must_equal "S1"
    a1.changed_columns.must_be_empty
  end

  it "shares objects encountered by standard eager loading" do
    roots = nil
    @node.identity_map do
      roots = @node.select(:id, :parent_id).eager(:parent, :children).all
      node1 = roots.first
      node1.label = "changed"
      node1.parent.children.must_include node1
      node1.parent.parent.must_be_same_as roots.first.parent.parent
    end

    node1 = roots.first
    node1.parent.id.must_equal 2
    node1.parent.parent.id.must_equal 3
    node1.parent.summary.must_equal "node2"
    node1.parent.label.must_equal "two"
    node1.parent.children.first.summary.must_equal "node1"
    node1.label.must_equal "changed"
    node1.changed_columns.must_equal [:label]
  end

  it "uses composite primary key values as identity map keys" do
    t1 = t2 = nil
    @tag.identity_map do
      t1 = @tag.select(:artist_id, :tag_id).first
      t2 = @tag.all.first
    end

    t1.must_be_same_as t2
    t1.name.must_equal "x"
  end

  it "uses the fast primary key lookup path" do
    a1 = a2 = nil
    @artist.identity_map do
      a1 = @artist[1]
      a2 = @artist.select(:id, :name, :summary).first
    end

    a1.must_be_same_as a2
    a1.name.must_equal "Initial"
  end

  it "separates records loaded from different servers" do
    db = Sequel.mock(:servers=>{:s1=>{}, :s2=>{}}, :fetch=>proc do |sql|
      case sql
      when / -- s1\z/ then {:id=>1, :name=>"A"}
      when / -- s2\z/ then {:id=>1, :name=>"B"}
      end
    end)
    model = Class.new(Sequel::Model(db[:artists]))
    model.columns :id, :name
    model.plugin :query_identity_map

    a1 = a2 = nil
    model.identity_map do
      a1 = model.server(:s1).first
      a2 = model.server(:s2).first
    end

    a1.wont_be_same_as a2
    a1.name.must_equal "A"
    a2.name.must_equal "B"
  end

  it "keeps aliased non-primary-key columns and rejects aliased primary key columns" do
    a = proc do
      @artist.identity_map do
        @artist.select(:id, Sequel.as(:name, :alias_name)).first
      end
    end.call
    a[:alias_name].must_equal "Initial"
    a.values.wont_include :name

    @artist.identity_map do
      proc { @artist.select(Sequel.as(:id, :primary_id), :name).first }.must_raise Sequel::Error
    end
  end

  it "raises for models without primary keys" do
    model = Class.new(Sequel::Model(@db[:artists]))
    model.no_primary_key
    model.plugin :query_identity_map

    model.identity_map do
      proc { model.first }.must_raise Sequel::Error
    end
  end

  it "makes refresh explicitly overwrite values and clear dirty tracking" do
    a = nil
    @db[:artists].where(:id=>1).update(:name=>"Updated")
    @artist.identity_map do
      a = @artist.select(:id, :name, :summary).first
      a.name = "Local"
      a.refresh
    end

    a.name.must_equal "Updated"
    a.summary.must_equal "S1"
    a.changed_columns.must_be_empty
  end

  it "releases records on normal and exceptional scope exit" do
    scope = nil
    @artist.identity_map do
      scope = Sequel::Plugins::QueryIdentityMap.current_scope
      @artist.first
      scope.instance_variable_get(:@servers).wont_be :empty?
    end
    scope.instance_variable_get(:@servers).must_be :empty?

    begin
      @artist.identity_map do
        scope = Sequel::Plugins::QueryIdentityMap.current_scope
        @artist.first
        raise RuntimeError, "boom"
      end
    rescue RuntimeError
    end
    scope.instance_variable_get(:@servers).must_be :empty?
  end

  it "does not identity map outside a scope or across sibling scopes" do
    a1 = @artist.first
    a2 = @artist.first
    a1.wont_be_same_as a2

    b1 = b2 = nil
    @artist.identity_map { b1 = @artist.first }
    @artist.identity_map { b2 = @artist.first }
    b1.wont_be_same_as b2
  end

  it "uses a separate map for nested scopes" do
    outer = inner = nil
    @artist.identity_map do
      outer = @artist.select(:id).first
      @artist.identity_map do
        inner = @artist.select(:id, :name, :summary).first
      end
      inner.wont_be_same_as outer
    end

    outer.values.wont_include :name
    inner.name.must_equal "Initial"
  end
end
