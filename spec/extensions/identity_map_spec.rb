# frozen_string_literal: true
require_relative "spec_helper"

describe "Sequel::Plugins::IdentityMap" do
  before do
    @db = Sequel.mock(:servers=>{:s1=>{}, :s2=>{}})
    @album_class = Class.new(Sequel::Model(@db[:albums]))
    @album_class.class_eval do
      columns :id, :artist_id, :name, :copies_sold
      plugin :identity_map
    end
    @artist_class = Class.new(Sequel::Model(@db[:artists]))
    @artist_class.class_eval do
      columns :id, :name
      plugin :identity_map
    end
    @node_class = Class.new(Sequel::Model(@db[:nodes]))
    @node_class.class_eval do
      set_primary_key [:a_id, :b_id]
      columns :a_id, :b_id, :name, :extra
      plugin :identity_map
    end
    @artist_class.one_to_many :albums, :class=>@album_class, :key=>:artist_id
    @album_class.many_to_one :artist, :class=>@artist_class

    @db.fetch = proc do |sql|
      case sql
      when /SELECT id, artist_id, name FROM albums/
        {:id=>1, :artist_id=>2, :name=>"Initial"}
      when /SELECT id, name FROM albums WHERE/
        {:id=>1, :name=>"Changed in database", :copies_sold=>7}
      when /SELECT id, copies_sold FROM albums WHERE/
        {:id=>1, :copies_sold=>7}
      when /FROM albums WHERE \(albums\.artist_id IN/
        [{:id=>1, :artist_id=>2, :copies_sold=>9}]
      when /FROM artists WHERE/
        [{:id=>2, :name=>"Artist"}]
      when /album_id/
        {:album_id=>1, :name=>"Initial"}
      when /SELECT \* FROM albums WHERE/
        {:id=>1, :artist_id=>2, :name=>"Initial", :copies_sold=>3}
      when /FROM nodes/
        [{:a_id=>10, :b_id=>20, :name=>"Node"}, {:a_id=>11, :b_id=>21, :name=>"Other"}]
      when /FROM albums/
        {:id=>1, :artist_id=>2, :name=>"Default", :copies_sold=>1}
      end
    end
    @db.sqls
  end

  it "returns the same object for repeated queries and fills only missing columns" do
    calls = 0
    @album_class.dataset = @album_class.dataset.with_fetch(proc do
      calls += 1
      calls == 1 ? {:id=>1, :name=>"Initial"} : {:id=>1, :name=>"Changed in database", :copies_sold=>7}
    end)

    @album_class.with_identity_map do
      album = @album_class.select(:id, :name).first(:id=>1)
      reloaded = @album_class.select(:id, :copies_sold).first(:id=>1)

      reloaded.must_be_same_as album
      album.name.must_equal "Initial"
      album.copies_sold.must_equal 7
      album.changed_columns.must_equal []
    end
  end

  it "does not overwrite a modified attribute when merging later projections" do
    @album_class.with_identity_map do
      album = @album_class.select(:id, :name).first(:id=>1)
      album.name = "Local change"
      reloaded = @album_class.select(:id, :copies_sold).first(:id=>1)

      reloaded.must_be_same_as album
      album.name.must_equal "Local change"
      album.copies_sold.must_equal 7
      album.changed_columns.must_equal [:name]
    end
  end

  it "uses one object throughout an eagerly loaded association cycle" do
    @album_class.with_identity_map do
      album = @album_class.select(:id, :artist_id, :name).
        eager(:artist=>:albums).all.first

      album.artist.name.must_equal "Artist"
      album.artist.albums.first.must_be_same_as album
      album.artist.albums.first.artist.must_be_same_as album.artist
      album.copies_sold.must_equal 9
      album.changed_columns.must_equal []
    end
  end

  it "identity maps objects built by eager_graph" do
    @album_class.with_identity_map do
      album = @album_class.select(:id, :artist_id, :name).eager_graph(:artist).with_fetch(
        :id=>1,
        :artist_id=>2,
        :name=>"Initial",
        :artist_id_0=>2,
        :artist_name=>"Artist"
      ).all.first
      reloaded = @album_class.select(:id, :copies_sold).first(:id=>1)

      reloaded.must_be_same_as album
      reloaded.copies_sold.must_equal 7
      reloaded.artist.must_be_same_as album.artist
      reloaded.artist.name.must_equal "Artist"
    end
  end

  it "normalizes aliased primary key columns to real model columns" do
    @album_class.with_identity_map do
      album = @album_class.select(Sequel.as(:id, :album_id), :name).first
      reloaded = @album_class.select(:id, :copies_sold).first(:id=>1)

      reloaded.must_be_same_as album
      album[:id].must_equal 1
      album.name.must_equal "Initial"
      album.copies_sold.must_equal 7
      album.values.wont_include :album_id
    end
  end

  it "fills later projections through aliased non-primary-key columns" do
    @album_class.with_identity_map do
      album = @album_class.select(:id, :name).first(:id=>1)
      reloaded = @album_class.select(:id, Sequel.as(:copies_sold, :copies)).first(:id=>1)

      reloaded.must_be_same_as album
      album.copies_sold.must_equal 7
      album[:copies].must_be_nil
      album.changed_columns.must_equal []
    end
  end

  it "keeps standard model-column alias semantics instead of rewriting the alias" do
    @album_class.with_identity_map do
      aliased = @album_class.select(Sequel.as(:id, :artist_id), :name).
        with_fetch(:artist_id=>1, :name=>"Aliased").first
      normal = @album_class.select(:id, :name).first(:id=>1)

      normal.wont_be_same_as aliased
      aliased.artist_id.must_equal 1
      aliased[:id].must_be_nil
      normal.id.must_equal 1
    end
  end

  it "raises for conflicting real and aliased values in one row" do
    @album_class.with_identity_map do
      proc do
        @album_class.select(:id, Sequel.as(:name, :title)).
          with_fetch(:id=>1, :name=>"Real", :title=>"Alias").first
      end.must_raise(Sequel::Error)
    end
  end

  it "supports composite primary keys" do
    @node_class.with_identity_map do
      node = @node_class.select(:a_id, :b_id, :name).all.first
      reloaded = @node_class.select(:a_id, :b_id, :extra).all.first

      reloaded.must_be_same_as node
      node.name = "Changed node"
      second = @node_class.select(:a_id, :b_id, :extra).all.first

      second.must_be_same_as node
      node.name.must_equal "Changed node"
      node.extra.must_be_nil
      node.changed_columns.must_equal [:name]
    end
  end

  it "does not identity map rows with an incompletely selected composite primary key" do
    @node_class.with_identity_map do
      node = @node_class.select(:a_id, :b_id, :name).all.first
      partial = @node_class.select(:b_id, :name).
        with_fetch(:b_id=>20, :name=>"Partial").first

      partial.wont_be_same_as node
      partial.name.must_equal "Partial"
    end
  end

  it "does not identity map models without a primary key" do
    book_class = Class.new(Sequel::Model(@db[:books]))
    book_class.class_eval do
      columns :id, :title
      no_primary_key
      plugin :identity_map
    end

    book_class.with_identity_map do
      first = book_class.dataset.with_fetch(:id=>1, :title=>"A").first
      second = book_class.dataset.with_fetch(:id=>1, :title=>"A").first

      second.wont_be_same_as first
    end
  end

  it "distinguishes records loaded from different database servers" do
    @album_class.plugin :sharding

    @album_class.with_identity_map do
      s1_album = @album_class.server(:s1).with_fetch(:id=>1, :name=>"S1").first
      s1_again = @album_class.server(:s1).with_fetch(:id=>1, :name=>"S1").first
      s2_album = @album_class.server(:s2).with_fetch(:id=>1, :name=>"S2").first

      s1_again.must_be_same_as s1_album
      s2_album.wont_be_same_as s1_album
      s1_album.instance_variable_get(:@server).must_equal :s1
      s2_album.instance_variable_get(:@server).must_equal :s2
    end
  end

  it "keeps explicit refresh semantics" do
    @album_class.with_identity_map do
      album = @album_class.select(:id, :name).first(:id=>1)
      album.name = "Local change"
      album.refresh

      album.name.must_equal "Initial"
      album.changed_columns.must_equal []
    end
  end

  it "removes the scope when the block exits normally or raises" do
    album = nil
    @album_class.with_identity_map do
      album = @album_class.first
      @album_class.identity_map?.must_equal true
    end

    @album_class.identity_map?.must_equal false

    proc do
      @album_class.with_identity_map { raise ArgumentError, "boom" }
    end.must_raise(ArgumentError)

    @album_class.identity_map?.must_equal false
    @album_class.first.wont_be_same_as album
  end
end
