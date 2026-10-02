# frozen_string_literal: true
require_relative "spec_helper"

describe Sequel::Model, "association aggregate eager loading" do
  before do
    class ::AggArtist < Sequel::Model(:artists)
      columns :id, :a, :b
      one_to_many :albums, :class=>'AggAlbum', :key=>:artist_id
      one_to_many :gold_albums, :class=>'AggAlbum', :key=>:artist_id, :conditions=>{:gold=>true}, :reciprocal=>nil
      one_to_one :first_album, :class=>'AggAlbum', :key=>:artist_id, :reciprocal=>nil
      many_to_many :tags, :class=>'AggTag', :left_key=>:artist_id, :right_key=>:tag_id, :join_table=>:artists_tags
      one_to_many :entries, :class=>'AggEntry', :key=>[:artist_a, :artist_b], :primary_key=>[:a, :b]
      many_to_one :label, :class=>'AggLabel', :key=>:label_id
    end
    class ::AggAlbum < Sequel::Model(:albums)
      columns :id, :artist_id, :copies_sold, :year, :gold
    end
    class ::AggTag < Sequel::Model(:tags)
      columns :id, :hours
    end
    class ::AggEntry < Sequel::Model(:entries)
      columns :id, :artist_a, :artist_b
    end
    class ::AggLabel < Sequel::Model(:labels)
      columns :id
    end
    AggArtist.dataset = AggArtist.dataset.with_fetch([{:id=>1, :a=>10, :b=>20}, {:id=>2, :a=>30, :b=>40}, {:id=>3, :a=>50, :b=>60}])
    AggArtist.dataset.columns(:id, :a, :b)
    AggAlbum.dataset = AggAlbum.dataset.with_fetch([{:x_key_0_x=>1, :x_agg_0_x=>3, :x_agg_1_x=>300, :x_agg_2_x=>100}, {:x_key_0_x=>2, :x_agg_0_x=>1, :x_agg_1_x=>50, :x_agg_2_x=>nil}])
    AggAlbum.dataset.columns(:id, :artist_id, :copies_sold, :year, :gold)
    AggTag.dataset = AggTag.dataset.with_fetch([{:x_key_0_x=>1, :x_agg_0_x=>2, :x_agg_1_x=>70}])
    AggTag.dataset.columns(:id, :hours)
    AggEntry.dataset = AggEntry.dataset.with_fetch([{:x_key_0_x=>10, :x_key_1_x=>20, :x_agg_0_x=>4}])
    AggEntry.dataset.columns(:id, :artist_a, :artist_b)
    DB.reset
  end
  after do
    [:AggArtist, :AggAlbum, :AggTag, :AggEntry, :AggLabel].each{|c| Object.send(:remove_const, c)}
  end

  it "should eagerly load count and sum aggregates for one_to_many associations in a single query" do
    artists = AggArtist.eager_association_aggregates(:albums=>{:count=>true, :sum=>:copies_sold}).all
    DB.sqls.must_equal [
      'SELECT * FROM artists',
      'SELECT artist_id AS x_key_0_x, count(*) AS x_agg_0_x, sum(copies_sold) AS x_agg_1_x FROM albums WHERE (artist_id IN (1, 2, 3)) GROUP BY artist_id'
    ]
    artists.map{|a| a.association_aggregate(:albums, :count)}.must_equal [3, 1, 0]
    artists.map{|a| a.association_aggregate(:albums, :sum, :copies_sold)}.must_equal [300, 50, nil]
    artists.map{|a| a.association_aggregates[:albums]}.must_equal [{:count=>3, [:sum, :copies_sold]=>300}, {:count=>1, [:sum, :copies_sold]=>50}, {:count=>0, [:sum, :copies_sold]=>nil}]
  end

  it "should support eager_load_association_aggregates on already loaded objects" do
    artists = AggArtist.all
    DB.sqls
    AggArtist.eager_load_association_aggregates(artists, :albums=>{:count=>true})
    DB.sqls.must_equal ['SELECT artist_id AS x_key_0_x, count(*) AS x_agg_0_x FROM albums WHERE (artist_id IN (1, 2, 3)) GROUP BY artist_id']
    artists.map{|a| a.association_aggregate(:albums, :count)}.must_equal [3, 1, 0]
  end

  it "should not issue additional queries when reading preloaded aggregates" do
    artists = AggArtist.eager_association_aggregates(:albums=>{:count=>true}, :tags=>{:count=>true}).all
    DB.sqls.length.must_equal 3
    artists.each do |artist|
      artist.association_aggregate(:albums, :count)
      artist.association_aggregate(:tags, :count)
    end
    DB.sqls.must_equal []
  end

  it "should not instantiate any associated objects" do
    loads = 0
    counter = Module.new do
      define_method(:call) do |values|
        loads += 1
        super(values)
      end
    end
    AggAlbum.singleton_class.send(:prepend, counter)
    AggTag.singleton_class.send(:prepend, counter)
    AggArtist.eager_association_aggregates(:albums=>{:count=>true, :sum=>:copies_sold}, :tags=>{:count=>true}).all
    loads.must_equal 0
  end

  it "should support filters on the aggregates themselves" do
    AggAlbum.dataset = AggAlbum.dataset.with_fetch(proc{|sql| sql =~ /year = 2020/ ? [{:x_key_0_x=>1, :x_agg_0_x=>2}] : [{:x_key_0_x=>1, :x_agg_0_x=>200}]})
    artists = AggArtist.eager_association_aggregates(:albums=>{
      :count=>{:filter=>{:year=>2020}},
      :sum=>{:column=>:copies_sold, :filter=>proc{|ds| ds.where(:copies_sold=>100)}}
    }).all
    sqls = DB.sqls
    sqls.length.must_equal 3
    sqls[1].must_equal 'SELECT artist_id AS x_key_0_x, count(*) AS x_agg_0_x FROM albums WHERE ((year = 2020) AND (artist_id IN (1, 2, 3))) GROUP BY artist_id'
    sqls[2].must_equal 'SELECT artist_id AS x_key_0_x, sum(copies_sold) AS x_agg_0_x FROM albums WHERE ((copies_sold = 100) AND (artist_id IN (1, 2, 3))) GROUP BY artist_id'
    artists.map{|a| a.association_aggregate(:albums, :count)}.must_equal [2, 0, 0]
    artists.map{|a| a.association_aggregate(:albums, :sum, :copies_sold)}.must_equal [200, nil, nil]
  end

  it "should use a single query for aggregates that share the same filter" do
    AggArtist.eager_association_aggregates(:albums=>{
      :count=>{:filter=>{:year=>2020}},
      :sum=>{:column=>:copies_sold, :filter=>{:year=>2020}}
    }).all
    sqls = DB.sqls
    sqls.length.must_equal 2
    sqls.last.must_equal 'SELECT artist_id AS x_key_0_x, count(*) AS x_agg_0_x, sum(copies_sold) AS x_agg_1_x FROM albums WHERE ((year = 2020) AND (artist_id IN (1, 2, 3))) GROUP BY artist_id'
  end

  it "should apply the association's conditions to the aggregate query" do
    AggArtist.eager_association_aggregates(:gold_albums=>{:count=>true}).all
    DB.sqls.last.must_equal 'SELECT artist_id AS x_key_0_x, count(*) AS x_agg_0_x FROM albums WHERE ((gold IS TRUE) AND (artist_id IN (1, 2, 3))) GROUP BY artist_id'
  end

  it "should eagerly load aggregates for many_to_many associations using a DISTINCT join table subquery" do
    artists = AggArtist.eager_association_aggregates(:tags=>{:count=>true, :sum=>:hours}).all
    DB.sqls.must_equal [
      'SELECT * FROM artists',
      'SELECT x_sequel_association_aggregate_join_table_x.artist_id AS x_key_0_x, count(*) AS x_agg_0_x, sum(hours) AS x_agg_1_x FROM tags INNER JOIN (SELECT DISTINCT artist_id, tag_id FROM artists_tags) AS x_sequel_association_aggregate_join_table_x ON (x_sequel_association_aggregate_join_table_x.tag_id = tags.id) WHERE (x_sequel_association_aggregate_join_table_x.artist_id IN (1, 2, 3)) GROUP BY x_sequel_association_aggregate_join_table_x.artist_id'
    ]
    artists.map{|a| a.association_aggregate(:tags, :count)}.must_equal [2, 0, 0]
    artists.map{|a| a.association_aggregate(:tags, :sum, :hours)}.must_equal [70, nil, nil]
  end

  it "should support composite keys" do
    artists = AggArtist.eager_association_aggregates(:entries=>{:count=>true}).all
    DB.sqls.must_equal [
      'SELECT * FROM artists',
      'SELECT artist_a AS x_key_0_x, artist_b AS x_key_1_x, count(*) AS x_agg_0_x FROM entries WHERE ((artist_a, artist_b) IN ((10, 20), (30, 40), (50, 60))) GROUP BY artist_a, artist_b'
    ]
    artists.map{|a| a.association_aggregate(:entries, :count)}.must_equal [4, 0, 0]
  end

  it "should support one_to_one associations" do
    artists = AggArtist.eager_association_aggregates(:first_album=>{:count=>true}).all
    artists.map{|a| a.association_aggregate(:first_album, :count)}.must_equal [3, 1, 0]
  end

  it "should support summing multiple columns" do
    AggAlbum.dataset = AggAlbum.dataset.with_fetch([{:x_key_0_x=>1, :x_agg_0_x=>300, :x_agg_1_x=>4040}])
    artists = AggArtist.eager_association_aggregates(:albums=>{:sum=>[:copies_sold, :year]}).all
    DB.sqls.must_equal [
      'SELECT * FROM artists',
      'SELECT artist_id AS x_key_0_x, sum(copies_sold) AS x_agg_0_x, sum(year) AS x_agg_1_x FROM albums WHERE (artist_id IN (1, 2, 3)) GROUP BY artist_id'
    ]
    artists.map{|a| a.association_aggregate(:albums, :sum, :copies_sold)}.must_equal [300, nil, nil]
    artists.map{|a| a.association_aggregate(:albums, :sum, :year)}.must_equal [4040, nil, nil]
  end

  it "should return 0 for count and nil for sum for objects without associated records" do
    AggAlbum.dataset = AggAlbum.dataset.with_fetch([])
    artists = AggArtist.eager_association_aggregates(:albums=>{:count=>true, :sum=>:copies_sold}).all
    artists.map{|a| a.association_aggregate(:albums, :count)}.must_equal [0, 0, 0]
    artists.map{|a| a.association_aggregate(:albums, :sum, :copies_sold)}.must_equal [nil, nil, nil]
  end

  it "should keep the aggregate cache separate from the association cache" do
    artist = AggArtist.eager_association_aggregates(:albums=>{:count=>true}).all.first
    artist.associations.must_equal({})
    artist.association_aggregates.must_equal(:albums=>{:count=>3})
    AggAlbum.dataset = AggAlbum.dataset.with_fetch([{:id=>11, :artist_id=>1, :copies_sold=>1}])
    artist.albums.map{|a| a.id}.must_equal [11]
    artist.association_aggregates.must_equal(:albums=>{:count=>3})
    artist.associations.keys.must_equal [:albums]
  end

  it "should clear the aggregate cache when refreshing the object" do
    artist = AggArtist.eager_association_aggregates(:albums=>{:count=>true}).all.first
    artist.association_aggregate(:albums, :count).must_equal 3
    artist.refresh
    artist.association_aggregates.must_equal({})
    artist.association_aggregate(:albums, :count).must_be_nil
  end

  it "should duplicate the aggregate cache when the object is duped" do
    artist = AggArtist.eager_association_aggregates(:albums=>{:count=>true}).all.first
    copy = artist.dup
    copy.association_aggregate(:albums, :count).must_equal 3
    copy.association_aggregates[:albums][:count] = 5
    artist.association_aggregate(:albums, :count).must_equal 3
  end

  it "should merge aggregates when eager_association_aggregates is called multiple times" do
    artists = AggArtist.eager_association_aggregates(:albums=>{:count=>true}).eager_association_aggregates(:tags=>{:count=>true}).all
    DB.sqls.length.must_equal 3
    artists.first.association_aggregate(:albums, :count).must_equal 3
    artists.first.association_aggregate(:tags, :count).must_equal 2
  end

  it "should not issue any queries when there are no objects" do
    AggArtist.eager_load_association_aggregates([], :albums=>{:count=>true}).must_be_nil
    DB.sqls.must_equal []
  end

  it "should raise an error for undefined associations" do
    proc{AggArtist.eager_load_association_aggregates([AggArtist.first], :bogus=>{:count=>true})}.must_raise Sequel::UndefinedAssociation
  end

  it "should raise an error for unsupported association types" do
    proc{AggArtist.eager_load_association_aggregates([AggArtist.first], :label=>{:count=>true})}.must_raise Sequel::Error
  end

  it "should raise an error for unsupported aggregate types" do
    proc{AggArtist.eager_load_association_aggregates([AggArtist.first], :albums=>{:avg=>:copies_sold})}.must_raise Sequel::Error
  end

  it "should raise an error for sum aggregates without a column" do
    proc{AggArtist.eager_load_association_aggregates([AggArtist.first], :albums=>{:sum=>true})}.must_raise Sequel::Error
  end
end

begin
  require 'sqlite3'
rescue LoadError
  # skip integration tests if sqlite3 is not available
end

if defined?(SQLite3)
describe Sequel::Model, "association aggregate eager loading integration" do
  before do
    @db = Sequel.sqlite
    @db.create_table(:artists) do
      primary_key :id
      Integer :a
      Integer :b
    end
    @db.create_table(:albums) do
      primary_key :id
      Integer :artist_id
      Integer :copies_sold
      Integer :year
    end
    @db.create_table(:tags) do
      primary_key :id
      Integer :hours
    end
    @db.create_table(:artists_tags) do
      Integer :artist_id
      Integer :tag_id
    end
    @db.create_table(:entries) do
      primary_key :id
      Integer :artist_a
      Integer :artist_b
    end
    @db[:artists].import([:id, :a, :b], [[1, 10, 20], [2, 30, 40], [3, 50, 60]])
    @db[:albums].import([:id, :artist_id, :copies_sold, :year], [[1, 1, 5, 2020], [2, 1, 7, 2021], [3, 2, 3, 2020]])
    @db[:tags].import([:id, :hours], [[1, 10], [2, 20]])
    # The duplicate join table row must not affect the aggregates
    @db[:artists_tags].import([:artist_id, :tag_id], [[1, 1], [1, 1], [1, 2], [2, 1]])
    @db[:entries].import([:id, :artist_a, :artist_b], [[1, 10, 20], [2, 10, 20], [3, 30, 40]])

    artist = Object.const_set(:AggIntArtist, Sequel::Model(@db[:artists]))
    album = Object.const_set(:AggIntAlbum, Sequel::Model(@db[:albums]))
    tag = Object.const_set(:AggIntTag, Sequel::Model(@db[:tags]))
    entry = Object.const_set(:AggIntEntry, Sequel::Model(@db[:entries]))
    artist.one_to_many :albums, :class=>album, :key=>:artist_id
    artist.many_to_many :tags, :class=>tag, :left_key=>:artist_id, :right_key=>:tag_id, :join_table=>:artists_tags
    artist.one_to_many :entries, :class=>entry, :key=>[:artist_a, :artist_b], :primary_key=>[:a, :b]
    @artist = artist

    query_count = [0]
    @query_count = query_count
    counter = Module.new do
      define_method(:execute) do |*args, &block|
        query_count[0] += 1
        super(*args, &block)
      end
    end
    @db.singleton_class.send(:prepend, counter)
  end
  after do
    [:AggIntArtist, :AggIntAlbum, :AggIntTag, :AggIntEntry].each{|c| Object.send(:remove_const, c)}
    @db.disconnect
  end

  it "should compute correct aggregates without fanout from duplicate join table rows, without N+1 queries, and without instantiating associated objects" do
    loads = 0
    load_counter = Module.new do
      define_method(:call) do |values|
        loads += 1
        super(values)
      end
    end
    AggIntAlbum.singleton_class.send(:prepend, load_counter)
    AggIntTag.singleton_class.send(:prepend, load_counter)

    artists = @artist.eager_association_aggregates(
      :albums=>{:count=>true, :sum=>:copies_sold},
      :tags=>{:count=>true, :sum=>:hours}
    ).order(:id).all

    @query_count[0].must_equal 3
    loads.must_equal 0
    artists.map{|a| a.association_aggregate(:albums, :count)}.must_equal [2, 1, 0]
    artists.map{|a| a.association_aggregate(:albums, :sum, :copies_sold)}.must_equal [12, 3, nil]
    artists.map{|a| a.association_aggregate(:tags, :count)}.must_equal [2, 1, 0]
    artists.map{|a| a.association_aggregate(:tags, :sum, :hours)}.must_equal [30, 10, nil]
    artists.each{|a| a.association_aggregates}
    @query_count[0].must_equal 3
  end

  it "should apply aggregate filters" do
    artists = @artist.eager_association_aggregates(:albums=>{:count=>{:filter=>{:year=>2020}}, :sum=>{:column=>:copies_sold, :filter=>{:year=>2020}}}).order(:id).all
    @query_count[0].must_equal 2
    artists.map{|a| a.association_aggregate(:albums, :count)}.must_equal [1, 1, 0]
    artists.map{|a| a.association_aggregate(:albums, :sum, :copies_sold)}.must_equal [5, 3, nil]
  end

  it "should support composite keys" do
    artists = @artist.eager_association_aggregates(:entries=>{:count=>true}).order(:id).all
    @query_count[0].must_equal 2
    artists.map{|a| a.association_aggregate(:entries, :count)}.must_equal [2, 1, 0]
  end
end
end
