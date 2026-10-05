# frozen_string_literal: true
require 'test/unit'
require 'pstore'
require 'tmpdir'
require 'json'

class PStoreJSONFormatTest < Test::Unit::TestCase
  def setup
    @pstore_file = File.join(Dir.tmpdir, "pstore-json.tmp.#{Process.pid}")
    @pstore = PStore.new(@pstore_file, format: :json)
  end

  def teardown
    File.unlink(@pstore_file) rescue nil
    Dir.glob("#{@pstore_file}.tmp.*").each {|f| File.unlink(f) rescue nil }
  end

  def test_round_trip_of_supported_types
    data = {
      "string" => "hello",
      "symbol" => :sym,
      "integer" => 42,
      "negative" => -7,
      "float" => 3.25,
      "true" => true,
      "false" => false,
      "nil" => nil,
      "array" => [1, "two", :three, [4.5]],
      "hash" => {"nested" => {"a" => 1}, :sym_key => [true, nil]},
    }
    @pstore.transaction do
      @pstore[:data] = data
    end
    reader = PStore.new(@pstore_file, format: :json)
    reader.transaction(true) do
      assert_equal(data, reader[:data])
    end
  end

  def test_string_and_symbol_keys_stay_distinct
    @pstore.transaction do
      @pstore[:entry] = {"key" => "string", :key => "symbol"}
      @pstore["top_string"] = 1
      @pstore[:top_symbol] = 2
    end
    reader = PStore.new(@pstore_file, format: :json)
    reader.transaction(true) do
      assert_equal({"key" => "string", :key => "symbol"}, reader[:entry])
      assert_equal(1, reader["top_string"])
      assert_equal(2, reader[:top_symbol])
      assert_nil(reader[:top_string])
      assert_nil(reader["top_symbol"])
    end
  end

  def test_file_is_inspectable_versioned_json
    @pstore.transaction do
      @pstore[:foo] = "bar"
    end
    envelope = JSON.parse(File.binread(@pstore_file))
    assert_equal("pstore-json", envelope["format"])
    assert_equal(1, envelope["version"])
    assert_equal({"$hash" => [[{"$sym" => "foo"}, "bar"]]}, envelope["data"])
  end

  def test_unknown_format_option_is_rejected
    assert_raise(ArgumentError) do
      PStore.new(@pstore_file, format: :yaml)
    end
  end

  def test_unsupported_objects_are_rejected_and_file_unchanged
    @pstore.transaction do
      @pstore[:ok] = "fine"
    end
    before = File.binread(@pstore_file)
    [Object.new, Time.now, 1..3, /re/, 1r, 1+2i].each do |value|
      assert_raise(PStore::Error) do
        @pstore.transaction { @pstore[:bad] = value }
      end
    end
    assert_equal(before, File.binread(@pstore_file))
    @pstore.transaction(true) do
      assert_nil(@pstore[:bad])
      assert_equal("fine", @pstore[:ok])
    end
  end

  def test_non_finite_floats_are_rejected
    [Float::NAN, Float::INFINITY, -Float::INFINITY].each do |value|
      assert_raise(PStore::Error) do
        @pstore.transaction { @pstore[:bad] = value }
      end
    end
  end

  def test_cyclic_structures_are_rejected
    array = []
    array << array
    assert_raise(PStore::Error) do
      @pstore.transaction { @pstore[:bad] = array }
    end
    hash = {}
    hash[:self] = hash
    assert_raise(PStore::Error) do
      @pstore.transaction { @pstore[:bad] = hash }
    end
  end

  def test_encode_depth_limit
    deep = []
    current = deep
    150.times do
      inner = []
      current << inner
      current = inner
    end
    assert_raise(PStore::Error) do
      @pstore.transaction { @pstore[:bad] = deep }
    end
  end

  def test_decode_depth_limit
    @pstore.transaction do
      @pstore[:deep] = [[["too deep"]]]
    end
    limited = PStore.new(@pstore_file, format: :json, max_depth: 2)
    assert_raise(PStore::Error) do
      limited.transaction(true) { limited[:deep] }
    end
  end

  def test_encode_node_limit
    limited = PStore.new(@pstore_file, format: :json, max_nodes: 5)
    assert_raise(PStore::Error) do
      limited.transaction { limited[:bad] = (1..10).to_a }
    end
  end

  def test_decode_node_limit
    @pstore.transaction do
      @pstore[:many] = [1, 2, 3, 4, 5]
    end
    limited = PStore.new(@pstore_file, format: :json, max_nodes: 3)
    assert_raise(PStore::Error) do
      limited.transaction(true) { limited[:many] }
    end
  end

  def test_version_mismatch_is_rejected
    @pstore.transaction do
      @pstore[:foo] = "bar"
    end
    content = File.binread(@pstore_file)
    File.binwrite(@pstore_file, content.sub('"version":1', '"version":99'))
    assert_raise(PStore::Error) do
      @pstore.transaction(true) { @pstore[:foo] }
    end
  end

  def test_non_finite_float_in_file_is_rejected
    File.binwrite(@pstore_file,
                  '{"format":"pstore-json","version":1,' +                  '"data":{"$hash":[[{"$sym":"x"},1e999]]}}')
    assert_raise(PStore::Error) do
      @pstore.transaction(true) { @pstore[:x] }
    end
  end

  def test_untagged_object_in_file_is_rejected
    File.binwrite(@pstore_file,
                  '{"format":"pstore-json","version":1,' +                  '"data":{"$hash":[[{"$sym":"x"},{"arbitrary":1}]]}}')
    assert_raise(PStore::Error) do
      @pstore.transaction(true) { @pstore[:x] }
    end
  end

  def test_marshal_file_requires_explicit_migration
    marshal_store = PStore.new(@pstore_file)
    marshal_store.transaction do
      marshal_store[:foo] = "bar"
    end
    error = assert_raise(PStore::Error) do
      @pstore.transaction(true) { @pstore[:foo] }
    end
    assert_match(/migrate/i, error.message)
  end

  def test_json_file_is_rejected_by_marshal_store
    @pstore.transaction do
      @pstore[:foo] = "bar"
    end
    marshal_store = PStore.new(@pstore_file)
    assert_raise(PStore::Error) do
      marshal_store.transaction(true) { marshal_store[:foo] }
    end
  end

  def test_migrate_to_json_converts_marshal_file
    marshal_store = PStore.new(@pstore_file)
    marshal_store.transaction do
      marshal_store[:foo] = "bar"
      marshal_store["num"] = 123
      marshal_store[:nested] = {"a" => [1, 2.5, :sym]}
    end
    assert_equal(true, PStore.migrate_to_json(@pstore_file))
    envelope = JSON.parse(File.binread(@pstore_file))
    assert_equal("pstore-json", envelope["format"])
    assert_equal(1, envelope["version"])
    json_store = PStore.new(@pstore_file, format: :json)
    json_store.transaction(true) do
      assert_equal("bar", json_store[:foo])
      assert_equal(123, json_store["num"])
      assert_equal({"a" => [1, 2.5, :sym]}, json_store[:nested])
    end
  end

  def test_migrate_to_json_preserves_original_on_validation_failure
    marshal_store = PStore.new(@pstore_file)
    marshal_store.transaction do
      marshal_store[:ok] = "fine"
      marshal_store[:bad] = Time.now
    end
    before = File.binread(@pstore_file)
    assert_raise(PStore::Error) do
      PStore.migrate_to_json(@pstore_file)
    end
    assert_equal(before, File.binread(@pstore_file))
    assert_equal([], Dir.glob("#{@pstore_file}.tmp.*"))
    marshal_store.transaction(true) do
      assert_equal("fine", marshal_store[:ok])
    end
  end

  def test_migrate_to_json_rejects_cyclic_data
    cyclic = []
    cyclic << cyclic
    marshal_store = PStore.new(@pstore_file)
    marshal_store.transaction do
      marshal_store[:bad] = cyclic
    end
    before = File.binread(@pstore_file)
    assert_raise(PStore::Error) do
      PStore.migrate_to_json(@pstore_file)
    end
    assert_equal(before, File.binread(@pstore_file))
  end

  def test_migrate_to_json_rejects_json_file
    @pstore.transaction do
      @pstore[:foo] = "bar"
    end
    assert_raise(PStore::Error) do
      PStore.migrate_to_json(@pstore_file)
    end
  end

  def test_migrate_to_json_requires_existing_file
    assert_raise(PStore::Error) do
      PStore.migrate_to_json(@pstore_file)
    end
  end

  def test_migrate_to_json_rejects_corrupt_file
    File.binwrite(@pstore_file, "not a pstore file")
    assert_raise(PStore::Error) do
      PStore.migrate_to_json(@pstore_file)
    end
    assert_equal("not a pstore file", File.binread(@pstore_file))
  end

  def test_json_format_with_ultra_safe
    @pstore.ultra_safe = true
    @pstore.transaction do
      @pstore[:foo] = "bar"
    end
    reader = PStore.new(@pstore_file, format: :json)
    reader.transaction(true) do
      assert_equal("bar", reader[:foo])
    end
  end

  def test_empty_json_file_reads_as_empty
    @pstore.transaction {}
    @pstore.transaction(true) do
      assert_nil(@pstore[:foo])
    end
  end
end
