# frozen_string_literal: true

require "common"
require "tmpdir"
require "fileutils"

# Integration tests for recursive downloads that exercise the explicit
# remote->local name mapping layer. They use an in-memory, synchronous SFTP
# driver so that name-equivalence rules for arbitrary target file systems
# can be emulated without depending on the behavior of the host running the
# tests, while still writing through the real Download state machine onto a
# scratch directory.
class DownloadNameMappingTest < Net::SFTP::TestCase
  include Net::SFTP::Constants::StatusCodes

  FakeAttrs = Struct.new(:size, :directory) do
    def directory?; directory; end
  end

  FakeName = Struct.new(:name, :attributes) do
    def directory?; attributes.directory?; end
  end

  # Minimal request wrapper: only the [] / []= property bag and the
  # callback plumbing are used by the Download operation.
  class FakeRequest
    def initialize; @properties = {}; end
    def [](key); @properties[key.to_sym]; end
    def []=(key, value); @properties[key.to_sym] = value; end
  end

  class FakeResponse
    EOF_CODE = Net::SFTP::Constants::StatusCodes::FX_EOF
    OK_CODE = Net::SFTP::Constants::StatusCodes::FX_OK
    def initialize(request, data)
      @request, @data = request, data
    end
    attr_reader :request
    def [](key); @data[key.to_sym]; end
    def ok?; !@data[:code]; end
    def eof?; @data[:code] == EOF_CODE; end
    def code; @data[:code] || OK_CODE; end
    def message; ""; end
  end

  # A tiny in-memory SFTP file system. Paths are split on "/"; entry names
  # are stored as raw bytes (ASCII-8BIT), exactly like the wire protocol.
  class FakeSFTP
    attr_reader :logger, :loops
    EOF_CODE = Net::SFTP::Constants::StatusCodes::FX_EOF

    def initialize(tree)
      @tree = tree
      @logger = nil
      @handles = {}
      @next_handle = 0
      @pending = []
    end

    def loop
      # Drain deferred responses for as long as the downloader is active,
      # mirroring the asynchronous packet flow of the real event loop.
      @pending.shift.call while @pending.any? && yield
    end

    def opendir(path, &callback)
      request = FakeRequest.new
      defer do
        node = resolve(path)
        handle = "d#{@next_handle += 1}"
        @handles[handle] = [node, 0]
        reply(request, callback, :handle => handle)
      end
      request
    end

    def readdir(handle, &callback)
      request = FakeRequest.new
      defer do
        node, cursor = @handles[handle]
        entries = node_entries(node)
        if cursor >= entries.length
          @handles.delete(handle)
          reply(request, callback, :code => EOF_CODE)
        else
          @handles[handle] = [node, entries.length]
          reply(request, callback, :names => entries[cursor..-1])
        end
      end
      request
    end

    def close(_handle, &callback)
      request = FakeRequest.new
      defer { reply(request, callback, {}) }
      request
    end

    def open(path, &callback)
      request = FakeRequest.new
      defer do
        handle = "f#{@next_handle += 1}"
        @handles[handle] = [resolve(path), 0]
        reply(request, callback, :handle => handle)
      end
      request
    end

    def read(handle, offset, length, &callback)
      request = FakeRequest.new
      defer do
        data, = @handles[handle]
        if offset >= data.bytesize
          reply(request, callback, :code => EOF_CODE)
        else
          reply(request, callback, :data => data.byteslice(offset, length))
        end
      end
      request
    end

    private

      def defer(&block)
        @pending << block
      end

      def reply(request, callback, data)
        callback.call(FakeResponse.new(request, data))
      end

      # Builds [name, node] pairs, with raw byte names, in insertion order.
      def node_entries(node)
        node.map do |name, child|
          directory = child.is_a?(Hash)
          attrs = FakeAttrs.new(directory ? 0 : child.bytesize, directory)
          FakeName.new(String(name).b.dup, attrs)
        end
      end

      def resolve(path)
        parts = String(path).b.split("/").reject(&:empty?)
        # The seeded tree is the content of the "/remote" root itself.
        parts.shift if parts.first == "remote"
        parts.inject(@tree) { |node, part| node.fetch(part) }
      end
  end

  def setup
    @root = Dir.mktmpdir("net-sftp-download")
  end

  def teardown
    FileUtils.remove_entry(@root) if @root && File.directory?(@root)
  end

  def destination
    File.join(@root, "dest")
  end

  def run_download!(tree, options = {})
    fake = FakeSFTP.new(tree)
    downloader = Net::SFTP::Operations::Download.new(
      fake, destination, "/remote", { :recursive => true }.merge(options)
    )
    downloader.wait
    downloader
  end

  def tree
    {
      "file1" => "contents of file1",
      "subdir1" => { "file2" => "contents of file2" }
    }
  end

  def test_recursive_download_mirrors_tree_and_writes_manifest
    run_download!(tree)

    assert_equal "contents of file1", File.read(File.join(destination, "file1"))
    assert_equal "contents of file2", File.read(File.join(destination, "subdir1", "file2"))

    manifest_path = File.join(destination, ".net-sftp-name-map")
    assert File.file?(manifest_path)
    records = Net::SFTP::Operations::NameManifest.read(manifest_path)
    locals = records.map(&:local_path)
    assert_includes locals, "file1"
    assert_includes locals, "subdir1"
    assert_includes locals, File.join("subdir1", "file2")
    file2 = records.find { |record| record.local_path == File.join("subdir1", "file2") }
    assert_equal "file2".b, file2.remote_name
    assert_equal "/remote/subdir1/file2".b, file2.remote_path
    assert_equal "f", file2.kind
  end

  def test_reject_strategy_aborts_layer_before_writing_and_preserves_existing_files
    # A pre-existing local file that a naively escaped/overwritten download
    # could otherwise truncate. Its mtime/content must survive a failed,
    # rejected layer.
    FileUtils.mkdir_p(destination)
    sentinel = File.join(destination, "sentinel")
    File.binwrite(sentinel, "do-not-touch")

    bad_tree = { "ok.txt" => "data", "bad\xFFname".b => "x" }
    error = assert_raises(Net::SFTP::Operations::InvalidNameError) do
      run_download!(bad_tree, :name_mapper => { :strategy => :reject })
    end
    assert_equal "bad\xFFname".b, error.name

    assert_equal "do-not-touch", File.binread(sentinel)
    refute File.exist?(File.join(destination, "ok.txt")),
           "layer contents must not be written when a sibling name is rejected"
    refute File.exist?(File.join(destination, ".net-sftp-name-map")),
           "manifest must not be written when a layer is rejected"
  end

  def test_escape_strategy_round_trips_invalid_utf8_without_replacement_characters
    bad_tree = { "a\xFFb".b => "one", "a\xFEb".b => "two", "pct%name" => "three" }
    run_download!(bad_tree, :name_mapper => { :strategy => :escape })

    assert_equal "one", File.binread(File.join(destination, "a%FFb"))
    assert_equal "two", File.binread(File.join(destination, "a%FEb"))
    assert_equal "three", File.binread(File.join(destination, "pct%25name"))

    records = Net::SFTP::Operations::NameManifest.read(
      File.join(destination, ".net-sftp-name-map")
    )
    by_local = records.each_with_object({}) { |record, map| map[record.local_path] = record }
    assert_equal "a\xFFb".b, by_local["a%FFb"].remote_name
    assert_equal "a\xFEb".b, by_local["a%FEb"].remote_name
    assert_equal "pct%name".b, by_local["pct%25name"].remote_name

    assert_equal "a\xFFb".b,
      Net::SFTP::Operations::NameMapper.unescape("a%FFb")
  end

  def test_injected_case_folding_equivalency_detects_foreign_filesystem_collision
    # NTFS/HFS+ style: names differ only in case on the (POSIX) remote host
    # but cannot coexist on a case-insensitive local file system.
    FileUtils.mkdir_p(destination)
    File.binwrite(File.join(destination, "sentinel"), "keep")
    collision_tree = { "Report.txt" => "upper", "report.txt" => "lower" }

    assert_raises(Net::SFTP::Operations::NameCollisionError) do
      run_download!(
        collision_tree,
        :name_equivalency => Net::SFTP::Operations::NameMapper::CASE_FOLD
      )
    end

    refute File.exist?(File.join(destination, "Report.txt"))
    refute File.exist?(File.join(destination, "report.txt"))
    assert_equal "keep", File.binread(File.join(destination, "sentinel"))
  end

  def test_injected_unicode_normalization_equivalency_detects_collision
    # Same visual name, two encodings: precomposed U+00E9 vs e + combining
    # acute. A normalizing file system would alias them.
    nfc = "\xC3\xA9".b       # é
    nfd = "e\xCC\x81".b      # e + U+0301
    collision_tree = { nfc => "a", nfd => "b" }

    assert_raises(Net::SFTP::Operations::NameCollisionError) do
      run_download!(
        collision_tree,
        :name_mapper => {
          :strategy => :escape,
          :equivalency => Net::SFTP::Operations::NameMapper::UNICODE_NFD
        }
      )
    end
  end

  def test_escape_does_not_collide_distinct_invalid_byte_names
    # Distinct invalid byte sequences must not be scrubbed into a shared
    # replacement character name; both must land on disk distinctly.
    run_download!(
      { "x\xFF".b => "1", "x\xFE".b => "2" },
      :name_mapper => { :strategy => :escape }
    )
    assert_equal "1", File.binread(File.join(destination, "x%FF"))
    assert_equal "2", File.binread(File.join(destination, "x%FE"))
  end

  def test_escape_works_across_multiple_directory_layers
    tree = {
      "d\xFF".b => {
        "d\xFE".b => { "f\xFD.txt".b => "deep" }
      }
    }
    run_download!(tree, :name_mapper => { :strategy => :escape })

    path = File.join(destination, "d%FF", "d%FE", "f%FD.txt")
    assert_equal "deep", File.binread(path)
    records = Net::SFTP::Operations::NameManifest.read(
      File.join(destination, ".net-sftp-name-map")
    )
    deep = records.find { |record| record.local_path.end_with?("f%FD.txt") }
    assert_equal "/remote/d\xFF/d\xFE/f\xFD.txt".b, deep.remote_path
    assert_equal "f\xFD.txt".b, deep.remote_name
  end

  def test_manifest_name_participates_in_top_level_collision_check
    assert_raises(Net::SFTP::Operations::NameCollisionError) do
      run_download!(
        { ".net-sftp-name-map" => "fake manifest", "other" => "x" },
        :name_mapper => { :strategy => :reject }
      )
    end
    refute File.exist?(File.join(destination, ".net-sftp-name-map"))
    refute File.exist?(File.join(destination, "other"))
  end

  def test_reserved_device_names_are_rejected_or_escaped
    assert_raises(Net::SFTP::Operations::InvalidNameError) do
      run_download!({ "CON" => "x" }, :name_mapper => { :strategy => :reject })
    end

    FileUtils.mkdir_p(@root)
    run_download!(
      { "CON" => "console" },
      :name_mapper => { :strategy => :escape }
    )
    assert_equal "console", File.binread(File.join(destination, "%43ON"))
  end

  def test_separator_and_parent_segment_names_are_rejected
    FileUtils.mkdir_p(destination)
    File.binwrite(File.join(destination, "sentinel"), "keep")
    ["a/b", "a\\b", "x" + 0.chr + "y"].each do |name|
      assert_raises(Net::SFTP::Operations::InvalidNameError) do
        run_download!({ name => "x" }, :name_mapper => { :strategy => :reject })
      end
    end
    assert_equal "keep", File.binread(File.join(destination, "sentinel"))
  end
end
