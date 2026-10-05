# frozen_string_literal: true
require 'test/unit'
require 'pstore'
require 'tmpdir'
require 'fileutils'
require 'digest'

class PStoreLogTest < Test::Unit::TestCase
  LOG_CHECKSUM_SIZE = 32 # SHA-256

  def setup
    @dir = Dir.mktmpdir("pstore-log-test")
    @pstore_file = File.join(@dir, "store.pstore")
    @log_file = "#{@pstore_file}.log"
    @lock_file = "#{@pstore_file}.lock"
    @pstore = PStore.new(@pstore_file, log: true)
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  # Parses the commit log, verifying the framing and checksum of every
  # record, and returns the list of operation payloads.
  def read_log_records
    data = File.binread(@log_file)
    pos = 0
    records = []
    while pos < data.bytesize
      assert_equal("PSL1", data.byteslice(pos, 4), "record magic")
      length = data.byteslice(pos + 4, 4).unpack1("N")
      payload = data.byteslice(pos + 8, length)
      checksum = data.byteslice(pos + 8 + length, LOG_CHECKSUM_SIZE)
      assert_equal(Digest("SHA256").digest(data.byteslice(pos + 4, 4 + length)),
                   checksum, "record checksum")
      records << Marshal.load(payload)
      pos += 8 + length + LOG_CHECKSUM_SIZE
    end
    records
  end

  def wait_until(timeout: 15)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      flunk("timed out waiting for child process") if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.01
    end
  end

  def spawn_child(source)
    env = {
      "RUBYOPT" => nil, "RUBYLIB" => nil,
      "BUNDLE_GEMFILE" => nil, "BUNDLER_VERSION" => nil, "BUNDLER_SETUP" => nil,
    }
    lib = File.expand_path("../lib", __dir__)
    spawn(env, EnvUtil.rubybin, "-I", lib, "-e", source, @pstore_file,
          out: File::NULL, err: File::NULL)
  end

  def test_log_mode_basic_roundtrip
    @pstore.transaction do
      @pstore[:foo] = "bar"
      @pstore[:num] = 42
    end
    fresh = PStore.new(@pstore_file, log: true)
    fresh.transaction(true) do
      assert_equal("bar", fresh[:foo])
      assert_equal(42, fresh[:num])
    end
  end

  def test_log_mode_read_only_on_missing_store_creates_no_files
    @pstore.transaction(true) do
      assert_nil(@pstore[:foo])
    end
    assert_equal([], Dir.children(@dir))
  end

  def test_log_mode_read_only_transaction_forbids_writes
    @pstore.transaction { @pstore[:foo] = "bar" }
    assert_raise(PStore::Error) do
      @pstore.transaction(true) { @pstore[:foo] = "baz" }
    end
  end

  def test_log_mode_abort_appends_no_record
    @pstore.transaction { @pstore[:foo] = "bar" }
    size = File.size(@log_file)
    @pstore.transaction do
      @pstore[:foo] = "baz"
      @pstore.abort
    end
    assert_equal(size, File.size(@log_file))
    assert_equal("bar", @pstore.transaction(true) { @pstore[:foo] })
  end

  def test_log_mode_commit_records_are_verifiable
    @pstore.transaction { @pstore[:foo] = "bar" }
    @pstore.transaction { @pstore[:baz] = [1, 2] }
    records = read_log_records
    assert_equal(2, records.size)
    assert_equal([[:set, :foo, "bar"]], records[0])
    assert_equal([[:set, :baz, [1, 2]]], records[1])
  end

  def test_log_mode_small_change_does_not_rewrite_snapshot
    @pstore.log_compaction_threshold = 0
    @pstore.transaction { @pstore[:big] = "x" * 100_000 }
    snapshot_before = File.binread(@pstore_file)

    @pstore.log_compaction_threshold = nil
    @pstore.transaction { @pstore[:small] = 1 }

    assert_equal(snapshot_before, File.binread(@pstore_file),
                 "snapshot must not be rewritten by a small change")
    assert_equal([[:set, :small, 1]], read_log_records.last)

    fresh = PStore.new(@pstore_file, log: true)
    fresh.transaction(true) do
      assert_equal(1, fresh[:small])
      assert_equal("x" * 100_000, fresh[:big])
    end
  end

  def test_log_mode_records_in_place_nested_mutation
    @pstore.transaction { @pstore[:nested] = {list: [], info: {count: 0}} }
    @pstore.transaction do
      @pstore[:nested][:list] << 1
      @pstore[:nested][:info][:count] += 1
    end
    assert_equal([[:set, :nested, {list: [1], info: {count: 1}}]], read_log_records.last)

    fresh = PStore.new(@pstore_file, log: true)
    fresh.transaction(true) do
      assert_equal({list: [1], info: {count: 1}}, fresh[:nested])
    end
  end

  def test_log_mode_records_delete
    @pstore.transaction { @pstore[:foo] = "bar" }
    @pstore.transaction { @pstore.delete(:foo) }
    assert_equal([[:delete, :foo]], read_log_records.last)
    assert_nil(@pstore.transaction(true) { @pstore[:foo] })
  end

  def test_log_mode_recovers_state_from_snapshot_and_log
    @pstore.log_compaction_threshold = 0
    @pstore.transaction { @pstore[:from_snapshot] = true }
    @pstore.log_compaction_threshold = nil
    @pstore.transaction { @pstore[:from_log] = true }

    fresh = PStore.new(@pstore_file, log: true)
    fresh.transaction(true) do
      assert_equal(true, fresh[:from_snapshot])
      assert_equal(true, fresh[:from_log])
    end
  end

  def test_log_mode_ignores_incomplete_tail_record
    @pstore.transaction { @pstore[:foo] = "bar" }
    valid_size = File.size(@log_file)
    # Simulate a crash in the middle of an append: a partial record.
    File.open(@log_file, "ab") do |file|
      file.write("PSL1" + [100].pack("N") + "partial-payload")
    end

    fresh = PStore.new(@pstore_file, log: true)
    assert_equal("bar", fresh.transaction(true) { fresh[:foo] })

    # A write transaction truncates the garbage tail away.
    fresh.transaction { fresh[:baz] = 1 }
    records = read_log_records
    assert_equal([[:set, :foo, "bar"]], records[0])
    assert_equal([[:set, :baz, 1]], records[1])
    assert_operator(File.size(@log_file), :>=, valid_size)
  end

  def test_log_mode_detects_corrupted_record_checksum
    @pstore.transaction { @pstore[:one] = 1 }
    @pstore.transaction { @pstore[:two] = 2 }
    data = File.binread(@log_file)
    # Flip a byte inside the first record's payload; a valid record follows.
    data.setbyte(8, data.getbyte(8) ^ 0xFF)
    File.binwrite(@log_file, data)

    assert_raise(PStore::Error) do
      PStore.new(@pstore_file, log: true).transaction(true) {}
    end
  end

  def test_log_mode_detects_corrupted_record_magic
    @pstore.transaction { @pstore[:one] = 1 }
    @pstore.transaction { @pstore[:two] = 2 }
    data = File.binread(@log_file)
    data.setbyte(0, data.getbyte(0) ^ 0xFF)
    File.binwrite(@log_file, data)

    assert_raise(PStore::Error) do
      PStore.new(@pstore_file, log: true).transaction(true) {}
    end
  end

  def test_log_mode_compaction_rotates_log_and_keeps_plain_snapshot
    @pstore.log_compaction_threshold = 128
    10.times { |i| @pstore.transaction { @pstore["key#{i}"] = "value#{i}" } }
    @pstore.log_compaction_threshold = 0
    @pstore.transaction { @pstore[:final] = true }

    assert_equal(0, File.size(@log_file), "log must be rotated after compaction")

    fresh = PStore.new(@pstore_file, log: true)
    fresh.transaction(true) do
      10.times { |i| assert_equal("value#{i}", fresh["key#{i}"]) }
      assert_equal(true, fresh[:final])
    end

    # The snapshot stays a plain PStore file.
    plain = PStore.new(@pstore_file)
    plain.transaction(true) do
      10.times { |i| assert_equal("value#{i}", plain["key#{i}"]) }
      assert_equal(true, plain[:final])
    end
  end

  def test_log_mode_compaction_preserves_snapshot_file_mode
    @pstore.transaction { @pstore[:foo] = "bar" }
    @pstore.log_compaction_threshold = 0
    @pstore.transaction { @pstore[:foo] = "baz" } # creates the snapshot
    File.chmod(0o600, @pstore_file)
    @pstore.transaction { @pstore[:foo] = "bam" } # compacts again
    assert_equal(0o600, File.stat(@pstore_file).mode & 0o7777)
  end

  def test_log_mode_lock_file_is_stable_across_compaction
    @pstore.log_compaction_threshold = 0
    @pstore.transaction { @pstore[:one] = 1 }
    assert(File.exist?(@lock_file))
    before = File.stat(@lock_file).ino
    @pstore.transaction { @pstore[:two] = 2 }
    @pstore.transaction { @pstore[:three] = 3 }
    assert_equal(before, File.stat(@lock_file).ino,
                 "lock file must never be renamed or replaced")
  end

  def test_log_mode_opens_plain_pstore_file
    plain = PStore.new(@pstore_file)
    plain.transaction { plain[:from_plain] = "yes" }

    logged = PStore.new(@pstore_file, log: true)
    assert_equal("yes", logged.transaction(true) { logged[:from_plain] })
    logged.transaction { logged[:from_log] = "too" }
    assert_equal("too", logged.transaction(true) { logged[:from_log] })
  end

  def test_log_mode_crash_recovery_when_child_killed_during_appends
    progress = File.join(@dir, "progress")
    pid = spawn_child(<<~RUBY)
      require "pstore"
      store = PStore.new(ARGV[0], log: true)
      store.log_compaction_threshold = 256
      progress = #{progress.dump}
      i = 0
      loop do
        store.transaction do
          store[:counter] = i
          store["key_\#{i}"] = "value_\#{i}"
        end
        File.open(progress, "a") { |f| f.puts(i) }
        i += 1
      end
    RUBY
    wait_until { File.exist?(progress) && File.readlines(progress).size >= 5 }
    Process.kill("KILL", pid)
    Process.wait(pid)

    committed = File.readlines(progress).size
    store = PStore.new(@pstore_file, log: true)
    store.transaction(true) do
      counter = store[:counter]
      assert_kind_of(Integer, counter)
      assert_include((committed - 1)..committed, counter,
                     "recovered state must be a consistent prefix of commits")
      (0..counter).each do |i|
        assert_equal("value_#{i}", store["key_#{i}"])
      end
      assert_nil(store["key_#{counter + 1}"])
    end
    # The store keeps accepting transactions after the crash.
    store.transaction { store[:after_crash] = true }
    assert_equal(true, store.transaction(true) { store[:after_crash] })
  end

  def test_log_mode_crash_recovery_when_child_killed_during_compaction
    progress = File.join(@dir, "progress")
    pid = spawn_child(<<~RUBY)
      require "pstore"
      store = PStore.new(ARGV[0], log: true)
      store.log_compaction_threshold = 0 # compact after every commit
      progress = #{progress.dump}
      i = 0
      loop do
        store.transaction do
          store[:counter] = i
          store["key_\#{i}"] = "value_\#{i}"
        end
        File.open(progress, "a") { |f| f.puts(i) }
        i += 1
      end
    RUBY
    wait_until { File.exist?(progress) && File.readlines(progress).size >= 5 }
    Process.kill("KILL", pid)
    Process.wait(pid)

    committed = File.readlines(progress).size
    store = PStore.new(@pstore_file, log: true)
    store.transaction(true) do
      counter = store[:counter]
      assert_kind_of(Integer, counter)
      assert_include((committed - 1)..committed, counter)
      (0..counter).each do |i|
        assert_equal("value_#{i}", store["key_#{i}"])
      end
    end
  end

  def test_log_mode_cross_process_lock_blocks_until_commit
    marker = File.join(@dir, "marker")
    pid = spawn_child(<<~RUBY)
      require "pstore"
      store = PStore.new(ARGV[0], log: true)
      store.transaction do
        store[:from_child] = "held"
        File.write(#{marker.dump}, "in")
        sleep 1.5
      end
    RUBY
    wait_until { File.exist?(marker) }

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @pstore.transaction { @pstore[:from_parent] = true }
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    Process.wait(pid)

    assert_operator(elapsed, :>=, 1.0,
                    "write transaction must wait for the other process")
    assert_equal("held", @pstore.transaction(true) { @pstore[:from_child] })
  end
end
