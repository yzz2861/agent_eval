# frozen_string_literal: true
require 'test/unit'
require 'pstore'
require 'tmpdir'
require 'fileutils'
require 'digest'
require 'open3'

class PStoreJournalTest < Test::Unit::TestCase
  MAGIC = "PSTJFRM1".b
  HEADER_SIZE = 17
  DIGEST_SIZE = 32

  def setup
    @dir = Dir.mktmpdir("pstore-journal-test")
    @pstore_file = File.join(@dir, "store")
    @journal_file = @pstore_file + ".journal"
    @pstore = PStore.new(@pstore_file, journal: true)
  end

  def teardown
    FileUtils.remove_entry(@dir) if @dir && File.directory?(@dir)
  end

  def journal_store(path = @pstore_file, **options)
    PStore.new(path, options.fetch(:thread_safe, false), journal: true,
               **options.slice(:compaction_threshold))
  end

  def read_all(path = @pstore_file)
    store = journal_store(path)
    result = nil
    store.transaction(true) { result = store.instance_variable_get(:@table).dup }
    result
  end

  # Parse concatenated framed records. Returns [payloads, torn_size]
  # where torn_size is the byte offset of the first unusable trailing
  # record (nil when every record verifies).
  def parse_frames(data)
    payloads = []
    offset = 0
    torn_size = nil
    while offset < data.bytesize
      frame = try_frame(data, offset)
      unless frame
        torn_size = offset
        break
      end
      end_offset, payload = frame
      payloads << payload
      offset = end_offset
    end
    [payloads, torn_size]
  end

  def try_frame(data, offset)
    available = data.bytesize - offset
    return nil if available < HEADER_SIZE
    header = data.byteslice(offset, HEADER_SIZE)
    return nil unless header.byteslice(0, 8) == MAGIC
    return nil unless header.getbyte(8) == 2
    payload_size = header.byteslice(9, 8).unpack1("Q>")
    frame_size = HEADER_SIZE + payload_size + DIGEST_SIZE
    return nil if available < frame_size
    signed = data.byteslice(offset, HEADER_SIZE + payload_size)
    digest = data.byteslice(offset + HEADER_SIZE + payload_size, DIGEST_SIZE)
    return nil unless Digest::SHA256.digest(signed) == digest
    [offset + frame_size, data.byteslice(offset + HEADER_SIZE, payload_size)]
  end

  def frame_count(data)
    count = 0
    offset = 0
    while (frame = try_frame(data, offset))
      offset = frame[0]
      count += 1
    end
    remaining = data.bytesize - offset
    [count, remaining == 0 ? nil : offset]
  end

  def run_worker(code, env = {})
    full = "require 'pstore'; #{code}"
    libdir = File.expand_path('../../lib', __FILE__)
    EnvUtil.invoke_ruby([clean_env(env), "-I#{libdir}", "-e", full],
                        "", true, true, timeout: 30)
  end

  # invoke_ruby builds a fresh environment for the child; strip bundler
  # related variables so an unrelated Bundler setup failure cannot mask
  # the worker's real result.
  def clean_env(extra = {})
    libdir = File.expand_path('../../lib', __FILE__)
    env = {"PATH" => ENV["PATH"], "HOME" => ENV["HOME"], "RUBYLIB" => libdir}
    # Ruby's spawn merges this hash into the inherited environment rather
    # than replacing it, so unwanted variables must be set to nil.
    ENV.each_key do |name|
      next if name == "PATH" || name == "HOME"
      if name.start_with?("BUNDLE") || name.start_with?("GEM") ||
          name == "RUBYOPT" || name == "RUBYLIB" || name == "RUBYOPT" ||
          name.start_with?("RUBY_")
        env[name] = nil
      end
    end
    env["RUBYLIB"] = libdir
    env.update(extra)
    env
  end

  # -- Basic behaviour -------------------------------------------------

  def test_journal_mode_is_opt_in
    store = PStore.new(@pstore_file)
    assert_equal(false, store.journal?)
    assert_equal(true, @pstore.journal?)
  end

  def test_first_commit_creates_snapshot
    @pstore.transaction { |s| s[:a] = 1 }
    assert(File.exist?(@pstore_file))
    assert(File.exist?(@journal_file))
    data = File.binread(@pstore_file)
    assert_equal(MAGIC, data.byteslice(0, 8))
    frame = try_frame(data, 0)
    assert_not_nil(frame)
    _size, payload = frame
    assert_equal({a: 1}, Marshal.load(payload))
    assert_equal(0, File.size?(@journal_file) || 0)
  end

  def test_small_change_appends_instead_of_rewriting
    @pstore.transaction { |s| s[:big] = "x" * 5000; s[:counter] = 0 }
    snapshot_size = File.size(@pstore_file)
    @pstore.transaction { |s| s[:counter] = 1 }
    assert_equal(snapshot_size, File.size(@pstore_file),
                 "snapshot must not be rewritten for a small append")
    journal = File.binread(@journal_file)
    count, torn = frame_count(journal)
    assert_nil(torn)
    assert_equal(1, count)
    assert_equal(1, read_all[:counter])
  end

  def test_each_changing_transaction_is_one_verified_record
    3.times { |i| @pstore.transaction { |s| s[:k] = i } }
    # First txn compacts (no snapshot yet); following two append.
    payloads, torn = parse_frames(File.binread(@journal_file))
    assert_nil(torn)
    assert_equal(2, payloads.size)
    assert_equal({"u" => {k: 1}, "d" => []}, Marshal.load(payloads[0]))
    assert_equal({"u" => {k: 2}, "d" => []}, Marshal.load(payloads[1]))
  end

  def test_no_change_transaction_writes_nothing
    @pstore.transaction { |s| s[:a] = "y" * 100 }
    File.delete(@journal_file) if File.exist?(@journal_file)
    snapshot_before = File.binread(@pstore_file)
    @pstore.transaction { }
    @pstore.transaction(true) { |s| s[:a] }
    @pstore.transaction { |s| s[:a] = "y" * 100 }
    assert(!File.exist?(@journal_file) || File.size(@journal_file) == 0,
           "no commit record should be appended")
    assert_equal(snapshot_before, File.binread(@pstore_file))
  end

  def test_in_place_nested_mutation_is_recorded
    @pstore.transaction do |s|
      s[:items] = []
      s[:config] = {flags: Set_like.new([1])}
    end
    @pstore.transaction do |s|
      s[:items] << :new_item
      s[:config][:flags].values << 2
      s[:config][:added] = true
    end
    reopened = read_all
    assert_equal([:new_item], reopened[:items])
    assert_equal([1, 2], reopened[:config][:flags].values)
    assert_equal(true, reopened[:config][:added])
  end

  def test_mutation_via_fetch_is_recorded
    @pstore.transaction { |s| s[:a] = {n: 1} }
    @pstore.transaction { |s| s.fetch(:a)[:n] = 2 }
    assert_equal({n: 2}, read_all[:a])
  end

  def test_mutated_then_reverted_writes_nothing
    @pstore.transaction { |s| s[:a] = [1] }
    @pstore.transaction do |s|
      s[:a] << 2
      s[:a].pop
    end
    assert(!File.exist?(@journal_file) || File.size(@journal_file) == 0)
  end

  def test_in_place_key_mutation_is_preserved
    key = [1, 2]
    @pstore.transaction { |s| s[key] = "v" }
    @pstore.transaction { |s| s.keys.first << 3 }
    assert_equal([[1, 2, 3]], read_all.keys)
    # Anomaly forces a full snapshot, so the journal stays empty.
    assert_equal(0, File.size(@journal_file))
  end

  def test_keys_and_keyp_work_outside_tracking
    @pstore.transaction { |s| s[:a] = 1 }
    assert_equal([:a], @pstore.transaction(true) { |s| s.keys })
    assert_equal(true, @pstore.transaction(true) { |s| s.key?(:a) })
    assert_equal([:a], @pstore.transaction(true) { |s| s.roots })
  end

  def test_delete_is_recorded_and_replayed
    @pstore.transaction { |s| s[:a] = 1; s[:b] = 2 }
    @pstore.transaction { |s| s.delete(:a) }
    assert_equal([:b], read_all.keys)
    _payloads, torn = parse_frames(File.binread(@journal_file))
    assert_nil(torn)
  end

  def test_add_then_delete_in_one_transaction_writes_nothing
    @pstore.transaction { |s| s[:keep] = 1 }
    @pstore.transaction { |s| s[:ghost] = 2; s.delete(:ghost) }
    assert_equal([:keep], read_all.keys)
    assert(!File.exist?(@journal_file) || File.size(@journal_file) == 0)
  end

  # Minimal object wrapping an Array so the test does not need 'set'.
  class Set_like
    attr_reader :values
    def initialize(values)
      @values = values
    end
    def ==(other)
      other.is_a?(Set_like) && other.values == @values
    end
  end

  # -- Compaction and log rotation -------------------------------------

  def test_compaction_rotates_when_threshold_reached
    store = journal_store(compaction_threshold: 100)
    100.times do |i|
      store.transaction { |s| s["k#{i}"] = "x" * 40 }
    end
    assert(File.size(@journal_file) < 1000, "journal should be compacted repeatedly")
    data = File.binread(@journal_file)
    _payloads, torn = parse_frames(data)
    assert_nil(torn)
    reopened = read_all
    assert_equal(100, reopened.size)
    assert_equal("x" * 40, reopened["k99"])
  end

  def test_repeated_compaction_keeps_full_state
    store = journal_store(compaction_threshold: 100)
    100.times do |i|
      store.transaction do |s|
        s["k#{i}"] = i
        (s["arr"] ||= []) << i
      end
    end
    reopened = read_all
    assert_equal(101, reopened.size)
    assert_equal((0...100).to_a, reopened["arr"])
    snapshot = File.binread(@pstore_file)
    assert_not_nil(try_frame(snapshot, 0))
  end

  def test_threshold_zero_compacts_every_changing_transaction
    store = journal_store(compaction_threshold: 0)
    5.times { |i| store.transaction { |s| s[:k] = i } }
    assert_equal(0, File.size(@journal_file))
    assert_equal(4, read_all[:k])
  end

  def test_nil_threshold_disables_size_compaction
    store = journal_store(compaction_threshold: nil)
    10.times { |i| store.transaction { |s| s[:k] = i } }
    count, torn = frame_count(File.binread(@journal_file))
    assert_nil(torn)
    assert_operator(count, :>=, 9)
    assert_equal(9, read_all[:k])
  end

  def test_invalid_threshold_is_rejected
    assert_raise(PStore::Error) do
      PStore.new(@pstore_file, journal: true, compaction_threshold: -1)
    end
    assert_raise(PStore::Error) do
      PStore.new(@pstore_file, journal: true, compaction_threshold: "1")
    end
  end

  # -- Corruption handling ---------------------------------------------

  def write_three_records
    @pstore.transaction { |s| s[:a] = "1" }
    @pstore.transaction { |s| s[:b] = "2" }
    @pstore.transaction { |s| s[:c] = "3" }
  end

  def test_truncated_tail_is_tolerated
    write_three_records
    data = File.binread(@journal_file)
    File.binwrite(@journal_file, data.byteslice(0, data.bytesize - 3))

    store = journal_store
    assert_equal([:a, :b], store.transaction(true) { |s| s.keys.sort })
    # Read-write open removes the torn tail.
    store.transaction { |s| s[:d] = "4" }
    payloads, torn = parse_frames(File.binread(@journal_file))
    assert_nil(torn)
    assert_equal([:a, :b, :d], read_all.keys.sort)
  end

  def test_corrupt_last_digest_is_treated_as_torn_tail
    write_three_records
    data = File.binread(@journal_file)
    corrupted = data.dup
    corrupted.setbyte(data.bytesize - 1, corrupted.getbyte(data.bytesize - 1) ^ 0xFF)
    File.binwrite(@journal_file, corrupted)

    assert_equal([:a, :b], journal_store.transaction(true) { |s| s.keys.sort })
    journal_store.transaction { }
    assert_equal([:a, :b], read_all.keys.sort)
  end

  def test_corrupt_middle_digest_raises
    write_three_records
    data = File.binread(@journal_file)
    first_frame_size = frame_end(data, 0)
    corrupted = data.dup
    corrupted.setbyte(first_frame_size - 1,
                      corrupted.getbyte(first_frame_size - 1) ^ 0xFF)
    File.binwrite(@journal_file, corrupted)

    assert_raise(PStore::Error) do
      journal_store.transaction(true) { |s| s.keys }
    end
    assert_raise(PStore::Error) do
      journal_store.transaction { |s| s[:x] = 1 }
    end
  end

  def test_garbage_between_records_is_mid_corruption
    write_three_records
    data = File.binread(@journal_file)
    cut = frame_end(data, 0)
    File.binwrite(@journal_file,
                  data.byteslice(0, cut) + "GARBAGE!!" +
                    data.byteslice(cut, data.bytesize - cut))
    assert_raise(PStore::Error) do
      journal_store.transaction(true) { |s| s.keys }
    end
  end

  def frame_end(data, offset)
    end_offset, _payload = try_frame(data, offset)
    end_offset
  end

  def test_snapshot_corruption_raises
    @pstore.transaction { |s| s[:a] = 1 }
    data = File.binread(@pstore_file)
    corrupted = data.dup
    corrupted.setbyte(data.bytesize - 5,
                      corrupted.getbyte(data.bytesize - 5) ^ 0xFF)
    File.binwrite(@pstore_file, corrupted)
    assert_raise(PStore::Error) do
      journal_store.transaction(true) { |s| s.keys }
    end
  end

  # -- Classic format interoperation -----------------------------------

  def test_plain_file_is_readable_and_migrated_on_first_change
    classic = PStore.new(@pstore_file)
    classic.transaction { |s| s[:old] = [1, 2]; s[:keep] = true }

    assert_equal([1, 2], journal_store.transaction(true) { |s| s[:old] })
    refute(File.binread(@pstore_file).start_with?(MAGIC),
           "read-only journal open must not touch the plain file")

    journal_store.transaction { }
    refute(File.binread(@pstore_file).start_with?(MAGIC),
           "read-write journal open without changes must not migrate")
    assert(!File.exist?(@journal_file))

    journal_store.transaction { |s| s[:old] << 3; s[:new] = "v" }
    assert(File.binread(@pstore_file).start_with?(MAGIC))
    reopened = read_all
    assert_equal([1, 2, 3], reopened[:old])
    assert_equal(true, reopened[:keep])
    assert_equal("v", reopened[:new])

    assert_raise(TypeError, EOFError) do
      classic.transaction(true) { |s| s.keys }
    end
  end

  def test_plain_format_default_remains_marshal
    store = PStore.new(@pstore_file)
    store.transaction { |s| s[:a] = 1 }
    data = File.binread(@pstore_file)
    assert_equal(Marshal.dump({a: 1}), data)
    refute(data.start_with?(MAGIC))
  end

  # -- Crash recovery with real child processes ------------------------

  WORKER_SETUP = <<~RUBY
    path = ENV["PS_PATH"]
    s = PStore.new(path, journal: true)
    s.transaction { |st| st[:base] = [1, 2] }
    s.transaction { |st| st[:base] << 3; st[:second] = "y" }
  RUBY

  CRASH_WORKER = <<~RUBY
    path = ENV["PS_PATH"]
    s = PStore.new(path, journal: true, compaction_threshold: Integer(ENV["PS_THRESHOLD"]))
    s.transaction { |st| st[:base] << 4; st[:after] = true }
  RUBY

  def crash_setup
    env = {"PS_PATH" => @pstore_file}
    out, err, status = run_worker(WORKER_SETUP, env)
    assert(status.success?, err)
  end

  def assert_recovery(expected)
    out, err, status = run_worker(
      "s = PStore.new(ENV['PS_PATH'], journal: true); "\
      "s.transaction(true) { |st| "\
      "print({base: st[:base], second: st[:second], after: st[:after]}.inspect) }",
      {"PS_PATH" => @pstore_file})
    assert(status.success?, err)
    assert_equal(expected.inspect, out.dup.force_encoding(Encoding::US_ASCII))
  end

  def assert_crashed(status)
    assert(status.signaled? || !status.success?,
             "expected the worker to be killed, status=#{status.inspect}")
  end

  {"append_header" => {base: [1, 2, 3], second: "y", after: nil},
   "append_payload" => {base: [1, 2, 3], second: "y", after: nil},
   "append_fsync" => {base: [1, 2, 3], second: "y", after: nil}}.each do |point, expected|
    define_method("test_crash_during_append_#{point}") do
      crash_setup
      _out, _err, status = run_worker(CRASH_WORKER,
                                      {"PS_PATH" => @pstore_file,
                                       "PS_THRESHOLD" => (1024 * 1024).to_s,
                                       "PSTORE_CRASH_AT" => point})
      assert_crashed(status)
      assert_recovery(expected)
    end
  end

  def test_crash_after_digest_preserves_commit
    crash_setup
    _out, _err, status = run_worker(CRASH_WORKER,
                                    {"PS_PATH" => @pstore_file,
                                     "PS_THRESHOLD" => (1024 * 1024).to_s,
                                     "PSTORE_CRASH_AT" => "append_digest"})
    assert_crashed(status)
    assert_recovery(base: [1, 2, 3, 4], second: "y", after: true)
  end

  {"snapshot_write" => {base: [1, 2, 3], second: "y", after: nil},
   "snapshot_fsync" => {base: [1, 2, 3], second: "y", after: nil},
   "snapshot_rename" => {base: [1, 2, 3], second: "y", after: true},
   "journal_rotate" => {base: [1, 2, 3, 4], second: "y", after: true}}.each do |point, expected|
    define_method("test_crash_during_compaction_#{point}") do
      crash_setup
      _out, _err, status = run_worker(CRASH_WORKER,
                                      {"PS_PATH" => @pstore_file,
                                       "PS_THRESHOLD" => "1",
                                       "PSTORE_CRASH_AT" => point})
      assert_crashed(status)
      assert_recovery(expected)
      # A later transaction must also work after every crash point.
      _o, e, st = run_worker(
        "PStore.new(ENV['PS_PATH'], journal: true)." \
        "transaction { |s| s[:later] = 'ok' }",
        {"PS_PATH" => @pstore_file})
      assert(st.success?, e)
      assert_equal("ok", read_all[:later])
    end
  end

  # -- Cross-process locking -------------------------------------------

  LOCK_WRITER = <<~RUBY
    s = PStore.new(ENV['PS_PATH'], journal: true)
    s.transaction { |st| st[:holding] = true; STDOUT.write('LOCKED'); STDOUT.flush; sleep 3 }
  RUBY

  def test_writers_are_serialized_across_processes
    env = clean_env("PS_PATH" => @pstore_file)
    libdir = File.expand_path('../../lib', __FILE__)
    _i1, o1, _e1, w1 = Open3.popen3(env, EnvUtil.rubybin, "-I#{libdir}", "-e",
                                   "require 'pstore'; #{LOCK_WRITER}")
    assert_equal("LOCKED", o1.read(6))

    started = Time.now
    out, err, status = run_worker(
      "PStore.new(ENV['PS_PATH'], journal: true).transaction { |s| s[:second] = 2 }",
      env)
    elapsed = Time.now - started
    assert(status.success?, err)
    assert_operator(elapsed, :>=, 2.0)
    w1.join

    reopened = read_all
    assert_equal(true, reopened[:holding])
    assert_equal(2, reopened[:second])
  end

  def test_readers_do_not_block_each_other
    env = clean_env("PS_PATH" => @pstore_file)
    libdir = File.expand_path('../../lib', __FILE__)
    reader_code =
      "require 'pstore'; PStore.new(ENV['PS_PATH'], journal: true)." \
      "transaction(true) { sleep 2 }"
    args = [env, EnvUtil.rubybin, "-I#{libdir}", "-e", reader_code]
    _i1, _o1, _e1, r1 = Open3.popen3(*args)
    sleep 0.5
    started = Time.now
    out, err, status = run_worker(
      "PStore.new(ENV['PS_PATH'], journal: true).transaction(true) { |s| s[:a] }",
      env)
    assert(status.success?, err)
    assert_operator(Time.now - started, :<, 1.5)
    r1.join
  end
end
