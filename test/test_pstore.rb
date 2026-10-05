# frozen_string_literal: true
require 'test/unit'
require 'pstore'
require 'tmpdir'
require 'pathname'
require 'rbconfig'
require 'fileutils'

class PStoreTest < Test::Unit::TestCase
  def setup
    @pstore_file = File.join(Dir.tmpdir, "pstore.tmp.#{Process.pid}")
    @pstore = PStore.new(@pstore_file)
  end

  def teardown
    File.unlink(@pstore_file) rescue nil
  end

  def test_opening_new_file_in_readonly_mode_should_result_in_empty_values
    @pstore.transaction(true) do
      assert_nil @pstore[:foo]
      assert_nil @pstore[:bar]
    end
  end

  def test_opening_new_file_in_readwrite_mode_should_result_in_empty_values
    @pstore.transaction do
      assert_nil @pstore[:foo]
      assert_nil @pstore[:bar]
    end
  end

  def test_data_should_be_loaded_correctly_when_in_readonly_mode
    @pstore.transaction do
      @pstore[:foo] = "bar"
    end
    @pstore.transaction(true) do
      assert_equal "bar", @pstore[:foo]
    end
  end

  def test_data_should_be_loaded_correctly_when_in_readwrite_mode
    @pstore.transaction do
      @pstore[:foo] = "bar"
    end
    @pstore.transaction do
      assert_equal "bar", @pstore[:foo]
    end
  end

  def test_changes_after_commit_are_discarded
    @pstore.transaction do
      @pstore[:foo] = "bar"
      @pstore.commit
      @pstore[:foo] = "baz"
    end
    @pstore.transaction(true) do
      assert_equal "bar", @pstore[:foo]
    end
  end

  def test_changes_are_not_written_on_abort
    @pstore.transaction do
      @pstore[:foo] = "bar"
      @pstore.abort
    end
    @pstore.transaction(true) do
      assert_nil @pstore[:foo]
    end
  end

  def test_data_should_be_stored_correctly_when_in_ultra_safe_mode
    @pstore.ultra_safe = true
    @pstore.transaction do
      @pstore[:foo] = "bar"
    end
    @pstore.transaction(true) do
      assert_equal "bar", @pstore[:foo]
    end
  end

  def test_ultra_safe_mode_preserves_file_mode
    omit("ultra_safe mode is not supported on Windows") if Gem.win_platform?

    @pstore.transaction { |store| store[:foo] = "bar" }
    File.chmod(0o600, @pstore_file)
    @pstore.ultra_safe = true

    original_umask = File.umask(0o000)
    @pstore.transaction { |store| store[:foo] = "baz" }

    assert_equal 0o600, File.stat(@pstore_file).mode & 0o7777
  ensure
    File.umask(original_umask) if original_umask
  end

  def test_writing_inside_readonly_transaction_raises_error
    assert_raise(PStore::Error) do
      @pstore.transaction(true) do
        @pstore[:foo] = "bar"
      end
    end
  end

  def test_thread_safe
    q1 = Thread::Queue.new
    assert_raise(PStore::Error) do
      th = Thread.new do
        @pstore.transaction do
          @pstore[:foo] = "bar"
          q1.push true
          sleep
        end
      end
      begin
        q1.pop
        @pstore.transaction {}
      ensure
        th.kill
        th.join
      end
    end
    q2 = Thread::Queue.new
    begin
      pstore = PStore.new(second_file, true)
      cur = Thread.current
      th = Thread.new do
        pstore.transaction do
          pstore[:foo] = "bar"
          q1.push true
          q2.pop
          # wait for cur to enter a transaction
          sleep 0.1 until cur.stop?
        end
      end
      begin
        q1.pop
        q2.push true
        assert_equal("bar", pstore.transaction { pstore[:foo] })
      ensure
        th.join
      end
    end
  ensure
    File.unlink(second_file) rescue nil
  end

  def test_nested_transaction_raises_error
    assert_raise(PStore::Error) do
      @pstore.transaction { @pstore.transaction { } }
    end
    pstore = PStore.new(second_file, true)
    assert_raise(PStore::Error) do
      pstore.transaction { pstore.transaction { } }
    end
  ensure
    File.unlink(second_file) rescue nil
  end

  # Test that PStore's file operations do not blow up when default encodings are set
  def test_pstore_files_are_accessed_as_binary_files
    bug5311 = '[ruby-core:39503]'
    n = 128
    top_dir = File.expand_path('../lib', __dir__)
    assert_in_out_err(["-Eutf-8:utf-8", "-I#{top_dir}", "-rpstore", "-", @pstore_file], <<-SRC, [bug5311], [], bug5311, timeout: 30)
      @pstore = PStore.new(ARGV[0])
      (1..#{n}).each do |i|
        @pstore.transaction {@pstore["Key\#{i}"] = "value \#{i}"}
      end
      @pstore.transaction {@pstore["Bug5311"] = '#{bug5311}'}
      puts @pstore.transaction {@pstore["Bug5311"]}
    SRC
    assert_equal(bug5311, @pstore.transaction {@pstore["Bug5311"]}, bug5311)
  end

  def test_key_p
    [:key?, :root?].each do |method|
      clear_store
      @pstore.transaction do
        @pstore[:foo] = 0
        assert_equal(true, @pstore.send(method, :foo))
        assert_equal(false, @pstore.send(method, :bar))
      end
    end
  end

  def test_keys
    [:keys, :roots].each do |method|
      clear_store
      @pstore.transaction do
        assert_equal([], @pstore.send(method))
      end
      @pstore.transaction do
        @pstore[:foo] = 0
        assert_equal([:foo], @pstore.send(method))
      end
    end
  end

  def clear_store
    @pstore.transaction do
      @pstore.keys.each do |key|
        @pstore.delete(key)
      end
    end
  end

  def second_file
    File.join(Dir.tmpdir, "pstore.tmp2.#{Process.pid}")
  end

  def test_truncated_read_only_store_is_not_empty
    @pstore.transaction { @pstore[:foo] = "bar" }
    data = File.binread(@pstore_file)
    File.binwrite(@pstore_file, data.byteslice(0, data.bytesize - 1))

    assert_raise(EOFError) { @pstore.transaction(true) { @pstore[:foo] } }
  end

  def test_store_operations_require_transaction_owner
    ready = Thread::Queue.new
    release = Thread::Queue.new
    owner = Thread.new do
      @pstore.transaction do
        @pstore[:foo] = "bar"
        ready << true
        release.pop
      end
    end

    ready.pop
    assert_raise(PStore::Error) { @pstore[:foo] }
    assert_raise(PStore::Error) { @pstore[:foo] = "other" }
  ensure
    release << true if release
    owner.join if owner
  end

  def test_commit_targets_the_owning_store
    inner = PStore.new(second_file)
    @pstore.transaction do
      @pstore[:outer] = true
      inner.transaction do
        inner[:inner] = true
        @pstore.commit
        flunk("outer commit should exit its own transaction")
      end
      flunk("outer commit should exit its own transaction")
    end

    assert_equal(true, @pstore.transaction(true) { @pstore[:outer] })
    assert_nil(inner.transaction(true) { inner[:inner] })
  ensure
    File.unlink(second_file) rescue nil
  end

  def test_fetch_compares_missing_default_by_identity
    default = Object.new
    def default.==(_other)
      true
    end

    assert_same(default, @pstore.transaction(true) { @pstore.fetch(:missing, default) })
  end

  def test_lock_retries_when_atomic_save_replaces_file
    fake_file = Struct.new(:closed) do
      def flock(_mode)
        true
      end

      def close
        self.closed = true
      end
    end
    first = fake_file.new(false)
    second = fake_file.new(false)
    files = [first, second]
    original_new = File.method(:new)
    original_identical = File.method(:identical?)
    EnvUtil.suppress_warning do
      File.define_singleton_method(:new) { |*_args, **_kwargs| files.shift }
      File.define_singleton_method(:identical?) { |file, _path| file.equal?(second) }
    end

    result = @pstore.send(:open_and_lock_file, @pstore_file, false)

    assert_same(second, result)
    assert_equal(true, first.closed)
    assert_equal(false, second.closed)
  ensure
    result.close if result && !result.closed
    EnvUtil.suppress_warning do
      File.define_singleton_method(:new, original_new) if original_new
      File.define_singleton_method(:identical?, original_identical) if original_identical
    end
  end

  def test_interrupted_atomic_save_removes_temporary_file
    return if /mswin|mingw|bccwin|wince/ =~ RUBY_PLATFORM

    @pstore.transaction { @pstore[:foo] = "old" }
    @pstore.ultra_safe = true
    original_new = File.method(:new)
    store_path = @pstore_file
    EnvUtil.suppress_warning do
      File.define_singleton_method(:new) do |path, **options|
        file = original_new.call(path, **options)
        if path.start_with?("#{store_path}.tmp.")
          file.define_singleton_method(:write) { |_data| raise Interrupt }
        end
        file
      end
    end

    assert_raise(Interrupt) { @pstore.transaction { @pstore[:foo] = "new" } }
    assert_equal([], Dir.glob("#{@pstore_file}.tmp.*"))
    assert_equal("old", @pstore.transaction(true) { @pstore[:foo] })
  ensure
    EnvUtil.suppress_warning do
      File.define_singleton_method(:new, original_new) if original_new
    end
    Dir.glob("#{@pstore_file}.tmp.*").each { |path| File.unlink(path) rescue nil }
  end

  def test_path_like_filename_is_normalized
    store = PStore.new(Pathname(@pstore_file))
    store.ultra_safe = true
    store.transaction { store[:foo] = "bar" }

    assert_instance_of(String, store.path)
    assert_equal(@pstore_file, store.path)
    assert_equal("bar", store.transaction(true) { store[:foo] })
  end

  def test_multi_store_transaction_publishes_both_stores
    with_multi_stores do |a_path, b_path, a, b|
      PStore.coordinate(a, b) do |first, second|
        first[:value] = "new"
        second[:value] = "new"
      end

      assert_equal("new", PStore.new(a_path).transaction(true) { _1[:value] })
      assert_equal("new", PStore.new(b_path).transaction(true) { _1[:value] })
      assert_equal(["a.store", "b.store"], Dir.children(File.dirname(a_path)).sort)
    end
  end

  def test_multi_store_transaction_preserves_file_modes
    omit("file mode checks are not supported on Windows") if Gem.win_platform?

    with_multi_stores do |a_path, b_path, a, b|
      a.transaction { a[:value] = "old" }
      b.transaction { b[:value] = "old" }
      File.chmod(0o600, a_path)
      File.chmod(0o640, b_path)

      PStore.coordinate(a, b) do |first, second|
        first[:value] = "new"
        second[:value] = "new"
      end

      assert_equal(0o600, File.stat(a_path).mode & 0o7777)
      assert_equal(0o640, File.stat(b_path).mode & 0o7777)
    end
  end

  def test_multi_store_failure_rolls_back_without_rerunning_block
    with_multi_stores do |a_path, b_path, a, b|
      a.transaction { a[:value] = "old" }
      b.transaction { b[:value] = "old" }
      counter = File.join(File.dirname(a_path), "counter")
      assert_raise(RuntimeError) do
        PStore.coordinate(a, b) do |first, second|
          File.write(counter, File.exist?(counter) ? File.read(counter).next + "1" : "1")
          first[:value] = "new"
          second[:value] = "new"
          raise "boom"
        end
      end

      assert_equal("1", File.read(counter))
      assert_equal("old", PStore.new(a_path).transaction(true) { _1[:value] })
      assert_equal("old", PStore.new(b_path).transaction(true) { _1[:value] })
      assert_equal(["a.store", "b.store", "counter"], Dir.children(File.dirname(a_path)).sort)
    end
  end

  def test_multi_store_recovers_after_kill_between_prepare_and_decision
    crash_multi_store_at("prepared") do |dir, _pid|
      assert_equal("old", raw_multi_value(File.join(dir, "a.store")))
      assert_equal("old", raw_multi_value(File.join(dir, "b.store")))
      assert_multi_artifacts_exist(dir, 2)

      reopen_multi_stores(dir, "old", "old")
      assert_multi_artifacts_removed(dir)
    end
  end

  def test_multi_store_recovers_after_kill_between_decision_and_publish
    crash_multi_store_at("decision") do |dir, _pid|
      assert_equal("old", raw_multi_value(File.join(dir, "a.store")))
      assert_equal("old", raw_multi_value(File.join(dir, "b.store")))
      assert_multi_artifacts_exist(dir, 2)

      reopen_multi_stores(dir, "new", "new")
      assert_multi_artifacts_removed(dir)
    end
  end

  def test_multi_store_recovers_after_kill_between_file_publications
    crash_multi_store_at("first_publish") do |dir, _pid|
      assert_equal("new", raw_multi_value(File.join(dir, "a.store")))
      assert_equal("old", raw_multi_value(File.join(dir, "b.store")))
      assert_multi_artifacts_exist(dir, 1)

      reopen_multi_stores(dir, "new", "new")
      assert_multi_artifacts_removed(dir)
    end
  end

  def test_missing_coordinator_record_fails
    with_multi_stores do |_a_path, _b_path, _a, _b|
      marker = PStore::TransactionRecovery.marker_path(@pstore_file, "missing")
      File.binwrite(marker, PStore::TransactionRecovery.dump_record(
        transaction_id: "missing",
        journal_path: File.join(File.dirname(@pstore_file), "missing-journal")
      ))

      error = assert_raise(PStore::Error) do
        @pstore.transaction(true) { @pstore[:foo] }
      end
      assert_match(/missing transaction recovery record/, error.message)
    end
  end

  def test_corrupt_coordinator_record_fails
    with_multi_stores do |_a_path, _b_path, _a, _b|
      journal = File.join(File.dirname(@pstore_file), "corrupt-journal")
      marker = PStore::TransactionRecovery.marker_path(@pstore_file, "corrupt")
      File.binwrite(journal, "not-a-marshal-record")
      File.binwrite(marker, PStore::TransactionRecovery.dump_record(
        transaction_id: "corrupt",
        journal_path: journal
      ))

      error = assert_raise(PStore::Error) do
        @pstore.transaction(true) { @pstore[:foo] }
      end
      assert_match(/corrupted transaction recovery record/, error.message)
    end
  end

  def test_multi_store_coordinator_locks_stores_in_stable_path_order
    with_multi_stores do |_a_path, _b_path, a, b|
      locked = []
      [a, b].each do |store|
        store.define_singleton_method(:lock_for_coordinator) do
          locked << path
          super()
        end
      end

      PStore.coordinate(b, a) { |_, _| }
      assert_equal([a.path, b.path].sort, locked)
    end
  end

  private

  def with_multi_stores
    Dir.mktmpdir("pstore-multi", tmp_root) do |dir|
      @pstore_file = File.join(dir, "a.store")
      @pstore = PStore.new(@pstore_file)
      a_path = File.join(dir, "a.store")
      b_path = File.join(dir, "b.store")
      yield(a_path, b_path, PStore.new(a_path), PStore.new(b_path))
    end
  end

  def crash_multi_store_at(stage)
    Dir.mktmpdir("pstore-crash", tmp_root) do |dir|
      counter = File.join(dir, "counter")
      script = File.join(dir, "crash.rb")
      File.write(script, multi_store_crash_script)
      pid = spawn(RbConfig.ruby, "-I#{File.expand_path("../lib", __dir__)}", script, dir, stage, counter)
      Process.wait(pid)
      assert_equal("1", File.read(counter))
      yield(dir, pid)
    end
  end

  def tmp_root
    root = File.expand_path("../tmp", __dir__)
    FileUtils.mkdir_p(root)
    root
  end

  def reopen_multi_stores(dir, a_value, b_value)
    a_path = File.join(dir, "a.store")
    b_path = File.join(dir, "b.store")
    assert_equal(a_value, PStore.new(a_path).transaction(true) { _1[:value] })
    assert_equal(b_value, PStore.new(b_path).transaction(true) { _1[:value] })
  end

  def raw_multi_value(path)
    data = File.binread(path)
    return nil if data.empty?
    Marshal.load(data)[:value]
  end

  def assert_multi_artifacts_exist(dir, expected_temps)
    assert(Dir.glob(File.join(dir, ".pstore-coordinator.*")).any?)
    assert(Dir.glob(File.join(dir, ".*.pstore-coordinator.*")).size >= 2)
    assert_equal(expected_temps, Dir.glob(File.join(dir, "*.tmp.pstore-coordinator.*")).size)
  end

  def assert_multi_artifacts_removed(dir)
    assert_equal([], Dir.glob(File.join(dir, ".pstore-coordinator.*")))
    assert_equal([], Dir.glob(File.join(dir, ".*.pstore-coordinator.*")))
    assert_equal([], Dir.glob(File.join(dir, "*.tmp.pstore-coordinator.*")))
  end

  def multi_store_crash_script
    <<~'RUBY'
      require "pstore"

      dir, stage, counter = ARGV
      a_path = File.join(dir, "a.store")
      b_path = File.join(dir, "b.store")
      a = PStore.new(a_path)
      b = PStore.new(b_path)

      PStore.coordinate(a, b) do |first, second|
        first[:value] = "old"
        second[:value] = "old"
      end

      CRASH_STAGE = stage

      class CrashCoordinator < PStore::TransactionCoordinator
        private

        def prepare
          record = super
          kill! if CRASH_STAGE == "prepared"
          record
        end

        def record_commit_decision(record)
          result = super
          kill! if CRASH_STAGE == "decision"
          result
        end

        def publish_participant(participant)
          result = super
          if CRASH_STAGE == "first_publish" && participant[:path].end_with?("/a.store")
            kill!
          end
          result
        end

        def kill!
          $stdout.flush
          Process.kill(:KILL, Process.pid)
          sleep
        end
      end

      module CrashCoordinate
        def coordinate(*stores, &block)
          CrashCoordinator.new(*stores).transaction(&block)
        end
      end
      PStore.singleton_class.prepend(CrashCoordinate)

      PStore.coordinate(a, b) do |first, second|
        File.write(counter, File.exist?(counter) ? File.read(counter).next : "1")
        first[:value] = "new"
        second[:value] = "new"
      end
    RUBY
  end
end
