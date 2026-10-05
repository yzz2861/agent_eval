# frozen_string_literal: true
require 'test/unit'
require 'pstore'
require 'tmpdir'
require 'pathname'
require 'rbconfig'
require 'timeout'

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

  def test_thread_lock_timeout_does_not_run_block_or_leave_lock
    store = PStore.new(second_file, true)
    ready = Thread::Queue.new
    release = Thread::Queue.new
    owner = Thread.new do
      store.transaction do
        ready << true
        release.pop
      end
    end
    executed = false

    ready.pop
    error = assert_raise(PStore::ThreadLockTimeoutError) do
      store.transaction(lock_timeout: 0.05) { executed = true }
    end

    assert_equal(:thread, error.lock)
    assert_kind_of(PStore::LockTimeoutError, error)
    refute(executed)
  ensure
    release&.<< true
    owner&.join
    refute(store.instance_variable_get(:@lock).locked?)
    File.unlink(second_file) rescue nil
  end

  def test_file_lock_timeout_releases_thread_lock_and_skips_block
    omit('advisory file locks are not supported on Windows') if Gem.win_platform?

    store = PStore.new(second_file, true)
    executed = false
    file_wait_started = Thread::Queue.new
    original_lock_file = store.method(:lock_file)
    store.define_singleton_method(:lock_file) do |*args|
      file_wait_started << true
      original_lock_file.call(*args)
    end

    IO.popen([RbConfig.ruby, "-I#{lib_dir}", '-rpstore', '-e', CHILD_PROCESS_LOCK_SCRIPT, second_file], 'r+') do |io|
      assert_equal("ready\n", io.gets)

      error = assert_raise(PStore::FileLockTimeoutError) do
        store.transaction(lock_timeout: 0.05) { executed = true }
      end
      assert_equal(:file, error.lock)
      refute(executed)
      refute(store.instance_variable_get(:@lock).locked?)
      file_wait_started.pop

      waiter = Thread.new do
        store.transaction { executed = true }
      end
      file_wait_started.pop
      waiter.kill
      waiter.join

      refute(executed)
      refute(store.instance_variable_get(:@lock).locked?)

      io.puts('release')
      io.flush
    end

    store.transaction(lock_timeout: nil) { store[:recovered] = true }
    assert_equal(true, store.transaction(true) { store[:recovered] })
  ensure
    File.unlink(second_file) rescue nil
  end

  def test_thread_and_file_lock_waits_share_one_deadline
    omit('advisory file locks are not supported on Windows') if Gem.win_platform?

    store = PStore.new(second_file, true)
    current_time = 1.0
    store.define_singleton_method(:monotonic_time) { current_time }

    waiter_started = Thread::Queue.new
    release_owner = Thread::Queue.new
    thread_wait_observed = Thread::Queue.new
    file_lock_attempt = Thread::Queue.new
    condition = store.instance_variable_get(:@lock_condition)
    condition.define_singleton_method(:wait) do |mutex, timeout|
      waiter_started << true
      thread_wait_observed << timeout
      super(mutex, 0.001)
    end
    original_lock_file = store.method(:lock_file)
    store.define_singleton_method(:lock_file) do |file, read_only, deadline|
      file_lock_attempt.pop
      current_time += 0.1
      result = original_lock_file.call(file, read_only, deadline)
      result
    end

    owner = Thread.new do
      store.send(:lock_transaction_lock, 1.1)
      release_owner.pop
      current_time += 0.05
      store.send(:unlock_transaction_lock)
    end

    executed = false
    owner_released = false
    IO.popen([RbConfig.ruby, "-I#{lib_dir}", '-rpstore', '-e', CHILD_PROCESS_LOCK_SCRIPT, second_file], 'r+') do |io|
      assert_equal("ready\n", io.gets)
      waiter = Thread.new do
        Thread.current.report_on_exception = false
        store.transaction(lock_timeout: 0.1) { executed = true }
      end
      waiter_started.pop
      release_owner << true
      owner_released = true
      file_lock_attempt << true

      error = assert_raise(PStore::FileLockTimeoutError) do
        Timeout.timeout(2) { waiter.join }
      end
      assert_equal(:file, error.lock)
      thread_wait = thread_wait_observed.pop
      assert_operator(thread_wait, :>, 0.0)
      assert_in_delta(0.1, thread_wait, 0.0001)
      refute(executed)
      refute(store.instance_variable_get(:@lock).locked?)
      io.puts('release')
      io.flush
    end
  ensure
    release_owner << true unless owner_released
    owner&.join
    File.unlink(second_file) rescue nil
  end

  def test_exception_inside_block_releases_both_locks
    store = PStore.new(second_file, true)

    assert_raise(RuntimeError) do
      store.transaction(lock_timeout: 1) { raise 'boom' }
    end

    assert_nothing_raised do
      store.transaction(lock_timeout: 1) { store[:recovered] = true }
    end
    assert_equal(true, store.transaction(true) { store[:recovered] })
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

  def lib_dir
    File.expand_path('../lib', __dir__)
  end

  CHILD_PROCESS_LOCK_SCRIPT = <<~'RUBY'
    store = PStore.new(ARGV[0])
    store.transaction do
      puts 'ready'
      STDOUT.flush
      STDIN.gets
    end
  RUBY

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
end
