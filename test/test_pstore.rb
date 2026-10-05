# frozen_string_literal: true
require 'test/unit'
require 'pstore'
require 'tmpdir'
require 'pathname'

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

  def test_thread_lock_timeout
    pstore = PStore.new(second_file, true)
    ready = Thread::Queue.new
    release = Thread::Queue.new
    holder = Thread.new do
      pstore.transaction do
        ready << true
        release.pop
      end
    end
    ready.pop

    executed = false
    error = assert_raise(PStore::LockTimeoutError) do
      pstore.transaction(lock_timeout: 0.1) { executed = true }
    end
    assert_equal(:thread, error.lock_type)
    assert_equal(false, executed)

    release << true
    holder.join
    # The timed-out call left no lock behind.
    assert_equal("ok", pstore.transaction { pstore[:after] = "ok" })
  ensure
    release << true if release && holder&.alive?
    holder&.join
    File.unlink(second_file) rescue nil
  end

  def test_file_lock_timeout
    @pstore.transaction { @pstore[:foo] = "bar" }
    with_externally_locked_file(@pstore_file) do
      executed = false
      error = assert_raise(PStore::LockTimeoutError) do
        @pstore.transaction(lock_timeout: 0.1) { executed = true }
      end
      assert_equal(:file, error.lock_type)
      assert_equal(false, executed)
    end
    # The timed-out call left no lock behind.
    assert_equal("bar", @pstore.transaction(true) { @pstore[:foo] })
  end

  def test_file_lock_timeout_in_read_only_mode
    @pstore.transaction { @pstore[:foo] = "bar" }
    with_externally_locked_file(@pstore_file) do
      executed = false
      error = assert_raise(PStore::LockTimeoutError) do
        @pstore.transaction(true, lock_timeout: 0.1) { executed = true }
      end
      assert_equal(:file, error.lock_type)
      assert_equal(false, executed)
    end
  end

  def test_file_lock_timeout_releases_thread_lock
    pstore = PStore.new(second_file, true)
    with_externally_locked_file(second_file) do
      assert_raise(PStore::LockTimeoutError) do
        pstore.transaction(lock_timeout: 0.1) { flunk("block must not run") }
      end
    end
    # Failing to acquire the file lock must not leak the thread lock.
    assert_equal("ok", pstore.transaction { pstore[:after] = "ok" })
  ensure
    File.unlink(second_file) rescue nil
  end

  def test_nested_transaction_with_lock_timeout_raises_error
    pstore = PStore.new(second_file, true)
    error = assert_raise(PStore::Error) do
      pstore.transaction(lock_timeout: 5) do
        pstore.transaction(lock_timeout: 5) { }
      end
    end
    assert_equal("nested transaction", error.message)
  ensure
    File.unlink(second_file) rescue nil
  end

  def test_lock_timeout_succeeds_without_contention
    assert_equal(1, @pstore.transaction(lock_timeout: 0) { 1 })
    pstore = PStore.new(second_file, true)
    assert_equal(2, pstore.transaction(lock_timeout: 0) { 2 })
  ensure
    File.unlink(second_file) rescue nil
  end

  # Holds an exclusive flock on +path+ in a child process while the
  # block runs. Pipes are used as a handshake so no sleeping is involved.
  def with_externally_locked_file(path)
    child_stdin = IO.pipe
    child_stdout = IO.pipe
    pid = Process.spawn(
      RbConfig.ruby, "-e",
      "f = File.open(ARGV[0], #{File::RDWR | File::CREAT | File::BINARY}); " +      "f.flock(File::LOCK_EX); puts 'locked'; STDOUT.flush; STDIN.gets",
      path,
      in: child_stdin[0], out: child_stdout[1]
    )
    child_stdin[0].close
    child_stdout[1].close
    child_stdout[0].gets # Wait until the child holds the lock.
    yield
  ensure
    child_stdin[1].close if child_stdin && !child_stdin[1].closed?
    child_stdout[0].close if child_stdout && !child_stdout[0].closed?
    Process.wait(pid) if pid
  end
end
