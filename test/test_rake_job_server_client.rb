# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)
require "rake/job_server_client"
require "stringio"
require "fcntl"

class TestRakeJobServerClient < Rake::TestCase # :nodoc:
  CustomError = Class.new(StandardError)

  def test_uses_the_implicit_slot_without_borrowing
    read_io, write_io = IO.pipe
    client = Rake::JobServerClient.new(read_io, write_io, 1)

    token = client.acquire

    assert_equal :implicit, token.kind
    client.release(token)
  end

  def test_returns_a_borrowed_byte_unchanged_after_an_action
    read_io, write_io = IO.pipe
    write_io.write("+")
    client = Rake::JobServerClient.new(read_io, write_io, 2)

    implicit = client.acquire
    borrowed = client.acquire

    assert_equal :borrowed, borrowed.kind
    assert_equal "+", borrowed.byte

    client.release(borrowed)
    client.release(implicit)

    assert_equal "+", read_io.read_nonblock(1)
  end

  def test_releases_the_implicit_slot_when_an_action_raises
    read_io, write_io = IO.pipe
    client = Rake::JobServerClient.new(read_io, write_io, 1)

    assert_raises(CustomError) do
      client.synchronize { raise CustomError, "failed action" }
    end

    completed = false
    client.synchronize { completed = true }
    assert_equal true, completed
  end

  def test_releases_borrowed_byte_when_an_action_raises
    read_io, write_io = IO.pipe
    write_io.write("Z")
    client = Rake::JobServerClient.new(read_io, write_io, 2)
    client.acquire

    assert_raises(CustomError) do
      client.synchronize { raise CustomError, "failed action" }
    end

    assert_equal "Z", read_io.read_nonblock(1)
  end

  def test_release_all_returns_all_borrowed_bytes
    read_io, write_io = IO.pipe
    write_io.write("AB")
    client = Rake::JobServerClient.new(read_io, write_io, 3)

    client.acquire
    client.acquire
    client.acquire

    client.release_all

    returned = read_io.read_nonblock(2)
    assert_equal "AB", returned.chars.sort.join
  end

  def test_release_all_runs_at_application_exit
    read_io, write_io = IO.pipe
    write_io.write("Z")
    script_dir = File.join(@orig_pwd, "tmp-jobserver-test")
    FileUtils.mkdir_p(script_dir)
    script = File.join(script_dir, "jobserver_exit.rb")
    File.write(script, <<~RUBY)
      require "rake/job_server_client"
      client = Rake::JobServerClient.from_env
      client.acquire
      client.acquire
    RUBY
    env = {
      "MAKEFLAGS" => "--jobserver-auth=#{read_io.fileno},#{write_io.fileno} -j2"
    }
    pid = spawn(env, RUBY, "-I#{@rake_lib}", script,
      read_io.fileno => read_io.fileno,
      write_io.fileno => write_io.fileno,
      close_others: false)

    _pid, status = Process.wait2(pid)
    assert status.success?, "jobserver subprocess failed"
    read_io.wait_readable
    assert_equal "Z", read_io.read_nonblock(1)
  ensure
    FileUtils.rm_rf(script_dir) if defined?(script_dir)
  end

  def test_waits_until_a_borrowed_slot_is_returned
    read_io, write_io = IO.pipe
    client = Rake::JobServerClient.new(read_io, write_io, 2)
    ready = Queue.new

    first = client.acquire
    thread = Thread.new do
      second = client.acquire
      ready << second.byte
      second
    end

    sleep 0.05
    assert_equal true, ready.empty?

    write_io.write("Z")
    borrowed = thread.value
    assert_equal "Z", ready.pop

    client.release(borrowed)
    client.release(first)
    assert_equal "Z", read_io.read_nonblock(1)
  end

  def test_recognizes_posix_pipe_authorization_and_job_count
    read_io, write_io = IO.pipe
    makeflags = " -j2 --jobserver-auth=#{read_io.fileno},#{write_io.fileno}"

    assert_equal "#{read_io.fileno},#{write_io.fileno}",
      Rake::JobServerClient.jobserver_authorization(makeflags)
    assert_equal 2, Rake::JobServerClient.job_count(makeflags)
  end

  def test_recognizes_legacy_fds_and_fifo_authorization
    Dir.mktmpdir do |directory|
      fifo_path = File.join(directory, "jobserver.fifo")
      File.mkfifo(fifo_path)

      assert_equal "3,4",
        Rake::JobServerClient.jobserver_authorization("--jobserver-fds=3,4")
      assert_equal "fifo:#{fifo_path}",
        Rake::JobServerClient.jobserver_authorization("--jobserver-auth=fifo:#{fifo_path}")
    end
  end

  def test_fifo_borrows_and_returns_original_byte
    Dir.mktmpdir do |directory|
      fifo_path = File.join(directory, "jobserver.fifo")
      File.mkfifo(fifo_path)
      read_fd = IO.sysopen(fifo_path, File::RDONLY | Fcntl::O_NONBLOCK)
      read_io = IO.for_fd(read_fd, "rb")
      writer_ready = Queue.new
      writer = Thread.new do
        fifo_write = File.open(fifo_path, "w")
        writer_ready << :ready
        fifo_write
      end
      writer_ready.pop
      write_fd = IO.sysopen(fifo_path, File::WRONLY)
      write_io = IO.for_fd(write_fd, "wb")
      client = Rake::JobServerClient.new(read_io, write_io, 2)
      fifo_write = writer.value
      fifo_write.write("+")
      fifo_write.flush

      implicit = client.acquire
      borrowed = client.acquire
      assert_equal "+", borrowed.byte

      client.release(borrowed)
      client.release(implicit)
      fifo_write.close
      returned = File.open(fifo_path, "r") { |fifo_read| fifo_read.read_nonblock(1) }
      assert_equal "+", returned
    ensure
      fifo_write&.close
    end
  end

  def test_invalid_authorization_degrades_to_single_concurrency
    error_stream = StringIO.new
    client = Rake::JobServerClient.from_env(
      { "MAKEFLAGS" => "--jobserver-auth=invalid" }, error_stream)

    assert_same Rake::JobServerClient::UnavailableClient, client
    assert_equal 0, client.thread_pool_size(8)
    assert_match(/unable to use GNU make job server/, error_stream.string)
    assert_match(/single concurrency/, error_stream.string)
  end

  def test_application_invalid_authorization_uses_no_additional_workers
    ENV["MAKEFLAGS"] = "--jobserver-auth=invalid"
    app = Rake::Application.new

    assert_equal 0, app.thread_pool_size
  ensure
    app&.job_server
  end

  def test_non_pipe_descriptors_degrade_to_single_concurrency
    Dir.mktmpdir do |directory|
      path = File.join(directory, "not-a-pipe")
      File.write(path, "")
      read_file = File.open(path, "r")
      write_file = File.open(path, "w")
      error_stream = StringIO.new
      env = {
        "MAKEFLAGS" => "--jobserver-auth=#{read_file.fileno},#{write_file.fileno}"
      }

      client = Rake::JobServerClient.from_env(env, error_stream)

      assert_same Rake::JobServerClient::UnavailableClient, client
      assert_match(/not pipes/, error_stream.string)
    end
  end

  def test_wrong_access_modes_degrade_to_single_concurrency
    read_io, write_io = IO.pipe
    error_stream = StringIO.new
    env = {
      "MAKEFLAGS" => "--jobserver-auth=#{write_io.fileno},#{read_io.fileno}"
    }

    client = Rake::JobServerClient.from_env(env, error_stream)

    assert_same Rake::JobServerClient::UnavailableClient, client
    assert_match(/unable to use GNU make job server/, error_stream.string)
  ensure
    read_io&.close
    write_io&.close
  end

  def test_thread_pool_size_matches_job_server_capacity
    read_io, write_io = IO.pipe

    assert_equal 4, Rake::JobServerClient.new(read_io, write_io, 4).thread_pool_size(10)
    assert_equal 2, Rake::JobServerClient.new(read_io, write_io, 4).thread_pool_size(2)
    assert_equal 1, Rake::JobServerClient.new(read_io, write_io, 1).thread_pool_size(10)
    assert_equal 10, Rake::JobServerClient.new(read_io, write_io, nil).thread_pool_size(10)
  end
end
