# frozen_string_literal: true

require "fcntl"
require "monitor"

module Rake
  # Client for the GNU make job server. The client process owns one implicit
  # job slot. Additional slots are represented by bytes borrowed from the job
  # server and must be written back unchanged.
  class JobServerClient # :nodoc: all
    AuthorizationError = Class.new(StandardError)

    Token = Struct.new(:kind, :byte)
    IMPLICIT_TOKEN = Token.new(:implicit, nil).freeze

    NullClient = Object.new

    def NullClient.thread_pool_size(size)
      size
    end

    def NullClient.synchronize
      yield
    end

    def NullClient.release_all
    end

    UnavailableClient = Object.new

    def UnavailableClient.thread_pool_size(_size)
      0
    end

    def UnavailableClient.synchronize
      yield
    end

    def UnavailableClient.release_all
    end

    def self.from_env(env=ENV, error_stream=$stderr)
      makeflags = env["MAKEFLAGS"].to_s
      authorization = jobserver_authorization(makeflags)
      return NullClient unless authorization

      read_io, write_io = open_authorization(authorization)
      client = new(read_io, write_io, job_count(makeflags))
      at_exit { client.release_all }
      client
    rescue AuthorizationError, SystemCallError, IOError, NotImplementedError => error
      error_stream.puts "Rake: unable to use GNU make job server " \
        "authorization (#{error.message}); using single concurrency."
      UnavailableClient
    end

    def self.jobserver_authorization(makeflags)
      require "shellwords"
      word = Shellwords.split(makeflags).find do |candidate|
        candidate.start_with?("--jobserver-auth=", "--jobserver-fds=")
      end
      word && word.split("=", 2)[1]
    rescue ArgumentError
      nil
    end

    def self.job_count(makeflags)
      require "shellwords"
      words = Shellwords.split(makeflags)
      words.each_with_index do |word, index|
        case word
        when "-j", "--jobs"
          next_word = words[index + 1]
          return next_word && /\A\d+\z/.match?(next_word) ? next_word.to_i : nil
        when /\A-j(\d+)\z/, /\A--jobs=(\d+)\z/
          return $1.to_i
        end
      end
      nil
    rescue ArgumentError
      nil
    end

    def self.open_authorization(authorization)
      if authorization.start_with?("fifo:")
        open_fifo_authorization(authorization.sub(/\Afifo:/, ""))
      elsif /\A(\d+),(\d+)\z/.match?(authorization)
        read_fd, write_fd = authorization.split(",").map(&:to_i)
        open_pipe_authorization(read_fd, write_fd)
      else
        raise AuthorizationError, "unsupported authorization #{authorization.inspect}"
      end
    end

    def self.open_pipe_authorization(read_fd, write_fd)
      raise AuthorizationError, "read and write file descriptors must differ" if read_fd == write_fd

      read_io = nil
      write_io = nil
      begin
        read_io = IO.for_fd(read_fd, "rb")
        write_io = IO.for_fd(write_fd, "wb")
        read_io.autoclose = false
        write_io.autoclose = false
        validate_pipe_authorization(read_io, write_io)
        [read_io, write_io]
      rescue StandardError => error
        raise AuthorizationError, error.message unless error.is_a?(AuthorizationError)
        raise
      end
    end

    def self.open_fifo_authorization(path)
      raise AuthorizationError, "FIFO path is empty" if path.empty?
      raise AuthorizationError, "#{path} is not a FIFO" unless
        File.exist?(path) && File.stat(path).ftype == "fifo"

      read_fd = IO.sysopen(path, File::RDONLY | Fcntl::O_NONBLOCK)
      read_io = IO.for_fd(read_fd, "rb")
      write_fd = IO.sysopen(path, File::WRONLY | Fcntl::O_NONBLOCK)
      begin
        write_io = IO.for_fd(write_fd, "wb")
      rescue StandardError
        write_io&.close unless write_io&.closed?
        raise
      end

      write_io.fcntl(Fcntl::F_SETFL, blocking_flags(write_io))
      validate_pipe_authorization(read_io, write_io)
      [read_io, write_io]
    rescue StandardError
      read_io.close unless read_io.closed?
      write_io&.close unless write_io&.closed?
      raise
    end

    def self.blocking_flags(io)
      io.fcntl(Fcntl::F_GETFL, 0) & ~Fcntl::O_NONBLOCK
    end

    def self.validate_pipe_authorization(read_io, write_io)
      unless read_io.stat.pipe? && write_io.stat.pipe? &&
          read_accessible?(read_io) && write_accessible?(write_io)
        raise AuthorizationError, "authorization file descriptors are not pipes"
      end
    end

    def self.read_accessible?(io)
      io.fcntl(Fcntl::F_GETFL, 0) & Fcntl::O_ACCMODE != Fcntl::O_WRONLY
    end

    def self.write_accessible?(io)
      mode = io.fcntl(Fcntl::F_GETFL, 0) & Fcntl::O_ACCMODE
      mode == Fcntl::O_WRONLY || mode == Fcntl::O_RDWR
    end

    def initialize(read_io, write_io, max_jobs)
      @read_io = read_io
      @write_io = write_io
      @write_io.sync = true if @write_io.respond_to?(:sync=)
      @max_jobs = max_jobs
      @mutex = Monitor.new
      @implicit_available = true
      @borrowed = {}
    end

    def thread_pool_size(size)
      return size if @max_jobs.nil?
      [size, @max_jobs].min
    end

    def synchronize
      if Thread.current.key?(:rake_job_server_token)
        return yield
      end

      token = acquire
      begin
        Thread.current[:rake_job_server_token] = token
        yield
      ensure
        Thread.current[:rake_job_server_token] = nil
        release(token)
      end
    end

    def acquire
      @mutex.synchronize do
        loop do
          if @implicit_available
            @implicit_available = false
            return IMPLICIT_TOKEN
          end

          byte = read_byte
          if byte
            token = Token.new(:borrowed, byte)
            @borrowed[token.object_id] = token
            return token
          end

          IO.select([@read_io])
        end
      end
    end

    def release(token)
      if token.equal?(IMPLICIT_TOKEN)
        @mutex.synchronize do
          @implicit_available = true
        end
        return
      end

      @mutex.synchronize do
        borrowed = @borrowed.delete(token.object_id)
        @write_io.write(borrowed.byte) if borrowed
      end
    end

    def release_all
      tokens = @mutex.synchronize do
        @implicit_available = true
        @borrowed.values
      end

      tokens.each do |token|
        @write_io.write(token.byte)
      end
      @mutex.synchronize { tokens.each { |token| @borrowed.delete(token.object_id) } }
    rescue StandardError
    end

    private

    def read_byte
      @read_io.read_nonblock(1)
    rescue IO::WaitReadable
      nil
    end
  end
end
