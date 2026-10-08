# frozen_string_literal: true
require "fcntl"

module Rake

  # Client for GNU make's POSIX jobserver.  Rake owns one implicit job slot
  # when it is invoked recursively.  Additional slots are bytes borrowed from
  # the authorization descriptor and must be written back unchanged.
  class JobServer # :nodoc: all
    JobServerError = Class.new(StandardError)

    Slot = Struct.new(:type, :byte, :depth, :returned)

    class NullServer
      def active?
        false
      end

      def around_action
        yield
      end

      def shutdown
      end
    end

    NULL = NullServer.new

    attr_reader :jobs

    def initialize(read_io, write_io, jobs=nil, owned=false)
      @read_io = read_io
      @write_io = write_io
      @jobs = jobs
      @owned = owned
      @monitor = Monitor.new
      @implicit_available = true
      @borrowed = []
      @active = true
      @thread_key = "rake_job_server_#{object_id}".to_sym
    end

    def self.open_from_env(env=ENV)
      makeflags = env["MAKEFLAGS"] || env["MFLAGS"]
      kind, auth = jobserver_authorization(makeflags)
      return :not_configured unless auth

      begin
        server =
          if kind == "--jobserver-fds" || !auth.start_with?("fifo:")
            open_pipe_authorization(auth)
          else
            open_fifo_authorization(auth)
          end
        server.jobs = job_count(makeflags)
        install_exit_handler(server)
        server
      rescue JobServerError => error
        warn "Rake: GNU make jobserver is unavailable (#{error.message}); running with one job"
        :unavailable
      end
    end

    def active?
      @monitor.synchronize { @active }
    end

    def around_action
      slot = Thread.current[@thread_key]

      if slot
        slot.depth += 1
      else
        slot = acquire
        Thread.current[@thread_key] = slot
      end

      error = nil
      begin
        yield
      rescue Exception => error
        raise
      ensure
        slot.depth -= 1
        if slot.depth.zero?
          Thread.current[@thread_key] = nil
          begin
            release(slot)
          rescue StandardError
            raise if error.nil?
          end
        end
      end
    end

    def acquire
      slot = acquire_implicit
      return slot if slot

      byte = read_token
      @monitor.synchronize { @borrowed << byte }
      Slot.new(:borrowed, byte, 1, false)
    end

    def release(slot)
      @monitor.synchronize do
        if slot.type == :implicit
          @implicit_available = true unless slot.returned
          slot.returned = true
          return
        end

        return if slot.returned

        raise JobServerError, "jobserver token was not borrowed" unless
          @borrowed.include?(slot.byte)

        write_token(slot.byte)
        slot.returned = true
        @borrowed.delete(slot.byte)
      end
    end

    def shutdown
      tokens = @monitor.synchronize do
        return unless @active
        @active = false
        @borrowed.dup
      end

      tokens.each do |token|
        write_token(token)
        @monitor.synchronize { @borrowed.delete(token) }
      end
      close_authorization
    end

    def jobs=(jobs)
      @jobs = jobs
    end

    private

    def acquire_implicit
      @monitor.synchronize do
        next unless @implicit_available
        @implicit_available = false
        Slot.new(:implicit, nil, 1, false)
      end
    end

    def read_token
      begin
        byte = @read_io.sysread(1)
      rescue EOFError, Errno::EIO
        raise JobServerError, "jobserver authorization descriptor reached end-of-file"
      rescue IOError, Errno::EBADF
        raise JobServerError, "jobserver authorization descriptor is closed"
      end

      raise JobServerError, "short jobserver read" if byte.nil? || byte.empty?
      byte
    end

    def write_token(byte)
      written = 0
      begin
        written += @write_io.syswrite(byte.byteslice(written) || byte)
      end while written < byte.bytesize
      written
    rescue IOError, Errno::EBADF, SystemCallError
      raise JobServerError, "unable to return jobserver token"
    end

    def shutdown_best_effort
      shutdown
    rescue StandardError
    end

    def close_authorization
      return unless @owned
      @read_io.close unless @read_io.closed?
    end

    def self.jobserver_authorization(makeflags)
      return nil unless makeflags

      match = makeflags.match(/(?:\A|\s)(--jobserver(?:-auth|-fds))=(\S+)/)
      match && [match[1], match[2]]
    end
    private_class_method :jobserver_authorization

    def self.job_count(makeflags)
      match = makeflags.match(/(?:\A|\s)(?:--jobs(?:=|\s+)|-j\s*|j)(\d+)(?=\s|\z)/)
      match && match[1].to_i
    end
    private_class_method :job_count

    def self.open_pipe_authorization(authorization)
      match = authorization.match(/\A(\d+),(\d+)\z/)
      raise JobServerError, "invalid pipe authorization" unless match

      read_io = authorized_io(match[1].to_i, File::RDONLY, Fcntl::O_RDONLY)
      write_io = authorized_io(match[2].to_i, File::WRONLY, Fcntl::O_WRONLY)
      new(read_io, write_io)
    end
    private_class_method :open_pipe_authorization

    def self.open_fifo_authorization(authorization)
      path = authorization.sub(/\Afifo:/, "")
      raise JobServerError, "empty FIFO authorization" if path.empty?

      begin
        stat = File.lstat(path)
      rescue SystemCallError
        raise JobServerError, "FIFO #{path.inspect} cannot be opened"
      end

      unless stat.pipe? && !stat.symlink?
        raise JobServerError, "#{path.inspect} is not a FIFO"
      end

      begin
        io = File.open(path, File::RDWR)
      rescue SystemCallError
        raise JobServerError, "FIFO #{path.inspect} cannot be opened"
      end
      io.autoclose = false
      io.close_on_exec = false
      new(io, io, nil, true)
    end
    private_class_method :open_fifo_authorization

    def self.authorized_io(descriptor, mode, access_mode)
      raise JobServerError, "invalid file descriptor" if descriptor < 0

      begin
        io = IO.for_fd(descriptor, mode)
      rescue Errno::EBADF
        raise JobServerError, "file descriptor #{descriptor} is not open"
      rescue SystemCallError
        raise JobServerError, "file descriptor #{descriptor} is unusable"
      end

      flags = io.fcntl(Fcntl::F_GETFL, 0)
      unless (flags & Fcntl::O_ACCMODE) == access_mode && io.stat.pipe?
        raise JobServerError, "file descriptor #{descriptor} is not a jobserver pipe"
      end

      io.autoclose = false
      io.close_on_exec = false
      io
    end
    private_class_method :authorized_io

    def self.install_exit_handler(server)
      at_exit { server.send(:shutdown_best_effort) }
    end
    private_class_method :install_exit_handler
  end
end
