# frozen_string_literal: true

require_relative 'period'

class Logger
  # Device used for logging messages.
  class LogDevice
    include Period

    attr_reader :dev
    attr_reader :filename
    include MonitorMixin

    def initialize(
      log = nil, shift_age: nil, shift_size: nil, shift_period_suffix: nil,
      shift_period: nil, clock: nil,
      binmode: false, reraise_write_errors: [], skip_header: false
    )
      @dev = @filename = @shift_age = @shift_size = @shift_period_suffix = nil
      @shift_period = @next_rotate_time = @current_period_end = @lock_path = nil
      @binmode = binmode
      @reraise_write_errors = reraise_write_errors
      @skip_header = skip_header
      self.clock = clock
      mon_initialize
      set_dev(log)
      if @filename
        configure_file(shift_age, shift_size, shift_period_suffix, shift_period)
      end
    end

    def write(message)
      handle_write_errors("writing") do
        synchronize do
          if @period_rotation && @dev.respond_to?(:stat)
            with_combined_rotation_lock do
              refresh_combined_dev
              handle_write_errors("shifting") { check_combined_shift }
              handle_write_errors("writing") { @dev.write(message) }
            end
          else
            if @shift_age and @dev.respond_to?(:stat)
              handle_write_errors("shifting") {check_shift_log}
            end
            handle_write_errors("writing") {@dev.write(message)}
          end
        end
      end
    end

    def close
      begin
        synchronize do
          @dev.close rescue nil
        end
      rescue Exception
        @dev.close rescue nil
      end
    end

    def reopen(log = nil, shift_age: nil, shift_size: nil, shift_period_suffix: nil,
               shift_period: nil, clock: nil, binmode: nil)
      # reopen the same filename if no argument, do nothing for IO
      log ||= @filename if @filename
      @binmode = binmode unless binmode.nil?
      if log
        synchronize do
          if @filename and @dev
            @dev.close rescue nil # close only file opened by Logger
            @filename = nil
          end
          self.clock = clock unless clock.nil?
          set_dev(log)
          if @filename
            configure_file(shift_age, shift_size, shift_period_suffix, shift_period)
          else
            @period_rotation = false
            @lock_path = nil
          end
        end
      end
      self
    end

  private

    # :stopdoc:

    MODE = File::WRONLY | File::APPEND
    # TruffleRuby < 24.2 does not have File::SHARE_DELETE
    if File.const_defined? :SHARE_DELETE
      MODE_TO_OPEN = MODE | File::SHARE_DELETE | File::BINARY
    else
      MODE_TO_OPEN = MODE | File::BINARY
    end
    MODE_TO_CREATE = MODE_TO_OPEN | File::CREAT | File::EXCL
    COMBINED_MODE_TO_OPEN = MODE | File::BINARY
    COMBINED_MODE_TO_CREATE = COMBINED_MODE_TO_OPEN | File::CREAT | File::EXCL
    LOCK_MODE = File::WRONLY | File::CREAT | File::BINARY

    def set_dev(log)
      if log.respond_to?(:write) and log.respond_to?(:close)
        @dev = log
        if log.respond_to?(:path) and path = log.path
          if File.exist?(path)
            @filename = path
          end
        end
      else
        @dev = open_logfile(log)
        @filename = log
      end
    end

    def configure_file(shift_age, shift_size, shift_period_suffix, new_shift_period)
      set_file(shift_age, shift_size, shift_period_suffix, new_shift_period)
      reopen_combined_dev if @period_rotation
    end

    def set_file(shift_age, shift_size, shift_period_suffix, new_shift_period)
      @shift_age = shift_age || @shift_age || 7
      @shift_size = shift_size || @shift_size || 1048576
      @shift_period_suffix = shift_period_suffix || @shift_period_suffix || '%Y%m%d'
      @shift_period = new_shift_period unless new_shift_period.nil?

      if @shift_period
        unless @shift_age.is_a?(Integer) && @shift_age > 0
          raise ArgumentError, "shift_age must be a positive integer when shift_period is given"
        end
        unless %w[daily weekly monthly].include?(@shift_period.to_s)
          raise ArgumentError, "invalid :shift_period #{@shift_period.inspect}, should be daily, weekly, or monthly"
        end

        @period_rotation = true
        @lock_path = "#{@filename}.lock"
        sync_period_schedule
      elsif @shift_age.is_a?(Integer)
        @period_rotation = false
      else
        @period_rotation = false
        base_time = rotation_base_time
        @next_rotate_time = next_rotate_time(base_time, @shift_age)
      end
    end

    def clock=(clock)
      if clock && !clock.respond_to?(:call)
        raise ArgumentError, "clock must respond to #call"
      end
      @clock = clock
    end

    def current_time
      @clock ? @clock.call : Time.now
    end

    if MODE_TO_OPEN == MODE
      def fixup_mode(dev)
        dev
      end
    else
      def fixup_mode(dev)
        return dev if @binmode
        dev.autoclose = false
        old_dev = dev
        dev = File.new(dev.fileno, mode: MODE, path: dev.path)
        old_dev.close
        PathAttr.set_path(dev, filename) if defined?(PathAttr)
        dev
      end
    end

    def open_logfile(filename)
      begin
        dev = File.open(filename, MODE_TO_OPEN)
      rescue Errno::ENOENT
        create_logfile(filename)
      else
        dev = fixup_mode(dev)
        dev.sync = true
        dev.binmode if @binmode
        dev
      end
    end

    def create_logfile(filename)
      begin
        logdev = File.open(filename, MODE_TO_CREATE)
        logdev.flock(File::LOCK_EX)
        logdev = fixup_mode(logdev)
        logdev.sync = true
        logdev.binmode if @binmode
        add_log_header(logdev) unless @skip_header
        logdev.flock(File::LOCK_UN)
        logdev
      rescue Errno::EEXIST
        # file is created by another process
        open_logfile(filename)
      end
    end

    def handle_write_errors(mesg)
      yield
    rescue *@reraise_write_errors
      raise
    rescue
      warn("log #{mesg} failed. #{$!}")
    end

    def add_log_header(file)
      file.write(
        "# Logfile created on %s by %s\n" % [current_time.to_s, Logger::ProgName]
      ) if file.size == 0
    end

    def check_shift_log
      if @period_rotation
        # Combined period/size rotation is handled by #check_combined_shift.
      elsif @shift_age.is_a?(Integer)
        # Note: always returns false if '0'.
        if @filename && (@shift_age > 0) && (@dev.stat.size > @shift_size)
          lock_shift_log { shift_log_age }
        end
      else
        now = Time.now
        if now >= @next_rotate_time
          @next_rotate_time = next_rotate_time(now, @shift_age)
          lock_shift_log { shift_log_period(previous_period_end(now, @shift_age)) }
        end
      end
    end

    def check_combined_shift
      now = current_time
      if now >= @next_rotate_time
        if @dev.stat.size.zero?
          sync_period_schedule(now)
        else
          shift_combined_log(@current_period_end)
        end
      elsif @dev.stat.size >= @shift_size
        shift_combined_log(@current_period_end)
      end
    end

    def with_combined_rotation_lock
      File.open(@lock_path, LOCK_MODE) do |lock|
        lock.flock(File::LOCK_EX)
        yield
      end
    end

    def refresh_combined_dev
      current = begin
        File.identical?(@filename, @dev)
      rescue Errno::ENOENT
        false
      end
      unless current
        @dev.close rescue nil
        @dev = create_combined_logfile(@filename)
        sync_period_schedule
      end
    end

    def rotation_base_time
      if @dev.respond_to?(:stat) && !@dev.stat.size.zero?
        @dev.stat.mtime
      else
        current_time
      end
    end

    def sync_period_schedule(time = rotation_base_time)
      @next_rotate_time = next_rotate_time(time, @shift_period)
      @current_period_end = @next_rotate_time - 1
    end

    def shift_combined_log(period_end)
      archive = next_combined_archive(period_end.strftime(@shift_period_suffix))
      old_period_start = @next_rotate_time
      old_period_end = @current_period_end
      stat = @dev.stat
      @dev.close rescue nil
      File.rename(@filename, archive)
      @dev = create_combined_logfile(@filename)
      mode, uid, gid = stat.mode, stat.uid, stat.gid
      begin
        @dev.chmod(mode) if mode
        mode = nil
        @dev.chown(uid, gid)
      rescue Errno::EPERM
        if mode
          # failed to chmod, probably nothing can do more.
        elsif uid
          uid = nil
          retry # to change gid only
        end
      end
      now = current_time
      if now >= old_period_start
        sync_period_schedule(now)
      else
        @next_rotate_time = old_period_start
        @current_period_end = old_period_end
      end
      remove_old_combined_archives
    end

    def create_combined_logfile(filename, existing = File.exist?(filename))
      begin
        logdev = File.open(filename, COMBINED_MODE_TO_CREATE)
      rescue Errno::EEXIST
        logdev = File.open(filename, COMBINED_MODE_TO_OPEN)
      end
      prepare_combined_logfile(logdev, existing)
    end

    def prepare_combined_logfile(logdev, existing = false)
      logdev.flock(File::LOCK_EX)
      logdev.sync = true
      logdev.binmode if @binmode
      add_log_header(logdev) unless @skip_header || existing
      logdev.flock(File::LOCK_UN)
      logdev
    end

    def next_combined_archive(suffix)
      sequence = combined_archive_entries.map(&:last).max || 0
      loop do
        sequence += 1
        archive = "#{@filename}.#{suffix}.#{format('%010d', sequence)}"
        break archive unless FileTest.exist?(archive)
      end
    end

    def reopen_combined_dev
      current = @dev
      existing = File.exist?(@filename)
      @dev = create_combined_logfile(@filename, existing)
      begin
        current.close
      rescue Errno::ENOENT
      end
    end

    def remove_old_combined_archives
      archives = combined_archive_entries.sort_by { |_, sequence| sequence }
      excess = archives.size - @shift_age
      excess.times do |index|
        File.delete(archives[index].first)
      end
    end

    def combined_archive_entries
      pattern = /\A#{Regexp.escape(@filename)}\..+\.(\d+)\z/
      directory = File.dirname(@filename)
      Dir.children(directory).each_with_object([]) do |entry, archives|
        path = File.join(directory, entry)
        match = pattern.match(path)
        archives << [path, match[1].to_i] if match
      end
    end

    def lock_shift_log
      retry_limit = 8
      retry_sleep = 0.1
      begin
        File.open(@filename, MODE_TO_OPEN) do |lock|
          lock.flock(File::LOCK_EX) # inter-process locking. will be unlocked at closing file
          if File.identical?(@filename, lock) and File.identical?(lock, @dev)
            yield # log shifting
          else
            # log shifted by another process (i-node before locking and i-node after locking are different)
            @dev.close rescue nil
            @dev = open_logfile(@filename)
          end
        end
        true
      rescue Errno::ENOENT
        # @filename file would not exist right after #rename and before #create_logfile
        if retry_limit <= 0
          warn("log rotation inter-process lock failed. #{$!}")
        else
          sleep retry_sleep
          retry_limit -= 1
          retry_sleep *= 2
          retry
        end
      end
    rescue
      warn("log rotation inter-process lock failed. #{$!}")
    end

    def shift_log_age
      (@shift_age-3).downto(0) do |i|
        if FileTest.exist?("#{@filename}.#{i}")
          File.rename("#{@filename}.#{i}", "#{@filename}.#{i+1}")
        end
      end
      shift_log_file("#{@filename}.0")
    end

    def shift_log_period(period_end)
      suffix = period_end.strftime(@shift_period_suffix)
      age_file = "#{@filename}.#{suffix}"
      if FileTest.exist?(age_file)
        # try to avoid filename crash caused by Timestamp change.
        idx = 0
        # .99 can be overridden; avoid too much file search with 'loop do'
        while idx < 100
          idx += 1
          age_file = "#{@filename}.#{suffix}.#{idx}"
          break unless FileTest.exist?(age_file)
        end
      end
      shift_log_file(age_file)
    end

    def shift_log_file(shifted)
      stat = @dev.stat
      @dev.close rescue nil
      File.rename(@filename, shifted)
      @dev = create_logfile(@filename)
      mode, uid, gid = stat.mode, stat.uid, stat.gid
      begin
        @dev.chmod(mode) if mode
        mode = nil
        @dev.chown(uid, gid)
      rescue Errno::EPERM
        if mode
          # failed to chmod, probably nothing can do more.
        elsif uid
          uid = nil
          retry # to change gid only
        end
      end
      return true
    end
  end
end

File.open(__FILE__) do |f|
  File.new(f.fileno, autoclose: false, path: "").path
rescue IOError
  module PathAttr               # :nodoc:
    attr_reader :path

    def self.set_path(file, path)
      file.extend(self).instance_variable_set(:@path, path)
    end
  end
end
