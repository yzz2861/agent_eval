# coding: US-ASCII
# frozen_string_literal: false
require 'logger'
require 'tempfile'
require 'stringio'

class TestLogger < Test::Unit::TestCase
  include Logger::Severity

  class CountingIO < StringIO
    attr_reader :write_count

    def initialize(*)#:nodoc:
      super
      @write_count = 0
    end

    def write(message)#:nodoc:
      @write_count += 1
      super(message)
    end
  end

  class GatedShortWriteIO
    def initialize(start, hold)
      @buffer = +''
      @start = start
      @hold = hold
      @first_write = true
    end

    def write(message)
      if @first_write
        @start << :started
        @hold.pop
        @first_write = false
      end
      length = [message.bytesize, 1].min
      @buffer << message.byteslice(0, length)
      length
    end

    def close
    end

    def string
      @buffer
    end
  end

  def setup
    @logger = Logger.new(nil)
  end

  class Log
    attr_reader :label, :datetime, :pid, :severity, :progname, :msg
    def initialize(line)
      /\A(\w+), \[([^#]*) #(\d+)\]\s+(\w+) -- (\w*): ([\x0-\xff]*)/ =~ line
      @label, @datetime, @pid, @severity, @progname, @msg = $1, $2, $3, $4, $5, $6
    end
  end

  def log_add(logger, severity, msg, progname = nil, &block)
    log(logger, :add, severity, msg, progname, &block)
  end

  def log(logger, msg_id, *arg, &block)
    Log.new(log_raw(logger, msg_id, *arg, &block))
  end

  def log_raw(logger, msg_id, *arg, &block)
    Tempfile.create(File.basename(__FILE__) + '.log') {|logdev|
      logger.instance_eval { @logdev = Logger::LogDevice.new(logdev) }
      logger.__send__(msg_id, *arg, &block)
      logdev.rewind
      logdev.read
    }
  end

  def test_level
    @logger.level = UNKNOWN
    assert_equal(UNKNOWN, @logger.level)
    @logger.level = INFO
    assert_equal(INFO, @logger.level)
    @logger.sev_threshold = ERROR
    assert_equal(ERROR, @logger.sev_threshold)
    @logger.sev_threshold = WARN
    assert_equal(WARN, @logger.sev_threshold)
    assert_equal(WARN, @logger.level)

    @logger.level = DEBUG
    assert(@logger.debug?)
    assert(@logger.info?)
    @logger.level = INFO
    assert(!@logger.debug?)
    assert(@logger.info?)
    assert(@logger.warn?)
    @logger.level = WARN
    assert(!@logger.info?)
    assert(@logger.warn?)
    assert(@logger.error?)
    @logger.level = ERROR
    assert(!@logger.warn?)
    assert(@logger.error?)
    assert(@logger.fatal?)
    @logger.level = FATAL
    assert(!@logger.error?)
    assert(@logger.fatal?)
    @logger.level = UNKNOWN
    assert(!@logger.error?)
    assert(!@logger.fatal?)
  end

  def test_symbol_level
    logger_symbol_levels = {
      debug:   DEBUG,
      info:    INFO,
      warn:    WARN,
      error:   ERROR,
      fatal:   FATAL,
      unknown: UNKNOWN,
      DEBUG:   DEBUG,
      INFO:    INFO,
      WARN:    WARN,
      ERROR:   ERROR,
      FATAL:   FATAL,
      UNKNOWN: UNKNOWN,
    }
    logger_symbol_levels.each do |symbol, level|
      @logger.level = symbol
      assert(@logger.level == level)
    end
    assert_raise(ArgumentError) { @logger.level = :something_wrong }
  end

  def test_string_level
    logger_string_levels = {
      'debug'   => DEBUG,
      'info'    => INFO,
      'warn'    => WARN,
      'error'   => ERROR,
      'fatal'   => FATAL,
      'unknown' => UNKNOWN,
      'DEBUG'   => DEBUG,
      'INFO'    => INFO,
      'WARN'    => WARN,
      'ERROR'   => ERROR,
      'FATAL'   => FATAL,
      'UNKNOWN' => UNKNOWN,
    }
    logger_string_levels.each do |string, level|
      @logger.level = string
      assert(@logger.level == level)
    end
    assert_raise(ArgumentError) { @logger.level = 'something_wrong' }
  end

  def test_reraise_write_errors
    c = Object.new
    e = Class.new(StandardError)
    c.define_singleton_method(:write){|*| raise e}
    c.define_singleton_method(:close){}
    logger = Logger.new(c, :reraise_write_errors=>[e])
    assert_raise(e) { logger.warn('foo') }
  end

  def test_progname
    assert_nil(@logger.progname)
    @logger.progname = "name"
    assert_equal("name", @logger.progname)
  end

  def test_datetime_format
    verbose, $VERBOSE = $VERBOSE, false
    dummy = STDERR
    logger = Logger.new(dummy)
    log = log_add(logger, INFO, "foo")
    assert_match(/^\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\s*\d+$/, log.datetime)
    logger.datetime_format = "%d%b%Y@%H:%M:%S"
    log = log_add(logger, INFO, "foo")
    assert_match(/^\d\d\w\w\w\d\d\d\d@\d\d:\d\d:\d\d$/, log.datetime)
    logger.datetime_format = ""
    log = log_add(logger, INFO, "foo")
    assert_match(/^$/, log.datetime)
  ensure
    $VERBOSE = verbose
  end

  def test_formatter
    dummy = STDERR
    logger = Logger.new(dummy)
    # default
    log = log(logger, :info, "foo")
    assert_equal("foo\n", log.msg)
    # config
    logger.formatter = proc { |severity, timestamp, progname, msg|
      "#{severity}:#{msg}\n\n"
    }
    line = log_raw(logger, :info, "foo")
    assert_equal("INFO:foo\n\n", line)
    # recover
    logger.formatter = nil
    log = log(logger, :info, "foo")
    assert_equal("foo\n", log.msg)
    # again
    o = Object.new
    def o.call(severity, timestamp, progname, msg)
      "<<#{severity}-#{msg}>>\n"
    end
    logger.formatter = o
    line = log_raw(logger, :info, "foo")
    assert_equal("<""<INFO-foo>>\n", line)
  end

  def test_initialize
    logger = Logger.new(STDERR)
    assert_nil(logger.progname)
    assert_equal(DEBUG, logger.level)
    assert_nil(logger.datetime_format)
  end

  def test_logdev
    logger = Logger.new(STDERR)
    assert_instance_of(Logger::LogDevice, logger.logdev)

    logdev = Logger::LogDevice.new(STDERR)
    logger = Logger.new(logdev)
    assert_instance_of(Logger::LogDevice, logger.logdev)
    assert_equal(STDERR, logger.logdev.dev)
  end

  def test_initialize_with_level
    # default
    logger = Logger.new(STDERR)
    assert_equal(Logger::DEBUG, logger.level)
    # config
    logger = Logger.new(STDERR, level: :info)
    assert_equal(Logger::INFO, logger.level)
  end

  def test_initialize_with_progname
    # default
    logger = Logger.new(STDERR)
    assert_equal(nil, logger.progname)
    # config
    logger = Logger.new(STDERR, progname: :progname)
    assert_equal(:progname, logger.progname)
  end

  def test_initialize_with_formatter
    # default
    logger = Logger.new(STDERR)
    log = log(logger, :info, "foo")
    assert_equal("foo\n", log.msg)
    # config
    logger = Logger.new(STDERR, formatter: proc { |severity, timestamp, progname, msg|
      "#{severity}:#{msg}\n\n"
    })
    line = log_raw(logger, :info, "foo")
    assert_equal("INFO:foo\n\n", line)
  end

  def test_initialize_with_datetime_format
    # default
    logger = Logger.new(STDERR)
    log = log_add(logger, INFO, "foo")
    assert_match(/^\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\s*\d+$/, log.datetime)
    # config
    logger = Logger.new(STDERR, datetime_format: "%d%b%Y@%H:%M:%S")
    log = log_add(logger, INFO, "foo")
    assert_match(/^\d\d\w\w\w\d\d\d\d@\d\d:\d\d:\d\d$/, log.datetime)
  end

  def test_reopen
    logger = Logger.new(STDERR)
    logger.reopen(STDOUT)
    assert_equal(STDOUT, logger.instance_variable_get(:@logdev).dev)
  end

  def test_reopen_nil_logdevice
    logger = Logger.new(File::NULL)
    assert_nothing_raised do
      logger.reopen(STDOUT)
    end
  end

  def test_add
    logger = Logger.new(nil)
    logger.progname = "my_progname"
    assert(logger.add(INFO))
    log = log_add(logger, nil, "msg")
    assert_equal("ANY", log.severity)
    assert_equal("my_progname", log.progname)
    logger.level = WARN
    assert(logger.log(INFO))
    assert_nil(log_add(logger, INFO, "msg").msg)
    log = log_add(logger, WARN, nil) { "msg" }
    assert_equal("msg\n", log.msg)
    log = log_add(logger, WARN, "") { "msg" }
    assert_equal("\n", log.msg)
    assert_equal("my_progname", log.progname)
    log = log_add(logger, WARN, nil, "progname?")
    assert_equal("progname?\n", log.msg)
    assert_equal("my_progname", log.progname)
    #
    logger = Logger.new(nil)
    log = log_add(logger, INFO, nil, false)
    assert_equal("false\n", log.msg)
  end

  def test_add_binary_data_with_binmode_logdev
    EnvUtil.with_default_internal(Encoding::UTF_8) do
      begin
        tempfile = Tempfile.new("logger")
        tempfile.close
        filename = tempfile.path
        File.unlink(filename)

        logger = Logger.new filename, binmode: true
        logger.level = Logger::DEBUG

        str = +"\x80"
        str.force_encoding("ASCII-8BIT")

        logger.add Logger::DEBUG, str
        assert_equal(2, File.binread(filename).split(/\n/).size)
      ensure
        logger.close
        tempfile.unlink
      end
    end
  end

  def test_level_log
    logger = Logger.new(nil)
    logger.progname = "my_progname"
    log = log(logger, :debug, "custom_progname") { "msg" }
    assert_equal("msg\n", log.msg)
    assert_equal("custom_progname", log.progname)
    assert_equal("DEBUG", log.severity)
    assert_equal("D", log.label)
    #
    log = log(logger, :debug) { "msg_block" }
    assert_equal("msg_block\n", log.msg)
    assert_equal("my_progname", log.progname)
    log = log(logger, :debug, "msg_inline")
    assert_equal("msg_inline\n", log.msg)
    assert_equal("my_progname", log.progname)
    #
    log = log(logger, :info, "custom_progname") { "msg" }
    assert_equal("msg\n", log.msg)
    assert_equal("custom_progname", log.progname)
    assert_equal("INFO", log.severity)
    assert_equal("I", log.label)
    #
    log = log(logger, :warn, "custom_progname") { "msg" }
    assert_equal("msg\n", log.msg)
    assert_equal("custom_progname", log.progname)
    assert_equal("WARN", log.severity)
    assert_equal("W", log.label)
    #
    log = log(logger, :error, "custom_progname") { "msg" }
    assert_equal("msg\n", log.msg)
    assert_equal("custom_progname", log.progname)
    assert_equal("ERROR", log.severity)
    assert_equal("E", log.label)
    #
    log = log(logger, :fatal, "custom_progname") { "msg" }
    assert_equal("msg\n", log.msg)
    assert_equal("custom_progname", log.progname)
    assert_equal("FATAL", log.severity)
    assert_equal("F", log.label)
    #
    log = log(logger, :unknown, "custom_progname") { "msg" }
    assert_equal("msg\n", log.msg)
    assert_equal("custom_progname", log.progname)
    assert_equal("ANY", log.severity)
    assert_equal("A", log.label)
  end

  def test_close
    r, w = IO.pipe
    assert(!w.closed?)
    logger = Logger.new(w)
    logger.close
    assert(w.closed?)
    r.close
  end

  class MyError < StandardError
  end

  class MyMsg
    def inspect
      "my_msg"
    end
  end

  def test_format
    logger = Logger.new(nil)
    log = log_add(logger, INFO, "msg\n")
    assert_equal("msg\n\n", log.msg)
    begin
      raise MyError.new("excn")
    rescue MyError => e
      log = log_add(logger, INFO, e)
      assert_match(/^excn \(TestLogger::MyError\)/, log.msg)
      # expects backtrace is dumped across multi lines.  10 might be changed.
      assert(log.msg.split(/\n/).size >= 10)
    end
    log = log_add(logger, INFO, MyMsg.new)
    assert_equal("my_msg\n", log.msg)
  end

  def test_lshift
    r, w = IO.pipe
    logger = Logger.new(w)
    logger << "msg"
    IO.select([r], nil, nil, 0.1)
    w.close
    msg = r.read
    r.close
    assert_equal("msg", msg)
    #
    r, w = IO.pipe
    logger = Logger.new(w)
    logger << "msg2\n\n"
    IO.select([r], nil, nil, 0.1)
    w.close
    msg = r.read
    r.close
    assert_equal("msg2\n\n", msg)
  end

  class CustomLogger < Logger
    def level
      INFO
    end
  end

  def test_overriding_level
    logger = CustomLogger.new(nil)
    log = log(logger, :info) { "msg" }
    assert_equal "msg\n", log.msg
    #
    log = log(logger, :debug) { "msg" }
    assert_nil log.msg
  end

  def test_does_not_instantiate_log_device_for_File_NULL
    l = Logger.new(File::NULL)
    assert_nil(l.instance_variable_get(:@logdev))
  end

  def test_subclass_initialize
    bad_logger = Class.new(Logger) {def initialize(*); end}.new(IO::NULL)
    line = __LINE__ - 1
    file = Regexp.quote(__FILE__)
    assert_warning(/not initialized properly.*\n#{file}:#{line}:/) do
      bad_logger.level
    end

    good_logger = Class.new(Logger) {def initialize(*); super; end}.new(IO::NULL)
    file = Regexp.quote(__FILE__)
    assert_warning('') do
      good_logger.level
    end
  end

  def test_batch_submits_entries_as_one_write
    io = CountingIO.new
    logger = Logger.new(io, formatter: lambda {|severity, time, progname, message|
      "#{message}\n"
    })

    result = logger.batch do
      logger.info('first')
      logger.info('second')
    end

    assert_equal("first\nsecond\n", io.string)
    assert_equal(1, io.write_count)
    assert_equal(true, result)
  end

  def test_batch_keeps_ordinary_add_writes_separate
    io = CountingIO.new
    logger = Logger.new(io, formatter: lambda {|severity, time, progname, message|
      "#{message}\n"
    })

    logger.info('first')
    logger.info('second')

    assert_equal("first\nsecond\n", io.string)
    assert_equal(2, io.write_count)
  end

  def test_batch_does_not_evaluate_filtered_messages
    logger = Logger.new(nil)
    logger.level = ERROR
    evaluated = false

    logger.batch do
      logger.info { evaluated = true }
    end

    assert_equal(false, evaluated)
  end

  def test_batch_discards_entries_and_reraises_on_error_by_default
    io = CountingIO.new
    logger = Logger.new(io)

    assert_raise(RuntimeError) do
      logger.batch do
        logger.info('before failure')
        raise('failed block')
      end
    end

    assert_equal('', io.string)
    assert_equal(0, io.write_count)
  end

  def test_batch_marks_entries_and_commits_on_error
    io = CountingIO.new
    logger = Logger.new(io)

    assert_raise(RuntimeError) do
      logger.batch(on_error: :mark) do
        logger.info('before failure')
        raise('failed block')
      end
    end

    assert_match(/before failure/, io.string)
    assert_match(/RuntimeError: failed block/, io.string)
    assert_equal(1, io.write_count)
  end

  def test_successful_nested_batch_keeps_enclosing_order
    io = CountingIO.new
    logger = Logger.new(io, formatter: lambda {|severity, time, progname, message|
      "#{message}\n"
    })

    logger.batch do
      logger.info('outer-before')
      logger.batch do
        logger.info('inner-1')
        logger.info('inner-2')
      end
      logger.info('outer-after')
    end

    assert_equal("outer-before\ninner-1\ninner-2\nouter-after\n", io.string)
    assert_equal(1, io.write_count)
  end

  def test_failed_nested_batch_can_be_marked_while_outer_continues
    io = CountingIO.new
    logger = Logger.new(io, formatter: lambda {|severity, time, progname, message|
      "#{message}\n"
    })

    logger.batch do
      logger.info('outer-before')
      begin
        logger.batch(on_error: :mark) do
          logger.info('inner')
          raise('inner failure')
        end
      rescue RuntimeError
      end
      logger.info('outer-after')
    end

    assert_equal("outer-before\ninner\nRuntimeError: inner failure\nouter-after\n",
                 io.string)
    assert_equal(2, io.write_count)
  end

  def test_failed_nested_mark_checkpoint_remains_when_enclosing_batch_fails
    io = CountingIO.new
    logger = Logger.new(io, formatter: lambda {|severity, time, progname, message|
      "#{message}\n"
    })

    assert_raise(RuntimeError) do
      logger.batch do
        logger.info('outer')
        begin
          logger.batch(on_error: :mark) do
            logger.info('inner')
            raise('inner failure')
          end
        rescue RuntimeError
        end
        raise('outer failure')
      end
    end

    assert_equal("outer\ninner\nRuntimeError: inner failure\n", io.string)
    assert_equal(1, io.write_count)
  end

  def test_batch_enforces_buffer_limit
    io = CountingIO.new
    logger = Logger.new(io, formatter: lambda {|severity, time, progname, message|
      "#{message}\n"
    })

    error = assert_raise(Logger::BatchBufferOverflow) do
      logger.batch(max_bytes: 4) do
        logger.info('a')
        logger.info('bb')
      end
    end

    assert_equal(4, error.limit)
    assert_equal('', io.string)
  end

  def test_batch_limit_marker_is_submitted_even_when_limit_is_exceeded
    io = CountingIO.new
    logger = Logger.new(io)

    assert_raise(Logger::BatchBufferOverflow) do
      logger.batch(on_error: :mark, max_bytes: 2) do
        logger.info('a')
        logger.info('bb')
      end
    end

    assert_match(/a/, io.string)
    assert_match(/Logger::BatchBufferOverflow/, io.string)
    assert_equal(1, io.write_count)
  end

  def test_batch_rejects_invalid_arguments
    logger = Logger.new(nil)

    assert_raise(ArgumentError) { logger.batch(on_error: :invalid) {} }
    assert_raise(ArgumentError) { logger.batch(max_bytes: -1) {} }
    assert_raise(ArgumentError) { logger.batch(max_bytes: 1.5) {} }
  end

  def test_batch_order_with_two_controlled_threads_and_short_writes
    start = Queue.new
    hold = Queue.new
    io = GatedShortWriteIO.new(start, hold)
    logger = Logger.new(io, formatter: lambda {|severity, time, progname, message|
      "#{message}\n"
    })
    ready = Queue.new

    first = Thread.new do
      logger.batch do
        logger.info('T1-1')
        logger.info('T1-2')
        ready << :first
      end
    end

    assert_equal(:first, ready.pop)
    second = Thread.new do
      logger.batch do
        logger.info('T2-1')
        logger.info('T2-2')
        ready << :second
      end
    end

    assert_equal(:second, ready.pop)
    assert_equal(:started, start.pop)
    wait_until_thread_is_blocked_in_log_device(first)
    hold << :go
    second.join(2)
    first.join(2)

    assert_equal(false, first.alive?)
    assert_equal(false, second.alive?)
    assert_equal("T1-1\nT1-2\nT2-1\nT2-2\n", io.string)
  end

  private

  def wait_until_thread_is_blocked_in_log_device(thread)
    deadline = Time.now + 2
    until thread.status == 'sleep'
      flunk('thread did not block') if Time.now >= deadline
      Thread.pass
    end
  end
end
