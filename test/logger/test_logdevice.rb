# coding: US-ASCII
# frozen_string_literal: false
require 'logger'
require 'tempfile'
require 'tmpdir'
require 'pathname'

class TestLogDevice < Test::Unit::TestCase
  class LogExcnRaiser
    def write(*arg)
      raise 'disk is full'
    end

    def close
    end

    def stat
      Object.new
    end
  end

  def setup
    @top_dir = File.expand_path('../../lib', __dir__)
    @tempfile = Tempfile.new("logger")
    @tempfile.close
    @filename = @tempfile.path
    File.unlink(@filename)
  end

  def teardown
    @tempfile.close(true)
  end

  def d(log, opt = {})
    Logger::LogDevice.new(log, **opt)
  end

  def test_initialize
    logdev = d(STDERR)
    assert_equal(STDERR, logdev.dev)
    assert_nil(logdev.filename)
    assert_raise(TypeError) do
      d(nil)
    end
    #
    logdev = d(@filename)
    begin
      assert_file.exist?(@filename)
      assert_predicate(logdev.dev, :sync)
      refute_predicate(logdev.dev, :binmode?)
      assert_equal(@filename, logdev.filename)
      logdev.write('hello')
    ensure
      logdev.close
    end
    # create logfile which is already exist.
    logdev = d(@filename)
    begin
      assert_predicate(logdev.dev, :sync)
      refute_predicate(logdev.dev, :binmode?)
      logdev.write('world')
      logfile = File.read(@filename)
      assert_equal(2, logfile.split(/\n/).size)
      assert_match(/^helloworld$/, logfile)
    ensure
      logdev.close
    end
    # logfile object with path
    tempfile = Tempfile.new("logger")
    tempfile.sync = true
    logdev = d(tempfile)
    begin
      logdev.write('world')
      logfile = File.read(tempfile.path)
      assert_equal(1, logfile.split(/\n/).size)
      assert_match(/^world$/, logfile)
      assert_equal(tempfile.path, logdev.filename)
    ensure
      logdev.close
      File.unlink(tempfile)
      tempfile.close(true)
    end
    # logfile object with Pathname object
    tempfile = Tempfile.new("logger")
    pathname = Pathname.new(tempfile.path)
    logdev = d(pathname)
    begin
      logdev.write('world')
      logfile = File.read(pathname)
      assert_equal(1, logfile.split(/\n/).size)
      assert_match(/^world$/, logfile)
      assert_equal(pathname, logdev.filename)
    ensure
      logdev.close
      tempfile.close(true)
    end
  end

  def test_write
    r, w = IO.pipe
    logdev = d(w)
    logdev.write("msg2\n\n")
    IO.select([r], nil, nil, 0.1)
    w.close
    msg = r.read
    r.close
    assert_equal("msg2\n\n", msg)
    #
    logdev = d(LogExcnRaiser.new)
    class << (stderr = '')
      alias write concat
    end
    $stderr, stderr = stderr, $stderr
    begin
      assert_nothing_raised do
        logdev.write('hello')
      end
    ensure
      logdev.close
      $stderr, stderr = stderr, $stderr
    end
    assert_equal "log writing failed. disk is full\n", stderr
  end

  def test_close
    r, w = IO.pipe
    logdev = d(w)
    logdev.write("msg2\n\n")
    IO.select([r], nil, nil, 0.1)
    assert_not_predicate(w, :closed?)
    logdev.close
    assert_predicate(w, :closed?)
    r.close
  end

  def test_reopen_io
    logdev  = d(STDERR)
    old_dev = logdev.dev
    logdev.reopen
    assert_equal(STDERR, logdev.dev)
    assert_not_predicate(old_dev, :closed?)
  end

  def test_reopen_io_by_io
    logdev  = d(STDERR)
    old_dev = logdev.dev
    logdev.reopen(STDOUT)
    assert_equal(STDOUT, logdev.dev)
    assert_not_predicate(old_dev, :closed?)
  end

  def test_reopen_io_by_file
    logdev  = d(STDERR)
    old_dev = logdev.dev
    logdev.reopen(@filename)
    begin
      assert_file.exist?(@filename)
      assert_equal(@filename, logdev.filename)
      assert_not_predicate(old_dev, :closed?)
    ensure
      logdev.close
    end
  end

  def test_reopen_file
    logdev = d(@filename)
    old_dev = logdev.dev

    logdev.reopen
    begin
      assert_file.exist?(@filename)
      assert_equal(@filename, logdev.filename)
      assert_predicate(old_dev, :closed?)
    ensure
      logdev.close
    end
  end

  def test_reopen_file_by_io
    logdev = d(@filename)
    old_dev = logdev.dev
    logdev.reopen(STDOUT)
    assert_equal(STDOUT, logdev.dev)
    assert_nil(logdev.filename)
    assert_predicate(old_dev, :closed?)
  end

  def test_reopen_file_by_file
    logdev = d(@filename)
    old_dev = logdev.dev

    tempfile2 = Tempfile.new("logger")
    tempfile2.close
    filename2 = tempfile2.path
    File.unlink(filename2)

    logdev.reopen(filename2)
    begin
      assert_file.exist?(filename2)
      assert_equal(filename2, logdev.filename)
      assert_predicate(old_dev, :closed?)
    ensure
      logdev.close
      tempfile2.close(true)
    end
  end

  def test_perm_after_shift
    mode = 0o611
    File.open(@filename, "w") {|f| f.chmod mode}
    logfile = @filename
    logfile0 = logfile + '.0'
    logdev = d(@filename, shift_age: 1, shift_size: 0)
    logdev.write('hello')
    logdev.write('hello')
    logdev.close

    assert_equal File.stat(logfile0).mode, File.stat(logfile).mode
  ensure
    if logfile0
      File.unlink(logfile0) rescue nil
    end
  end

  def test_shifting_size_with_reopen
    tmpfile = Tempfile.new([File.basename(__FILE__, '.*'), '_1.log'])
    logfile = tmpfile.path
    logfile0 = logfile + '.0'
    logfile1 = logfile + '.1'
    logfile2 = logfile + '.2'
    logfile3 = logfile + '.3'
    tmpfile.close(true)
    File.unlink(logfile) if File.exist?(logfile)
    File.unlink(logfile0) if File.exist?(logfile0)
    File.unlink(logfile1) if File.exist?(logfile1)
    File.unlink(logfile2) if File.exist?(logfile2)

    logger = Logger.new(STDERR)
    logger.reopen(logfile, 4, 100)

    logger.error("0" * 15)
    assert_file.exist?(logfile)
    assert_file.not_exist?(logfile0)
    logger.error("0" * 15)
    assert_file.exist?(logfile0)
    assert_file.not_exist?(logfile1)
    logger.error("0" * 15)
    assert_file.exist?(logfile1)
    assert_file.not_exist?(logfile2)
    logger.error("0" * 15)
    assert_file.exist?(logfile2)
    assert_file.not_exist?(logfile3)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile3)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile3)
    logger.close
    File.unlink(logfile)
    File.unlink(logfile0)
    File.unlink(logfile1)
    File.unlink(logfile2)

    tmpfile = Tempfile.new([File.basename(__FILE__, '.*'), '_2.log'])
    logfile = tmpfile.path
    logfile0 = logfile + '.0'
    logfile1 = logfile + '.1'
    logfile2 = logfile + '.2'
    logfile3 = logfile + '.3'
    tmpfile.close(true)
    logger = Logger.new(logfile, 4, 150)
    logger.error("0" * 15)
    assert_file.exist?(logfile)
    assert_file.not_exist?(logfile0)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile0)
    logger.error("0" * 15)
    assert_file.exist?(logfile0)
    assert_file.not_exist?(logfile1)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile1)
    logger.error("0" * 15)
    assert_file.exist?(logfile1)
    assert_file.not_exist?(logfile2)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile2)
    logger.error("0" * 15)
    assert_file.exist?(logfile2)
    assert_file.not_exist?(logfile3)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile3)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile3)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile3)
    logger.close
    File.unlink(logfile)
    File.unlink(logfile0)
    File.unlink(logfile1)
    File.unlink(logfile2)
  end

  def test_shifting_size
    tmpfile = Tempfile.new([File.basename(__FILE__, '.*'), '_1.log'])
    logfile = tmpfile.path
    logfile0 = logfile + '.0'
    logfile1 = logfile + '.1'
    logfile2 = logfile + '.2'
    logfile3 = logfile + '.3'
    tmpfile.close(true)
    File.unlink(logfile) if File.exist?(logfile)
    File.unlink(logfile0) if File.exist?(logfile0)
    File.unlink(logfile1) if File.exist?(logfile1)
    File.unlink(logfile2) if File.exist?(logfile2)
    logger = Logger.new(logfile, 4, 100)
    logger.error("0" * 15)
    assert_file.exist?(logfile)
    assert_file.not_exist?(logfile0)
    logger.error("0" * 15)
    assert_file.exist?(logfile0)
    assert_file.not_exist?(logfile1)
    logger.error("0" * 15)
    assert_file.exist?(logfile1)
    assert_file.not_exist?(logfile2)
    logger.error("0" * 15)
    assert_file.exist?(logfile2)
    assert_file.not_exist?(logfile3)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile3)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile3)
    logger.close
    File.unlink(logfile)
    File.unlink(logfile0)
    File.unlink(logfile1)
    File.unlink(logfile2)

    tmpfile = Tempfile.new([File.basename(__FILE__, '.*'), '_2.log'])
    logfile = tmpfile.path
    logfile0 = logfile + '.0'
    logfile1 = logfile + '.1'
    logfile2 = logfile + '.2'
    logfile3 = logfile + '.3'
    tmpfile.close(true)
    logger = Logger.new(logfile, 4, 150)
    logger.error("0" * 15)
    assert_file.exist?(logfile)
    assert_file.not_exist?(logfile0)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile0)
    logger.error("0" * 15)
    assert_file.exist?(logfile0)
    assert_file.not_exist?(logfile1)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile1)
    logger.error("0" * 15)
    assert_file.exist?(logfile1)
    assert_file.not_exist?(logfile2)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile2)
    logger.error("0" * 15)
    assert_file.exist?(logfile2)
    assert_file.not_exist?(logfile3)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile3)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile3)
    logger.error("0" * 15)
    assert_file.not_exist?(logfile3)
    logger.close
    File.unlink(logfile)
    File.unlink(logfile0)
    File.unlink(logfile1)
    File.unlink(logfile2)
  end

  def test_shifting_age_variants
    logger = Logger.new(@filename, 'daily')
    logger.info('daily')
    logger.close
    logger = Logger.new(@filename, 'weekly')
    logger.info('weekly')
    logger.close
    logger = Logger.new(@filename, 'monthly')
    logger.info('monthly')
    logger.close
  end

  def test_invalid_shifting_age
    assert_raise(ArgumentError) { Logger::Period.next_rotate_time(Time.now, 'invalid') }
    assert_raise(ArgumentError) { Logger::Period.previous_period_end(Time.now, 'invalid') }
  end

  def test_shifting_age
    yyyymmdd = Time.now.strftime("%Y%m%d")
    filename1 = @filename + ".#{yyyymmdd}"
    filename2 = @filename + ".#{yyyymmdd}.1"
    filename3 = @filename + ".#{yyyymmdd}.2"
    begin
      logger = Logger.new(@filename, 'now')
      assert_file.exist?(@filename)
      assert_file.not_exist?(filename1)
      assert_file.not_exist?(filename2)
      assert_file.not_exist?(filename3)
      logger.info("0" * 15)
      assert_file.exist?(@filename)
      assert_file.exist?(filename1)
      assert_file.not_exist?(filename2)
      assert_file.not_exist?(filename3)
      logger.warn("0" * 15)
      assert_file.exist?(@filename)
      assert_file.exist?(filename1)
      assert_file.exist?(filename2)
      assert_file.not_exist?(filename3)
      logger.error("0" * 15)
      assert_file.exist?(@filename)
      assert_file.exist?(filename1)
      assert_file.exist?(filename2)
      assert_file.exist?(filename3)
    ensure
      logger.close if logger
      [filename1, filename2, filename3].each do |filename|
        File.unlink(filename) if File.exist?(filename)
      end
    end
  end

  def test_shifting_period_suffix
    ['%Y%m%d', '%Y-%m-%d', '%Y'].each do |format|
      if format == '%Y%m%d' # default
        logger = Logger.new(@filename, 'now', 1048576)
      else # config
        logger = Logger.new(@filename, 'now', 1048576, shift_period_suffix: format)
      end
      begin
        yyyymmdd = Time.now.strftime(format)
        filename1 = @filename + ".#{yyyymmdd}"
        filename2 = @filename + ".#{yyyymmdd}.1"
        filename3 = @filename + ".#{yyyymmdd}.2"
        logger.info("0" * 15)
        logger.info("0" * 15)
        logger.info("0" * 15)
        assert_file.exist?(@filename)
        assert_file.exist?(filename1)
        assert_file.exist?(filename2)
        assert_file.exist?(filename3)
      ensure
        logger.close if logger
        [filename1, filename2, filename3].each do |filename|
          File.unlink(filename) if File.exist?(filename)
        end
      end
    end
  end

  def test_shifting_size_in_multiprocess
    tmpfile = Tempfile.new([File.basename(__FILE__, '.*'), '_1.log'])
    logfile = tmpfile.path
    logfile0 = logfile + '.0'
    logfile1 = logfile + '.1'
    logfile2 = logfile + '.2'
    tmpfile.close(true)
    File.unlink(logfile) if File.exist?(logfile)
    File.unlink(logfile0) if File.exist?(logfile0)
    File.unlink(logfile1) if File.exist?(logfile1)
    File.unlink(logfile2) if File.exist?(logfile2)
    begin
      stderr = run_children(2, [logfile], "#{<<-"begin;"}\n#{<<-'end;'}")
      begin;
        logger = Logger.new(ARGV[0], 4, 10)
        10.times do
          logger.info '0' * 15
        end
      end;
      assert_no_match(/log shifting failed/, stderr)
      assert_no_match(/log writing failed/, stderr)
      assert_no_match(/log rotation inter-process lock failed/, stderr)
    ensure
      File.unlink(logfile) if File.exist?(logfile)
      File.unlink(logfile0) if File.exist?(logfile0)
      File.unlink(logfile1) if File.exist?(logfile1)
      File.unlink(logfile2) if File.exist?(logfile2)
    end
  end

  def test_shifting_age_in_multiprocess
    yyyymmdd = Time.now.strftime("%Y%m%d")
    begin
      stderr = run_children(2, [@filename], "#{<<-"begin;"}\n#{<<-'end;'}")
      begin;
        logger = Logger.new(ARGV[0], 'now')
        10.times do
          logger.info '0' * 15
        end
      end;
      assert_no_match(/log shifting failed/, stderr)
      assert_no_match(/log writing failed/, stderr)
      assert_no_match(/log rotation inter-process lock failed/, stderr)
    ensure
      Dir.glob("#{@filename}.#{yyyymmdd}{,.[1-9]*}") do |filename|
        File.unlink(filename) if File.exist?(filename)
      end
    end
  end

  def test_open_without_header
    d(@filename, skip_header: true)

    assert_equal("", File.read(@filename))
  end

  def test_open_logfile_in_multiprocess
    tmpfile = Tempfile.new([File.basename(__FILE__, '.*'), '_1.log'])
    logfile = tmpfile.path
    tmpfile.close(true)
    begin
      20.times do
        run_children(2, [logfile], "#{<<-"begin;"}\n#{<<-'end;'}")
        begin;
          logfile = ARGV[0]
          logdev = Logger::LogDevice.new(logfile)
          logdev.send(:open_logfile, logfile)
        end;
        assert_equal(1, File.readlines(logfile).grep(/# Logfile created on/).size)
        File.unlink(logfile)
      end
    ensure
      File.unlink(logfile) if File.exist?(logfile)
    end
  end

  def test_shifting_size_not_rotate_too_much
    logdev0 = d(@filename)
    logdev0.__send__(:add_log_header, @tempfile)
    header_size = @tempfile.size
    message = "*" * 99 + "\n"
    shift_size = header_size + message.size * 3 - 1
    opt = {shift_age: 1, shift_size: shift_size}

    Dir.mktmpdir do |tmpdir|
      begin
        log = File.join(tmpdir, "log")
        logdev1 = d(log, opt)
        logdev2 = d(log, opt)

        assert_file.identical?(log, logdev1.dev)
        assert_file.identical?(log, logdev2.dev)

        3.times{logdev1.write(message)}
        assert_file.identical?(log, logdev1.dev)
        assert_file.identical?(log, logdev2.dev)

        logdev1.write(message)
        assert_file.identical?(log, logdev1.dev)
        # NOTE: below assertion fails in JRuby 9.3 and TruffleRuby
        unless %w[jruby truffleruby].include? RUBY_ENGINE
          assert_file.identical?(log + ".0", logdev2.dev)
        end

        logdev2.write(message)
        assert_file.identical?(log, logdev1.dev)
        assert_file.identical?(log, logdev2.dev)

        logdev1.write(message)
        assert_file.identical?(log, logdev1.dev)
        assert_file.identical?(log, logdev2.dev)
      ensure
        logdev1.close if logdev1
        logdev2.close if logdev2
      end
    end
  ensure
    logdev0.close
  end

  def test_shifting_midnight
    Dir.mktmpdir do |tmpdir|
      assert_in_out_err([*%W"--disable=gems -I#{@top_dir} -rlogger -C#{tmpdir} -"], "#{<<-"begin;"}\n#{<<-'end;'}")
      begin;
        begin
          module FakeTime
            attr_accessor :now
          end

          class << Time
            prepend FakeTime
          end

          log = "log"
          File.open(log, "w") {}
          File.utime(*[Time.mktime(2014, 1, 2, 0, 0, 0)]*2, log)

          Time.now = Time.mktime(2014, 1, 2, 23, 59, 59, 999000)
          dev = Logger::LogDevice.new(log, shift_age: 'daily')
          dev.write("#{Time.now} hello-1\n")
          File.utime(Time.now, Time.now, log)

          Time.now = Time.mktime(2014, 1, 3, 1, 1, 1)
          dev.write("#{Time.now} hello-2\n")
          File.utime(Time.now, Time.now, log)
        ensure
          dev.close
        end
      end;

      bug = '[GH-539]'
      log = File.join(tmpdir, "log")
      cont = File.read(log)
      assert_match(/hello-2/, cont)
      assert_not_match(/hello-1/, cont)
      assert_file.for(bug).exist?(log+".20140102")
      assert_match(/hello-1/, File.read(log+".20140102"), bug)
    end
  end

  env_tz_works = /linux|darwin|freebsd|openbsd/ =~ RUBY_PLATFORM # borrow from test/ruby/test_time_tz.rb

  def test_shifting_weekly
    Dir.mktmpdir do |tmpdir|
      assert_in_out_err([{"TZ"=>"UTC"}, *%W"-I#{@top_dir} -rlogger -C#{tmpdir} -"], "#{<<-"begin;"}\n#{<<-'end;'}")
      begin;
        begin
          module FakeTime
            attr_accessor :now
          end

          class << Time
            prepend FakeTime
          end

          log = "log"
          File.open(log, "w") {}
          Time.now = Time.utc(2015, 12, 14, 0, 1, 1)
          File.utime(Time.now, Time.now, log)

          dev = Logger::LogDevice.new("log", shift_age: 'weekly')

          Time.now = Time.utc(2015, 12, 19, 12, 34, 56)
          dev.write("#{Time.now} hello-1\n")
          File.utime(Time.now, Time.now, log)

          Time.now = Time.utc(2015, 12, 20, 0, 1, 1)
          dev.write("#{Time.now} hello-2\n")
          File.utime(Time.now, Time.now, log)
        ensure
          dev.close if dev
        end
      end;
      log = File.join(tmpdir, "log")
      cont = File.read(log)
      assert_match(/hello-2/, cont)
      assert_not_match(/hello-1/, cont)
      log = Dir.glob(log+".*")
      assert_equal(1, log.size)
      log, = *log
      cont = File.read(log)
      assert_match(/hello-1/, cont)
      assert_equal("2015-12-19", cont[/^[-\d]+/])
      assert_equal("20151219", log[/\d+\z/])
    end
  end if env_tz_works

  def test_shifting_monthly
    Dir.mktmpdir do |tmpdir|
      assert_in_out_err([{"TZ"=>"UTC"}, *%W"-I#{@top_dir} -rlogger -C#{tmpdir} -"], "#{<<-"begin;"}\n#{<<-'end;'}")
      begin;
        begin
          module FakeTime
            attr_accessor :now
          end

          class << Time
            prepend FakeTime
          end

          log = "log"
          File.open(log, "w") {}
          Time.now = Time.utc(2015, 12, 14, 0, 1, 1)
          File.utime(Time.now, Time.now, log)

          dev = Logger::LogDevice.new("log", shift_age: 'monthly')

          Time.now = Time.utc(2015, 12, 31, 12, 34, 56)
          dev.write("#{Time.now} hello-1\n")
          File.utime(Time.now, Time.now, log)

          Time.now = Time.utc(2016, 1, 1, 0, 1, 1)
          dev.write("#{Time.now} hello-2\n")
          File.utime(Time.now, Time.now, log)
        ensure
          dev.close if dev
        end
      end;
      log = File.join(tmpdir, "log")
      cont = File.read(log)
      assert_match(/hello-2/, cont)
      assert_not_match(/hello-1/, cont)
      log = Dir.glob(log+".*")
      assert_equal(1, log.size)
      log, = *log
      cont = File.read(log)
      assert_match(/hello-1/, cont)
      assert_equal("2015-12-31", cont[/^[-\d]+/])
      assert_equal("20151231", log[/\d+\z/])
    end
  end if env_tz_works

  def test_shifting_dst_change
    Dir.mktmpdir do |tmpdir|
      assert_in_out_err([{"TZ"=>"Europe/London"}, *%W"--disable=gems -I#{@top_dir} -rlogger -C#{tmpdir} -"], "#{<<-"begin;"}\n#{<<-'end;'}")
      begin;
        begin
          module FakeTime
            attr_accessor :now
          end

          class << Time
            prepend FakeTime
          end

          log = "log"
          File.open(log, "w") {}

          Time.now = Time.mktime(2014, 3, 30, 0, 1, 1)
          File.utime(Time.now, Time.now, log)

          dev = Logger::LogDevice.new(log, shift_age: 'daily')
          dev.write("#{Time.now} hello-1\n")
          File.utime(*[Time.mktime(2014, 3, 30, 0, 2, 3)]*2, log)

          Time.now = Time.mktime(2014, 3, 31, 0, 1, 1)
          dev.write("#{Time.now} hello-2\n")
          File.utime(Time.now, Time.now, log)
        ensure
          dev.close
        end
      end;

      log = File.join(tmpdir, "log")
      cont = File.read(log)
      assert_match(/hello-2/, cont)
      assert_not_match(/hello-1/, cont)
      assert_file.exist?(log+".20140330")
    end
  end if env_tz_works

  def test_shifting_weekly_dst_change
    Dir.mktmpdir do |tmpdir|
      assert_separately([{"TZ"=>"Europe/London"}, *%W"-I#{@top_dir} -W0 -rlogger -C#{tmpdir} -"], "#{<<-"begin;"}\n#{<<-'end;'}")
      begin;
        begin
          module FakeTime
            attr_accessor :now
          end

          class << Time
            prepend FakeTime
          end

          log = "log"
          File.open(log, "w") {}
          Time.now = Time.mktime(2015, 10, 25, 0, 1, 1)
          File.utime(Time.now, Time.now, log)

          dev = Logger::LogDevice.new("log", shift_age: 'weekly')
          dev.write("#{Time.now} hello-1\n")
          File.utime(Time.now, Time.now, log)
        ensure
          dev.close if dev
        end
      end;
      log = File.join(tmpdir, "log")
      cont = File.read(log)
      assert_match(/hello-1/, cont)
    end
  end if env_tz_works

  def test_shifting_monthly_dst_change
    Dir.mktmpdir do |tmpdir|
      assert_separately([{"TZ"=>"Europe/London"}, *%W"-I#{@top_dir} -W0 -rlogger -C#{tmpdir} -"], "#{<<-"begin;"}\n#{<<-'end;'}")
      begin;
        begin
          module FakeTime
            attr_accessor :now
          end

          class << Time
            prepend FakeTime
          end

          log = "log"
          File.open(log, "w") {}
          Time.now = Time.utc(2016, 9, 1, 0, 1, 1)
          File.utime(Time.now, Time.now, log)

          dev = Logger::LogDevice.new("log", shift_age: 'monthly')

          Time.now = Time.utc(2016, 9, 8, 7, 6, 5)
          dev.write("#{Time.now} hello-1\n")
          File.utime(Time.now, Time.now, log)

          Time.now = Time.utc(2016, 10, 9, 8, 7, 6)
          dev.write("#{Time.now} hello-2\n")
          File.utime(Time.now, Time.now, log)

          Time.now = Time.utc(2016, 10, 9, 8, 7, 7)
          dev.write("#{Time.now} hello-3\n")
          File.utime(Time.now, Time.now, log)
        ensure
          dev.close if dev
        end
      end;
      log = File.join(tmpdir, "log")
      cont = File.read(log)
      assert_match(/hello-2/, cont)
      assert_not_match(/hello-1/, cont)
      log = Dir.glob(log+".*")
      assert_equal(1, log.size)
      log, = *log
      cont = File.read(log)
      assert_match(/hello-1/, cont)
      assert_equal("2016-09-08", cont[/^[-\d]+/])
      assert_equal("20160930", log[/\d+\z/])
    end
  end if env_tz_works

  def test_shifting_midnight_exist_file
    Dir.mktmpdir do |tmpdir|
      assert_in_out_err([*%W"--disable=gems -I#{@top_dir} -rlogger -C#{tmpdir} -"], "#{<<-"begin;"}\n#{<<-'end;'}")
      begin;
        begin
          module FakeTime
            attr_accessor :now
          end

          class << Time
            prepend FakeTime
          end

          log = "log"
          File.open(log, "w") {}
          File.utime(*[Time.mktime(2014, 1, 2, 0, 0, 0)]*2, log)

          Time.now = Time.mktime(2014, 1, 2, 23, 59, 59, 999000)
          dev = Logger::LogDevice.new(log, shift_age: 'daily')
          dev.write("#{Time.now} hello-1\n")
          dev.close
          File.utime(Time.now, Time.now, log)

          Time.now = Time.mktime(2014, 1, 3, 1, 1, 1)
          dev = Logger::LogDevice.new(log, shift_age: 'daily')
          dev.write("#{Time.now} hello-2\n")
          File.utime(Time.now, Time.now, log)
        ensure
          dev.close
        end
      end;

      bug = '[GH-539]'
      log = File.join(tmpdir, "log")
      cont = File.read(log)
      assert_match(/hello-2/, cont)
      assert_not_match(/hello-1/, cont)
      assert_file.for(bug).exist?(log+".20140102")
      assert_match(/hello-1/, File.read(log+".20140102"), bug)
    end
  end

  def test_shifting_weekly_exist_file
    Dir.mktmpdir do |tmpdir|
      assert_in_out_err([{"TZ"=>"UTC"}, *%W"-I#{@top_dir} -rlogger -C#{tmpdir} -"], "#{<<-"begin;"}\n#{<<-'end;'}")
      begin;
        begin
          module FakeTime
            attr_accessor :now
          end

          class << Time
            prepend FakeTime
          end

          log = "log"
          File.open(log, "w") {}
          Time.now = Time.utc(2015, 12, 14, 0, 1, 1)
          File.utime(Time.now, Time.now, log)

          dev = Logger::LogDevice.new("log", shift_age: 'weekly')

          Time.now = Time.utc(2015, 12, 19, 12, 34, 56)
          dev.write("#{Time.now} hello-1\n")
          dev.close
          File.utime(Time.now, Time.now, log)

          Time.now = Time.utc(2015, 12, 20, 0, 1, 1)
          dev = Logger::LogDevice.new("log", shift_age: 'weekly')
          dev.write("#{Time.now} hello-2\n")
          File.utime(Time.now, Time.now, log)
        ensure
          dev.close if dev
        end
      end;
      log = File.join(tmpdir, "log")
      cont = File.read(log)
      assert_match(/hello-2/, cont)
      assert_not_match(/hello-1/, cont)
      log = Dir.glob(log+".*")
      assert_equal(1, log.size)
      log, = *log
      cont = File.read(log)
      assert_match(/hello-1/, cont)
      assert_equal("2015-12-19", cont[/^[-\d]+/])
      assert_equal("20151219", log[/\d+\z/])
    end
  end if env_tz_works

  def test_shifting_monthly_exist_file
    Dir.mktmpdir do |tmpdir|
      assert_in_out_err([{"TZ"=>"UTC"}, *%W"-I#{@top_dir} -rlogger -C#{tmpdir} -"], "#{<<-"begin;"}\n#{<<-'end;'}")
      begin;
        begin
          module FakeTime
            attr_accessor :now
          end

          class << Time
            prepend FakeTime
          end

          log = "log"
          File.open(log, "w") {}
          Time.now = Time.utc(2015, 12, 14, 0, 1, 1)
          File.utime(Time.now, Time.now, log)

          dev = Logger::LogDevice.new("log", shift_age: 'monthly')

          Time.now = Time.utc(2015, 12, 31, 12, 34, 56)
          dev.write("#{Time.now} hello-1\n")
          dev.close
          File.utime(Time.now, Time.now, log)

          Time.now = Time.utc(2016, 1, 1, 0, 1, 1)
          dev = Logger::LogDevice.new("log", shift_age: 'monthly')
          dev.write("#{Time.now} hello-2\n")
          File.utime(Time.now, Time.now, log)
        ensure
          dev.close if dev
        end
      end;
      log = File.join(tmpdir, "log")
      cont = File.read(log)
      assert_match(/hello-2/, cont)
      assert_not_match(/hello-1/, cont)
      log = Dir.glob(log+".*")
      assert_equal(1, log.size)
      log, = *log
      cont = File.read(log)
      assert_match(/hello-1/, cont)
      assert_equal("2015-12-31", cont[/^[-\d]+/])
      assert_equal("20151231", log[/\d+\z/])
    end
  end if env_tz_works

  # A mutable, injectable time source for rotation tests, so that
  # period boundaries can be crossed without waiting for real time.
  class FakeClock
    attr_accessor :now

    def initialize(now)
      @now = now
    end

    def call
      @now
    end
  end

  def prepare_log_file(log, mtime)
    File.open(log, 'w') {}
    File.utime(mtime, mtime, log)
  end

  # Dir.glob with an absolute pattern does not work in every test
  # environment, so list archive files (log.<suffix>...) directly.
  def log_archives(log)
    dir = File.dirname(log)
    prefix = File.basename(log) + '.'
    Dir.children(dir).select {|name|
      name.start_with?(prefix)
    }.map {|name|
      File.join(dir, name)
    }.reject {|path|
      File.directory?(path)
    }.sort
  end

  # The active log file plus all of its archives.
  def log_files(log)
    dir = File.dirname(log)
    base = File.basename(log)
    Dir.children(dir).select {|name|
      name == base || name.start_with?(base + '.')
    }.map {|name|
      File.join(dir, name)
    }
  end

  def test_combined_rotation_size_within_period
    Dir.mktmpdir do |dir|
      log = File.join(dir, 'app.log')
      clock = FakeClock.new(Time.mktime(2014, 1, 2, 10, 0, 0))
      prepare_log_file(log, clock.now)
      dev = Logger::LogDevice.new(log, shift_age: 'daily', shift_size: 30,
                                  skip_header: true, clock: clock)
      begin
        dev.write('1' * 21)
        dev.write('1' * 21) # 42 bytes, exceeds 30; rotated before next write
        assert_file.not_exist?("#{log}.20140102")
        dev.write('2' * 21)
        assert_file.exist?("#{log}.20140102")
        assert_equal('1' * 42, File.read("#{log}.20140102"))
        assert_file.not_exist?("#{log}.20140102.1")
        dev.write('2' * 21) # 42 bytes again
        dev.write('3' * 21)
        assert_file.exist?("#{log}.20140102.1")
        assert_equal('2' * 42, File.read("#{log}.20140102.1"))
        assert_equal('3' * 21, File.read(log))
      ensure
        dev.close
      end
    end
  end

  def test_combined_rotation_period_does_not_overwrite_segments
    Dir.mktmpdir do |dir|
      log = File.join(dir, 'app.log')
      clock = FakeClock.new(Time.mktime(2014, 1, 2, 10, 0, 0))
      prepare_log_file(log, clock.now)
      dev = Logger::LogDevice.new(log, shift_age: 'daily', shift_size: 30,
                                  skip_header: true, clock: clock)
      begin
        dev.write('1' * 21)
        dev.write('1' * 21)
        dev.write('2' * 21) # rotates: log.20140102
        dev.write('2' * 21)
        dev.write('3' * 21) # rotates: log.20140102.1
        assert_equal('1' * 42, File.read("#{log}.20140102"))
        assert_equal('2' * 42, File.read("#{log}.20140102.1"))
        # Cross into the next day; the last segment of 2014-01-02 must
        # land on the next free index instead of clobbering .20140102.
        clock.now = Time.mktime(2014, 1, 3, 9, 0, 0)
        dev.write('4' * 21)
        assert_file.exist?("#{log}.20140102.2")
        assert_equal('3' * 21, File.read("#{log}.20140102.2"))
        assert_equal('1' * 42, File.read("#{log}.20140102"))
        assert_equal('2' * 42, File.read("#{log}.20140102.1"))
        # Size rotation in the new period uses the new day's suffix.
        dev.write('4' * 21)
        dev.write('5' * 21)
        assert_file.exist?("#{log}.20140103")
        assert_equal('4' * 42, File.read("#{log}.20140103"))
        assert_equal('5' * 21, File.read(log))
      ensure
        dev.close
      end
    end
  end

  def test_combined_rotation_exact_size_boundary
    Dir.mktmpdir do |dir|
      log = File.join(dir, 'app.log')
      clock = FakeClock.new(Time.mktime(2014, 1, 2, 10, 0, 0))
      prepare_log_file(log, clock.now)
      dev = Logger::LogDevice.new(log, shift_age: 'daily', shift_size: 42,
                                  skip_header: true, clock: clock)
      begin
        dev.write('1' * 21)
        dev.write('1' * 21) # exactly 42 bytes == shift_size
        dev.write('2' * 21) # no rotation yet: 42 is not > 42
        assert_file.not_exist?("#{log}.20140102")
        assert_equal('1' * 42 + '2' * 21, File.read(log))
        dev.write('3' * 21) # now 63 > 42, so this write rotates first
        assert_file.exist?("#{log}.20140102")
        assert_equal('1' * 42 + '2' * 21, File.read("#{log}.20140102"))
        assert_equal('3' * 21, File.read(log))
      ensure
        dev.close
      end
    end
  end

  def test_combined_rotation_clock_rollback
    Dir.mktmpdir do |dir|
      log = File.join(dir, 'app.log')
      clock = FakeClock.new(Time.mktime(2014, 1, 2, 10, 0, 0))
      prepare_log_file(log, clock.now)
      dev = Logger::LogDevice.new(log, shift_age: 'daily', shift_size: 30,
                                  skip_header: true, clock: clock)
      begin
        dev.write('1' * 21)
        dev.write('1' * 21)
        dev.write('2' * 21) # size rotation -> log.20140102
        clock.now = Time.mktime(2014, 1, 3, 9, 0, 0)
        dev.write('3' * 21) # period rotation -> log.20140102.1
        assert_equal('1' * 42, File.read("#{log}.20140102"))
        assert_equal('2' * 21, File.read("#{log}.20140102.1"))
        # The clock jumps backwards: no period rotation may happen,
        # and later segments must not overwrite the existing ones.
        clock.now = Time.mktime(2014, 1, 2, 15, 0, 0)
        dev.write('4' * 21)
        assert_file.not_exist?("#{log}.20140102.2")
        dev.write('4' * 21) # size rotation with the rolled-back date
        assert_file.exist?("#{log}.20140102.2")
        assert_equal('3' * 21 + '4' * 21, File.read("#{log}.20140102.2"))
        dev.write('5' * 21)
        assert_equal('1' * 42, File.read("#{log}.20140102"))
        assert_equal('2' * 21, File.read("#{log}.20140102.1"))
        assert_equal('4' * 21 + '5' * 21, File.read(log))
      ensure
        dev.close
      end
    end
  end

  def test_combined_rotation_shift_keep_prunes_all_archives
    Dir.mktmpdir do |dir|
      log = File.join(dir, 'app.log')
      clock = FakeClock.new(Time.mktime(2014, 1, 2, 10, 0, 0))
      prepare_log_file(log, clock.now)
      dev = Logger::LogDevice.new(log, shift_age: 'daily', shift_size: 30,
                                  shift_keep: 3, skip_header: true, clock: clock)
      begin
        # Three size-based segments with increasing mtimes.
        dev.write('1' * 21)
        dev.write('1' * 21)
        File.utime(Time.mktime(2014, 1, 2, 10, 0, 0), Time.mktime(2014, 1, 2, 10, 0, 0), log)
        dev.write('x') # rotates -> log.20140102
        dev.write('2' * 21)
        dev.write('2' * 21)
        File.utime(Time.mktime(2014, 1, 2, 11, 0, 0), Time.mktime(2014, 1, 2, 11, 0, 0), log)
        dev.write('x') # rotates -> log.20140102.1
        dev.write('3' * 21)
        dev.write('3' * 21)
        File.utime(Time.mktime(2014, 1, 2, 12, 0, 0), Time.mktime(2014, 1, 2, 12, 0, 0), log)
        dev.write('x') # rotates -> log.20140102.2
        assert_file.exist?("#{log}.20140102")
        assert_file.exist?("#{log}.20140102.1")
        assert_file.exist?("#{log}.20140102.2")
        # A period-based archive competes for the same retention budget:
        # crossing midnight rotates into the next free index and prunes
        # the oldest remaining archive, whichever rotation made it.
        clock.now = Time.mktime(2014, 1, 3, 9, 0, 0)
        File.utime(clock.now, clock.now, log)
        dev.write('4' * 21) # period rotation -> log.20140102.3, prunes .20140102
        assert_file.exist?("#{log}.20140102.3")
        assert_file.not_exist?("#{log}.20140102")
        assert_equal(["#{log}.20140102.1", "#{log}.20140102.2", "#{log}.20140102.3"], log_archives(log))
      ensure
        dev.close
      end
    end
  end

  def test_combined_rotation_multi_instance
    Dir.mktmpdir do |dir|
      log = File.join(dir, 'app.log')
      clock = FakeClock.new(Time.mktime(2014, 1, 2, 10, 0, 0))
      prepare_log_file(log, clock.now)
      opt = {shift_age: 'daily', shift_size: 30, skip_header: true, clock: clock}
      dev1 = Logger::LogDevice.new(log, **opt)
      dev2 = Logger::LogDevice.new(log, **opt)
      begin
        dev1.write('1' * 21)
        dev1.write('1' * 21) # 42 bytes, over the limit
        dev2.write('2' * 21) # dev2 rotates first -> log.20140102
        dev1.write('1' * 21) # dev1 notices the shift and reopens
        dev2.write('2' * 21) # dev2 rotates again -> log.20140102.1
        assert_equal('1' * 42, File.read("#{log}.20140102"))
        assert_equal('2' * 21 + '1' * 21, File.read("#{log}.20140102.1"))
        assert_equal('2' * 21, File.read(log))
        # Nothing was lost, duplicated, or overwritten.
        total = log_files(log).map {|path| File.read(path) }.join
        assert_equal(5, total.scan('1').size / 21 + total.scan('2').size / 21)
        assert_equal(3, log_files(log).size)
      ensure
        dev1.close
        dev2.close
      end
    end
  end

  def test_combined_rotation_dst_change
    Dir.mktmpdir do |dir|
      log = File.join(dir, 'app.log')
      prev_tz = ENV['TZ']
      ENV['TZ'] = 'Europe/London'
      begin
        # 2014-03-30 is the 23-hour day (clocks spring forward).
        clock = FakeClock.new(Time.mktime(2014, 3, 30, 0, 1, 1))
        prepare_log_file(log, clock.now)
        dev = Logger::LogDevice.new(log, shift_age: 'daily', shift_size: 30,
                                    skip_header: true, clock: clock)
        begin
          dev.write('1' * 21)
          dev.write('1' * 21)
          dev.write('2' * 21) # size rotation -> log.20140330
          assert_file.exist?("#{log}.20140330")
          clock.now = Time.mktime(2014, 3, 31, 0, 1, 1)
          dev.write('3' * 21) # period rotation -> log.20140330.1
          assert_file.exist?("#{log}.20140330.1")
          assert_equal('1' * 42, File.read("#{log}.20140330"))
          assert_equal('2' * 21, File.read("#{log}.20140330.1"))
          assert_equal('3' * 21, File.read(log))
        ensure
          dev.close
        end
      ensure
        ENV['TZ'] = prev_tz
      end
    end
  end if env_tz_works

  def test_periodic_rotation_without_shift_size_ignores_size
    Dir.mktmpdir do |dir|
      log = File.join(dir, 'app.log')
      clock = FakeClock.new(Time.mktime(2014, 1, 2, 10, 0, 0))
      prepare_log_file(log, clock.now)
      dev = Logger::LogDevice.new(log, shift_age: 'daily',
                                  skip_header: true, clock: clock)
      begin
        dev.write('1' * 10_000) # far beyond any default shift_size
        assert_file.not_exist?("#{log}.20140102")
        clock.now = Time.mktime(2014, 1, 3, 9, 0, 0)
        dev.write('2' * 21)
        assert_file.exist?("#{log}.20140102")
      ensure
        dev.close
      end
    end
  end

  def test_shift_keep_validation
    assert_raise(ArgumentError) do
      Logger::LogDevice.new(@filename, shift_age: 'daily', shift_keep: -1)
    end
    assert_raise(ArgumentError) do
      Logger::LogDevice.new(@filename, shift_age: 'daily', shift_keep: '2')
    end
  end

  def test_combined_rotation_via_logger
    Dir.mktmpdir do |dir|
      log = File.join(dir, 'app.log')
      clock = FakeClock.new(Time.mktime(2014, 1, 2, 10, 0, 0))
      prepare_log_file(log, clock.now)
      logger = Logger.new(log, 'daily', 100, shift_keep: 2,
                          skip_header: true, clock: clock)
      begin
        4.times { logger.info('x' * 100) } # each entry exceeds shift_size
        archives = log_archives(log)
        assert_equal(2, archives.size) # rotated, and pruned down to shift_keep
        assert(archives.all? {|path| File.basename(path).start_with?('app.log.20140102') })
        clock.now = Time.mktime(2014, 1, 3, 9, 0, 0)
        File.utime(clock.now, clock.now, log)
        4.times { logger.info('y' * 100) }
        archives = log_archives(log)
        assert_equal(2, archives.size)
        assert(archives.all? {|path| File.basename(path).start_with?('app.log.2014') })
      ensure
        logger.close
      end
    end
  end

  private

  def run_children(n, args, src)
    r, w = IO.pipe
    [w, *(1..n).map do
       f = IO.popen([EnvUtil.rubybin, *%w[--disable=gems -], *args], "w", err: w)
       src = "$LOAD_PATH.unshift('#{@top_dir}'); require 'logger';#{src}"
       f.puts(src)
       f
     end].each(&:close)
    stderr = r.read
    r.close
    stderr
  end
end
