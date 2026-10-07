require "common"

class ParallelDownloadTest < Net::SFTP::TestCase
  READ_SIZE = 4
  CONTENT = "abcdefghijklmnop".b

  class FakeRequest
    attr_accessor :callback
    attr_reader :id, :type, :properties

    def initialize(id, type)
      @id = id
      @type = type
      @properties = {}
      @callback = nil
    end

    def [](key)
      properties[key]
    end

    def []=(key, value)
      properties[key] = value
    end
  end

  class FakeResponse
    attr_reader :request, :code, :data

    def initialize(request, code, data = nil, eof = nil)
      @request = request
      @code = code
      @data = data
      @eof = eof.nil? ? code == Net::SFTP::Constants::StatusCodes::FX_EOF : eof
    end

    def [](key)
      return data if key == :data
      return "handle" if key == :handle
    end

    def ok?
      code == Net::SFTP::Constants::StatusCodes::FX_OK
    end

    def eof?
      @eof
    end

    def message
      ""
    end
  end

  class FakeSFTP
    attr_reader :logger, :read_requests, :closes, :close_count

    def initialize(content)
      @content = content
      @logger = Logger.new(File::NULL)
      @next_id = 0
      @open_requests = []
      @read_requests = []
      @buffered_ranges = []
      @closes = []
      @close_count = 0
    end

    def open(*, &callback)
      request = FakeRequest.new(@next_id += 1, :open)
      request.callback = callback
      @open_requests << request
      request
    end

    def flush_open
      request = @open_requests.shift or return
      request.callback.call(FakeResponse.new(request, Net::SFTP::Constants::StatusCodes::FX_OK))
    end

    def read(handle, offset, length, &callback)
      request = FakeRequest.new(@next_id += 1, :read)
      request[:offset] = offset
      request[:length] = length
      request.callback = callback
      @read_requests << request
      request
    end

    def close(handle, &callback)
      request = FakeRequest.new(@next_id += 1, :close)
      request[:handle] = handle
      request.callback = callback
      @closes << request
      request
    end

    def deliver_close
      request = @closes.shift or return false
      @close_count += 1
      request.callback.call(FakeResponse.new(request, Net::SFTP::Constants::StatusCodes::FX_OK))
      true
    end

    def loop
      yield while @read_requests.any? || @closes.any?
    end

    def deliver(request, code = nil, data = nil)
      index = @read_requests.index { |item| item.id == request.id }
      return unless index

      @read_requests.delete_at(index)
      @buffered_ranges << [request[:offset], request[:offset] + data.bytesize] if code == Net::SFTP::Constants::StatusCodes::FX_OK && data
      code ||= Net::SFTP::Constants::StatusCodes::FX_OK
      if code == Net::SFTP::Constants::StatusCodes::FX_EOF
        code = Net::SFTP::Constants::StatusCodes::FX_EOF
        data = ""
      else
        data ||= @content.byteslice(request[:offset], request[:length])
      end
      request.callback.call(FakeResponse.new(request, code, data, code == Net::SFTP::Constants::StatusCodes::FX_EOF))
    end

    def deliver_pending(order = :fifo, max = nil, offsets = @content.bytesize, default_code = nil)
      count = 0
      while @read_requests.any? && (max.nil? || count < max)
        request = if order == :lifo
          @read_requests.max_by(&:id)
        else
          @read_requests.min_by(&:id)
        end
        code = request[:offset] >= offsets ?
          Net::SFTP::Constants::StatusCodes::FX_EOF : default_code
        deliver(request, code)
        count += 1
      end
      count
    end

    def unoutput_bytes(delivered)
      ranges = @read_requests.map { |request| [request[:offset], request[:offset] + request[:length]] } + @buffered_ranges
      pending_end = merge_ranges(ranges).map(&:last).max || delivered
      [pending_end - delivered, 0].max
    end

    def consume_buffer(offset, length)
      @buffered_ranges.delete([offset, offset + length])
    end

    def merge_ranges(ranges)
      merged = []
      ranges.sort_by(&:first).each do |start, finish|
        if merged.empty? || start > merged.last[1]
          merged << [start, finish]
        elsif finish > merged.last[1]
          merged[1] = finish
        end
      end
      merged
    end

  end

  class SlowSink
    attr_reader :written, :max_pending_reads, :max_unoutput_bytes

    def initialize(sftp)
      @sftp = sftp
      @written = "".b
      @max_pending_reads = 0
      @max_unoutput_bytes = 0
    end

    def write(data)
      @sftp.deliver_pending(:fifo, 1)
      @max_pending_reads = [@max_pending_reads, @sftp.read_requests.length].max
      @max_unoutput_bytes = [@max_unoutput_bytes, @sftp.unoutput_bytes(written.bytesize + data.bytesize)].max
      @sftp.consume_buffer(written.bytesize, data.bytesize)
      @written << data
      data.bytesize
    end

    def close
      @closed = true
    end

    def closed?
      @closed
    end
  end

  def test_parallel_reads_reassemble_unordered_and_short_reads
    [1, 4].each do |window|
      fake = FakeSFTP.new(CONTENT)
      sink = StringIO.new
      events = []

      start_download(fake, sink,
        :read_size => READ_SIZE, :read_requests => window) do |*args|
        events << args
      end

      deliver_unordered_short_reads(fake)

      assert_equal CONTENT, sink.string
      fake.deliver_close unless fake.closes.empty?
      assert_equal 1, fake.close_count
      assert_progress_is_contiguous(events, CONTENT)
    end
  end

  def test_empty_file
    [1, 4].each do |window|
      fake = FakeSFTP.new("")
      sink = StringIO.new

      download = start_download(fake, sink,
        :read_size => READ_SIZE, :read_requests => window)

      assert_equal window, fake.read_requests.length
      fake.deliver_pending
      fake.deliver_close

      assert_equal "", sink.string
      refute download.active?
      assert_equal 1, fake.close_count
    end
  end

  def test_early_eof_does_not_skip_unfinished_prefix
    fake = FakeSFTP.new(CONTENT)
    sink = StringIO.new
    events = []

    download = start_download(fake, sink,
      :read_size => READ_SIZE, :read_requests => 4) do |*args|
      events << args
    end

    eof_request = fake.read_requests.find { |request| request[:offset] == 8 }
    fake.deliver(eof_request, Net::SFTP::Constants::StatusCodes::FX_EOF)
    assert_equal 0, fake.close_count

    original = [4, 12].map do |offset|
      fake.read_requests.find { |request| request[:offset] == offset }
    end
    original.compact.each { |request| fake.deliver(request) }
    fake.deliver_pending(:fifo, nil, CONTENT.bytesize)
    fake.deliver_close

    assert_equal CONTENT, sink.string
    refute download.active?
    assert_equal 1, fake.close_count
    assert_progress_is_contiguous(events, CONTENT)
  end

  def test_slow_sink_keeps_window_and_writes_in_order
    fake = FakeSFTP.new(CONTENT)
    sink = SlowSink.new(fake)

    download = start_download(fake, sink,
      :read_size => READ_SIZE, :read_requests => 4)

    fake.deliver_pending(:lifo, 1)
    assert download.active?
    assert_equal 0, sink.written.bytesize

    fake.deliver_pending
    fake.deliver_close

    assert_equal CONTENT, sink.written
    assert_operator sink.max_pending_reads, :<=, 4
    assert_operator sink.max_unoutput_bytes, :<=, READ_SIZE * 4
    assert sink.max_unoutput_bytes > 0
    refute download.active?
    assert_equal 1, fake.close_count
  end

  def test_abort_stops_new_requests_drains_pending_and_closes_once
    fake = FakeSFTP.new(CONTENT)
    sink = StringIO.new

    download = start_download(fake, sink,
      :read_size => READ_SIZE, :read_requests => 4)

    pending = fake.read_requests.dup
    pending.reverse.each { |request| fake.deliver(request) if request[:offset] >= READ_SIZE }
    assert_equal "", sink.string

    download.abort!
    pending_count = fake.read_requests.length
    assert pending_count > 0
    assert_equal 0, fake.close_count

    fake.deliver_pending
    fake.deliver_close

    assert_equal "", sink.string
    refute download.active?
    assert_equal 1, fake.close_count
  end

  def test_failure_drains_pending_and_closes_once
    fake = FakeSFTP.new(CONTENT)
    sink = StringIO.new

    download = start_download(fake, sink,
      :read_size => READ_SIZE, :read_requests => 4)

    failed = fake.read_requests[2]
    pending_after_failure = fake.read_requests.length - 1
    fake.deliver(failed, Net::SFTP::Constants::StatusCodes::FX_FAILURE)

    assert_equal 0, fake.close_count
    assert_equal pending_after_failure, fake.read_requests.length
    fake.deliver_pending(:fifo, nil, 0, Net::SFTP::Constants::StatusCodes::FX_FAILURE)
    assert_raises(Net::SFTP::StatusException) { fake.deliver_close }

    assert_equal "", sink.string
    refute download.active?
    assert_equal 1, fake.close_count
  end

  private

  def start_download(fake, sink, options, &progress)
    download = if progress
      Net::SFTP::Operations::Download.new(fake, sink, "remote", options, &progress)
    else
      Net::SFTP::Operations::Download.new(fake, sink, "remote", options)
    end
    fake.flush_open
    download
  end

  def deliver_unordered_short_reads(fake)
    first = fake.read_requests.first
    fake.deliver(first, Net::SFTP::Constants::StatusCodes::FX_OK, "ab")

    4.times do
      request = fake.read_requests.max_by { |item| item[:offset] }
      fake.deliver(request)
    end

    fake.deliver_pending
    fake.deliver_close
  end

  def assert_progress_is_contiguous(events, content)
    delivered = "".b
    delivered_count = 0

    events.each do |event, _download, _entry, offset, data, received, current_delivered, *_|
      next unless event == :receive
      assert_operator delivered_count, :<=, current_delivered
      delivered_count = current_delivered
    end

    events.each do |event, _download, _entry, offset, data, *_|
      next unless event == :get

      assert_equal delivered.bytesize, offset
      delivered << data
    end

    assert_equal content, delivered
  end
end
