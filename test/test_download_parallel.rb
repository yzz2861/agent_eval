require "common"

# Tests for parallel single-file downloads (:read_window option), using a
# local in-memory SFTP protocol stub instead of a scripted SSH session, so
# that out-of-order responses, short reads, slow sinks and mid-transfer
# cancellation can be exercised deterministically.
class DownloadParallelTest < Net::SFTP::TestCase
  include Net::SFTP::Constants::StatusCodes

  # A minimal in-memory stand-in for an SFTP server (and the Net::SFTP
  # session in front of it). It serves a single file from a string and
  # queues every response, delivering them one at a time via #pump, which
  # lets each test decide exactly when and in which order responses
  # arrive.
  class StubServer
    include Net::SFTP::Constants::StatusCodes

    # Every READ request the client issued, as [offset, length] pairs.
    attr_reader :reads

    # How many CLOSE requests the client issued.
    attr_reader :close_count

    # Options:
    # * :max_chunk - never return more than this many bytes per READ,
    #   simulating servers that answer with short reads.
    # * :fail_at   - answer the READ at this offset with FX_FAILURE.
    # * :reorder   - :fifo (default) answers in request order, :lifo
    #   answers the most recently queued response first, simulating
    #   out-of-order arrival on a high-latency link.
    def initialize(contents, options={})
      @contents = contents
      @max_chunk = options[:max_chunk]
      @fail_at = options[:fail_at]
      @reorder = options[:reorder] || :fifo
      @reads = []
      @close_count = 0
      @next_id = 0
      @queue = []
    end

    def logger
      nil
    end

    def open(_remote, &callback)
      request = build_request(:open, &callback)
      enqueue(request, :handle => "handle")
      request
    end

    def read(_handle, offset, length, &callback)
      @reads << [offset, length]
      request = build_request(:read, &callback)
      if @fail_at == offset
        enqueue(request, :code => FX_FAILURE, :message => "read failed")
      elsif offset >= @contents.bytesize
        enqueue(request, :code => FX_EOF)
      else
        data = @contents.byteslice(offset, length)
        data = data.byteslice(0, @max_chunk) if @max_chunk && data.bytesize > @max_chunk
        enqueue(request, :data => data)
      end
      request
    end

    def close(_handle, &callback)
      @close_count += 1
      request = build_request(:close, &callback)
      enqueue(request, :code => FX_OK)
      request
    end

    def pending?
      @queue.any?
    end

    # Delivers the next queued response to the client. Returns false when
    # there is nothing to deliver.
    def pump
      return false if @queue.empty?
      index = @reorder == :lifo ? @queue.length - 1 : 0
      request, response = @queue.delete_at(index)
      request.callback.call(response)
      true
    end

    # Emulates Net::SFTP::Session#loop for Download#wait.
    def loop
      while yield
        raise "stalled: download still active but no response in flight" unless pump
      end
    end

    private

      def build_request(type, &callback)
        @next_id += 1
        Net::SFTP::Request.new(self, type, @next_id, &callback)
      end

      def enqueue(request, data)
        @queue << [request, Net::SFTP::Response.new(request, data)]
      end
  end

  # A sink that only supports sequential #write, recording every write so
  # tests can verify that data was delivered contiguously and in order.
  class RecordingSink
    attr_reader :writes

    def initialize
      @writes = []
      @closed = false
    end

    def write(data)
      @writes << data
      data.bytesize
    end

    def close
      raise "sink closed twice" if @closed
      @closed = true
    end

    def closed?
      @closed
    end

    def string
      @writes.join
    end
  end

  READ_SIZE = 16

  def test_parallel_download_reassembles_out_of_order_responses
    content = make_content(320)
    server, sink, download, _events = prepare_download(content,
      :read_window => 4, :reorder => :lifo)

    download.wait

    assert_equal content, sink.string
    assert sink.closed?
    assert_equal 1, server.close_count
  end

  def test_parallel_download_handles_consecutive_short_reads
    content = make_content(200)
    server, sink, download, _events = prepare_download(content,
      :read_window => 4, :max_chunk => 3, :reorder => :lifo)

    download.wait

    assert_equal content, sink.string
    assert_equal 1, server.close_count
    # the stub really did answer with short reads
    assert server.reads.any? { |offset, length| length < READ_SIZE || offset % READ_SIZE != 0 }
  end

  def test_parallel_download_of_empty_file
    [1, 4].each do |window|
      server, sink, download, _events = prepare_download("", :read_window => window)

      download.wait

      assert_equal "", sink.string
      assert sink.closed?
      assert_equal 1, server.close_count
    end
  end

  def test_parallel_download_to_slow_sink_writes_sequentially_and_bounds_buffer
    content = make_content(256)
    server, sink, download, events = prepare_download(content,
      :read_window => 4, :read_buffer => 2 * READ_SIZE, :reorder => :lifo)

    received = delivered = max_buffered = 0
    while download.active?
      assert server.pump, "stalled with undelivered responses"
      events.each do |event, _dl, _entry, _offset, data|
        received += data.bytesize if event == :receive
        delivered += data.bytesize if event == :get
      end
      events.clear
      max_buffered = [max_buffered, received - delivered].max
    end

    assert_equal content, sink.string
    # every write picked up exactly where the previous one ended
    offset = 0
    sink.writes.each do |chunk|
      assert_equal content.byteslice(offset, chunk.bytesize), chunk
      offset += chunk.bytesize
    end
    # never held more undelivered data than the buffer plus what could
    # still be in flight when the limit was reached
    assert max_buffered <= 2 * READ_SIZE + 4 * READ_SIZE,
      "expected at most #{2 * READ_SIZE + 4 * READ_SIZE} buffered bytes, saw #{max_buffered}"
  end

  def test_parallel_download_abort_discards_in_flight_and_closes_handle_once
    content = make_content(512)
    server, sink, download, _events = prepare_download(content, :read_window => 4)

    3.times { server.pump } # open + two reads
    reads_before_abort = server.reads.length
    bytes_before_abort = sink.string.bytesize

    download.abort!
    assert !download.active?

    server.pump while server.pending?

    assert_equal reads_before_abort, server.reads.length
    assert_equal bytes_before_abort, sink.string.bytesize
    assert_equal 1, server.close_count
  end

  def test_parallel_download_abort_before_open_completes
    content = make_content(512)
    server, _sink, download, _events = prepare_download(content, :read_window => 4)

    download.abort!
    server.pump while server.pending?

    assert_equal [], server.reads
    assert_equal 1, server.close_count
  end

  def test_parallel_download_failure_stops_requests_and_closes_handle_once
    content = make_content(512)
    server, _sink, download, _events = prepare_download(content,
      :read_window => 4, :fail_at => 2 * READ_SIZE)

    error = assert_raises(Net::SFTP::StatusException) { download.wait }
    assert_equal "read failed", error.description

    # reads at 0,16,32,48 plus two more issued after the first two
    # successful responses; nothing new once the failure was seen
    assert_equal 6, server.reads.length
    assert_equal 1, server.close_count
  end

  def test_parallel_download_reports_received_and_delivered_separately
    content = make_content(4 * READ_SIZE)
    _server, _sink, download, events = prepare_download(content,
      :read_window => 4, :reorder => :lifo)

    download.wait

    received = events.select { |e| e[0] == :receive }.map { |e| e[3] }
    delivered = events.select { |e| e[0] == :get }.map { |e| e[3] }

    # chunks arrive out of order (most recently requested first)...
    assert_equal [3, 2, 1, 0].map { |n| n * READ_SIZE }, received
    # ...but are delivered strictly in order, contiguous from zero
    assert_equal [0, 1, 2, 3].map { |n| n * READ_SIZE }, delivered
    assert_equal :open, events.first[0]
    assert_equal :close, events[-2][0]
    assert_equal :finish, events.last[0]
  end

  def test_window_one_and_window_four_transfer_identical_bytes
    content = make_content(1000)

    _s1, sink1, download1, _e1 = prepare_download(content,
      :read_window => 1, :max_chunk => 7)
    download1.wait

    _s4, sink4, download4, _e4 = prepare_download(content,
      :read_window => 4, :max_chunk => 7, :reorder => :lifo)
    download4.wait

    assert_equal content, sink1.string
    assert_equal content, sink4.string
    assert_equal sink1.string, sink4.string
  end

  private

    # Position-coded content: byte i holds (i * 31 + 7) % 256, so any
    # reassembly error changes the resulting string.
    def make_content(size)
      (0...size).map { |i| ((i * 31 + 7) % 256).chr }.join
    end

    def prepare_download(content, options={})
      stub_options = {}
      [:max_chunk, :fail_at, :reorder].each do |key|
        stub_options[key] = options.delete(key) if options.key?(key)
      end
      server = StubServer.new(content, stub_options)
      sink = RecordingSink.new
      events = []
      options = { :read_size => READ_SIZE }.merge(options)
      download = Net::SFTP::Operations::Download.new(server, sink, "/remote/file", options) do |*args|
        events << args
      end
      [server, sink, download, events]
    end
end
