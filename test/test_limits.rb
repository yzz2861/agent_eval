require "common"
require "fileutils"

class LimitsTest < Net::SFTP::TestCase
  PACKET_LIMIT = 100
  READ_LIMIT   = 70
  WRITE_LIMIT  = 80
  HANDLE_LIMIT = 2

  def setup
    @root = File.expand_path("limits-test-#{Process.pid}-#{object_id}", ".tmp-test")
    FileUtils.rm_rf(@root)
    FileUtils.mkdir_p(@root)
  end

  def teardown
    FileUtils.rm_rf(@root)
  end

  def test_upload_uses_packet_budget_and_shared_handle_limit
    local = File.join(@root, "upload")
    FileUtils.mkdir_p(File.join(local, "sub"))
    3.times { |n| File.binwrite(File.join(local, "file#{n}"), "u#{n}" * 150) }
    File.binwrite(File.join(local, "sub", "child"), "child-upload-data\n")

    server = FakeSftpServer.new(limits: true)
    sftp = connected_sftp(server)

    sftp.upload!(local, "/upload", mkdir: true, requests: 16)

    assert server.packets.all? { |packet| packet[:wire_length] <= PACKET_LIMIT }
    assert_equal 15, server.write_lengths.count { |length| length == 59 }
    assert_equal 3, server.write_lengths.count { |length| length == 5 }
    assert_equal 1, server.write_lengths.count { |length| length == 18 }
    assert_equal 19, server.write_lengths.length
    assert_equal 59, server.write_lengths.max
    assert_equal 2, server.max_active_handles
    assert_equal 4, server.opened_handles.count
    assert_equal "u0" * 150, server.files["/upload/file0"].string
    assert_equal "child-upload-data\n", server.files["/upload/sub/child"].string
  end

  def test_download_uses_packet_budget_and_keeps_directory_traversal_open
    destination = File.join(@root, "download")
    server = FakeSftpServer.new(limits: true, directories: {
      "/download" => [["sub", true], ["root1", false], ["root2", false]],
      "/download/sub" => [["child", false]]
    }, files: {
      "/download/root1" => "a" * 300,
      "/download/root2" => "b" * 80,
      "/download/sub/child" => "c" * 300
    })
    sftp = connected_sftp(server)

    sftp.download!("/download", destination, recursive: true, requests: 16)

    assert server.packets.all? { |packet| packet[:wire_length] <= PACKET_LIMIT }
    assert server.responses.all? { |packet| packet.bytesize <= PACKET_LIMIT + 4 }
    assert server.read_lengths.all? { |length| length == READ_LIMIT }
    assert_equal 2, server.max_active_handles
    assert_equal 2, server.directory_open_count
    assert_equal "a" * 300, File.binread(File.join(destination, "root1"))
    assert_equal "b" * 80, File.binread(File.join(destination, "root2"))
    assert_equal "c" * 300, File.binread(File.join(destination, "sub", "child"))
  end

  class FakeSsh
    attr_reader :channel, :logger

    def initialize(server)
      @server = server
      @logger = Logger.new(IO::NULL)
      @channel = FakeChannel.new(self, server)
    end

    def open_channel(&block)
      @confirm_channel = block
      @channel
    end

    def confirm_channel
      callback = @confirm_channel
      @confirm_channel = nil
      callback.call(@channel)
      @channel.confirm
      @channel.drain
    end

    def loop
      while !block_given? || yield
        @channel.drain
        break if @server.queue.empty?
      end
    end
  end

  class FakeChannel
    FXP = Net::SFTP::Constants::PacketTypes

    attr_reader :server

    def initialize(ssh, server)
      @ssh = ssh
      @server = server
    end

    def send_data(data)
      @server.receive(data)
    end

    def subsystem(name, &block)
      @subsystem_callback = block
    end

    def confirm
      callback = @subsystem_callback
      @subsystem_callback = nil
      callback.call(self, true) if callback
    end

    def on_data(&block)
      @on_data = block
    end

    def on_extended_data(&block)
    end

    def on_close(&block)
    end

    def on_process(&block)
      @on_process = block
    end

    def drain
      if @subsystem_callback
        callback = @subsystem_callback
        @subsystem_callback = nil
        callback.call(self, true)
      end
      @on_process.call(self)
      while (response = @server.queue.shift)
        @on_data.call(self, response)
        @on_process.call(self)
      end
    end
  end

  class FakeSftpServer
    FXP = Net::SFTP::Constants::PacketTypes

    attr_reader :queue, :packets, :write_lengths, :read_lengths, :files,
                :opened_handles, :responses
    attr_accessor :max_active_handles, :directory_open_count

    def initialize(limits:, directories: {}, files: {})
      @limits = limits
      @directories = directories
      @files = {}
      files.each { |path, data| @files[path] = StringIO.new(data) }
      @queue = []
      @packets = []
      @responses = []
      @write_lengths = []
      @read_lengths = []
      @handles = {}
      @directory_listings = {}
      @opened_handles = []
      @max_active_handles = 0
      @directory_open_count = 0
      @incoming = String.new
      @sequence = 0
    end

    def receive(data)
      @incoming << data

      while @incoming.bytesize >= 4
        length = @incoming[0, 4].unpack1("N")
        break if @incoming.bytesize < 4 + length

        wire = @incoming.slice!(0, 4 + length)
        packet = Net::SFTP::Packet.new(wire[4, length])
        record_packet(wire, packet)
        dispatch(packet)
      end
    end

    private

      def record_packet(wire, packet)
        @packets << { wire: wire, wire_length: wire.bytesize - 4, type: packet.type }
        if wire.bytesize - 4 > PACKET_LIMIT
          raise "SFTP packet #{packet.type} exceeded negotiated packet limit"
        end
      end

      def dispatch(packet)
        case packet.type
        when FXP::FXP_INIT then send_version
        when FXP::FXP_EXTENDED then send_limits(packet.read_long, packet.read_string)
        when FXP::FXP_MKDIR then send_status(packet.read_long, 0)
        when FXP::FXP_OPEN then open_file(packet)
        when FXP::FXP_OPENDIR then open_directory(packet)
        when FXP::FXP_READ then read_file(packet)
        when FXP::FXP_WRITE then write_file(packet)
        when FXP::FXP_READDIR then read_directory(packet)
        when FXP::FXP_CLOSE then close_handle(packet)
        else raise "unexpected packet #{packet.type}"
        end
      end

      def send_version
        extensions = @limits ? [["limits@openssh.com", "1"]] : []
        args = [:long, 3]
        extensions.each { |name, value| args.concat([:string, name, :string, value]) }
        enqueue(frame(FXP::FXP_VERSION, *args))
      end

      def send_limits(id, name)
        raise unless name == "limits@openssh.com"
        values = [PACKET_LIMIT, READ_LIMIT, WRITE_LIMIT, HANDLE_LIMIT]
        enqueue(frame(FXP::FXP_EXTENDED_REPLY, :long, id,
                      :raw, values.map { |value| [value].pack("Q>") }.join))
      end

      def open_file(packet)
        id = packet.read_long
        path = packet.read_string
        open_handle(id, "w", path) do
          @files[path] ||= StringIO.new
        end
      end

      def open_directory(packet)
        id = packet.read_long
        path = packet.read_string
        open_handle(id, "d", path) do |handle|
          @directory_listings[handle] = 0
          @directory_open_count += 1
        end
      end

      def open_handle(id, prefix, path)
        handle = handle_value(prefix)
        raise "too many open handles" if @handles.size >= HANDLE_LIMIT
        yield handle
        @handles[handle] = { :path => path }
        @opened_handles << handle
        @max_active_handles = [@max_active_handles, @handles.size].max
        enqueue(frame(FXP::FXP_HANDLE, :long, id, :string, handle))
      end

      def read_file(packet)
        id = packet.read_long
        handle = packet.read_string
        offset = packet.read_int64
        length = packet.read_long
        details = @handles.fetch(handle)
        @read_lengths << length

        file = @files.fetch(details[:path])
        file.pos = offset
        data = file.read(length)
        if data.nil? || data.empty?
          send_status(id, 1)
        else
          enqueue(frame(FXP::FXP_DATA, :long, id, :string, data))
        end
      end

      def write_file(packet)
        id = packet.read_long
        handle = packet.read_string
        offset = packet.read_int64
        data = packet.read_string
        details = @handles.fetch(handle)
        @write_lengths << data.bytesize
        file = @files.fetch(details[:path])
        file.pos = offset
        file.write(data)
        send_status(id, 0)
      end

      def read_directory(packet)
        id = packet.read_long
        handle = packet.read_string
        details = @handles.fetch(handle)
        position = @directory_listings[handle]
        entries = @directories.fetch(details[:path])

        if position >= entries.size
          send_status(id, 1)
        else
          name = entries[position]
          @directory_listings[handle] = position + 1
          enqueue(name_frame(id, [name]))
        end
      end

      def close_handle(packet)
        id = packet.read_long
        handle = packet.read_string
        @handles.delete(handle)
        send_status(id, 0)
      end

      def send_status(id, code)
        enqueue(frame(FXP::FXP_STATUS, :long, id, :long, code))
      end

      def name_frame(id, names)
        args = [:long, id, :long, names.size]
        names.each do |name, directory|
          args.concat([:string, name, :string, name, :raw, attributes(directory)])
        end
        frame(FXP::FXP_NAME, *args)
      end

      def attributes(directory)
        Net::SSH::Buffer.from(:long, 0x05, :int64, 0,
                              :long, directory ? 040755 : 0100644).to_s
      end

      def handle_value(prefix)
        @sequence += 1
        format("#{prefix}-%018d", @sequence)
      end

      def frame(type, *args)
        data = Net::SSH::Buffer.from(*args).to_s
        Net::SSH::Buffer.from(:long, data.length + 1, :byte, type, :raw, data).to_s
      end

      def enqueue(packet)
        raise "response exceeded packet limit" if packet.bytesize - 4 > PACKET_LIMIT
        @queue << packet
        @responses << packet
      end
  end

  def connected_sftp(server)
    ssh = FakeSsh.new(server)
    sftp = Net::SFTP::Session.new(ssh)
    ssh.confirm_channel
    sftp
  end
end
