# frozen_string_literal: false
#
# Bidirectional DRb sessions.
#
# In a restricted network the DRb client may be able to open an outgoing
# connection while the server cannot connect back to objects the client
# exports.  When both sides explicitly enable bidirectional sessions the
# original connection is upgraded to a multiplexed session: requests may
# travel in either direction over the very same socket and replies always
# travel back over it as well.
#
# The wire of a bidirectional session is distinct from the classic DRb
# message stream.  The client announces itself with a handshake, and every
# frame afterwards carries the frame kind (request or reply), the side that
# originated it and a session-wide request id.  References marshalled inside
# the frames carry the URI of their owning session, so calls on them are
# routed back over the same connection.

module DRb

  # Frame kinds.
  DRB_BIDI_FRAME_REQUEST = ?R.getbyte(0)
  DRB_BIDI_FRAME_REPLY = ?r.getbyte(0)

  # Originating sides.
  DRB_BIDI_SIDE_CLIENT = ?C.getbyte(0)
  DRB_BIDI_SIDE_SERVER = ?S.getbyte(0)

  # Registry of the active bidirectional sessions, keyed by the URI under
  # which the *remote* end of the session is known locally.
  module DRbBidiProtocol
    BIDI_SCHEME = 'drbvbidi:'

    HANDSHAKE_MAGIC = "\xE7dRBBIDI".b
    HANDSHAKE_VERSION = 1

    # Status codes returned by the server during the handshake.
    HANDSHAKE_OK = 1
    HANDSHAKE_UNSUPPORTED = 2
    HANDSHAKE_BAD_VERSION = 3

    @mutex = Thread::Mutex.new
    @sessions = {}
    @connect_mutex = Thread::Mutex.new

    def self.scheme?(uri)
      uri.start_with?(BIDI_SCHEME)
    end

    def self.register(session, keys = session.registry_keys)
      @mutex.synchronize do
        keys.each { |key| @sessions[key] = session }
      end
    end

    def self.unregister(session, keys = session.registry_keys)
      @mutex.synchronize do
        keys.each { |key| @sessions.delete(key) }
      end
    end

    def self.lookup(uri)
      @mutex.synchronize do
        @sessions[uri]
      end
    end

    # Snapshot of the currently registered sessions, keyed by remote URI.
    def self.sessions
      @mutex.synchronize { @sessions.dup }
    end

    # Sessions this process initiated (client side of a connection).
    def self.client_sessions
      @mutex.synchronize do
        @sessions.each_with_object({}) do |(key, session), hash|
          hash[key] = session if session.side == DRB_BIDI_SIDE_CLIENT
        end
      end
    end

    def self.session_uri(token)
      "#{BIDI_SCHEME}#{token}"
    end

    def self.new_token
      bytes = Random.respond_to?(:urandom) ? Random.urandom(4) : (0...4).map { rand(256) }.pack('C4')
      bytes
    end

    def self.token_uri(token)
      session_uri(token.unpack1('H8'))
    end

    # Open a connection routed over a bidirectional session.  Session URIs
    # resolve to an already established session; classic +druby+:// URIs
    # establish a new connection and upgrade it with a handshake.
    def self.open(uri, config)
      unless config[:bidi] || scheme?(uri)
        raise DRbBadScheme, uri
      end

      existing = lookup(uri)
      return existing if existing && existing.alive?

      # Serialize establishing sessions to the same endpoint so concurrent
      # first calls multiplex over one connection instead of each opening
      # their own.
      @connect_mutex.synchronize do
        existing = lookup(uri)
        return existing if existing && existing.alive?
        open_new_session(uri, config)
      end
    end

    def self.open_new_session(uri, config)
      raise DRbConnError, "bidirectional session not found: #{uri}" if scheme?(uri)

      host, port, = DRbTCPSocket.send(:parse_uri, uri)
      socket = TCPSocket.open(host, port)
      protocol = begin
        DRbTCPSocket.new(uri, socket, config)
      rescue
        socket.close
        raise
      end
      begin
        start_bidi_client(protocol, config, uri)
      rescue Exception
        protocol.close
        raise
      end
    end

    # Finish establishing the client side of a bidirectional session on an
    # already connected +transport+ (opened via DRbTCPSocket.open).
    def self.start_bidi_client(transport, config, remote_front_uri = transport.uri)
      server = DRb.current_server rescue nil
      unless server && server.config[:bidi]
        raise DRbConnError,
              'bidirectional sessions require a local DRb server started with bidi: true'
      end

      client_token = new_token
      client_uri = token_uri(client_token)
      hello = HANDSHAKE_MAGIC + [HANDSHAKE_VERSION].pack('C') + client_token
      transport.stream.write(hello)

      reply = transport.stream.read(HANDSHAKE_MAGIC.bytesize + 1 + 1 + 4)
      if reply.nil? || reply.bytesize < HANDSHAKE_MAGIC.bytesize + 6
        raise DRbConnError, 'connection closed during bidirectional handshake'
      end
      magic = reply.byteslice(0, HANDSHAKE_MAGIC.bytesize)
      unless magic == HANDSHAKE_MAGIC
        raise DRbConnError, 'invalid bidirectional handshake reply'
      end
      status = reply.getbyte(HANDSHAKE_MAGIC.bytesize + 1)
      server_token = reply.byteslice(-4, 4)
      case status
      when HANDSHAKE_UNSUPPORTED
        raise DRbConnError, 'remote endpoint does not support bidirectional sessions'
      when HANDSHAKE_BAD_VERSION
        raise DRbConnError, 'remote endpoint rejected bidirectional protocol version'
      when HANDSHAKE_OK
        # continue
      else
        raise DRbConnError, 'remote endpoint rejected bidirectional handshake'
      end

      server_uri = token_uri(server_token)
      # The client reaches server objects (including the front object) via
      # the same classic URI; the extra registry key reuses this session.
      session = DRbBidiSocket.new(transport, client_uri, server_uri,
                                 DRB_BIDI_SIDE_CLIENT, server, [remote_front_uri])
      session.start
    end

    # Open the passive transport used by a process that only serves the
    # client side of outgoing bidirectional sessions.  The transport never
    # listens itself; sessions are attached as outgoing connections are
    # established.
    def self.open_server(uri, config)
      unless uri.nil? || uri == BIDI_SCHEME || uri.start_with?(BIDI_SCHEME)
        raise DRbBadScheme, uri
      end
      DRbBidiListener.new(uri || BIDI_SCHEME, config)
    end

    def self.uri_option(uri, config)
      unless uri == BIDI_SCHEME || uri.start_with?(BIDI_SCHEME)
        raise DRbBadScheme, uri
      end
      [uri, nil]
    end
  end

  # Passive transport for a process whose DRb server only owns client sides
  # of bidirectional sessions.  It parks in #accept until the server is
  # stopped.
  class DRbBidiListener
    def initialize(uri, config)
      @uri = uri
      @config = config
      @shutdown_r, @shutdown_w = IO.pipe
    end

    attr_reader :uri

    def accept
      IO.select([@shutdown_r])
      nil
    end

    def alive?
      !@shutdown_r.closed?
    end

    def shutdown
      @shutdown_w.close unless @shutdown_w.closed?
    end

    def close
      shutdown
      [@shutdown_r, @shutdown_w].each { |io| io.close unless io.closed? }
    end
  end

  # StringIO returns "" at EOF for length-bounded reads while DRbMessage
  # relies on socket semantics (#read returns nil at EOF).  This wrapper
  # provides socket-style reads over an in-memory frame payload.
  class DRbBidiPayloadIO
    def initialize(payload)
      @io = StringIO.new(payload)
    end

    def read(bytes=nil)
      data = bytes.nil? ? @io.read : @io.read(bytes)
      return nil if data.nil?
      data.empty? ? nil : data
    end
  end

  # A multiplexed bidirectional session sitting on top of an established
  # transport (normally a DRbTCPSocket).
  #
  # A single reader thread consumes frames so that application threads never
  # race for the socket.  Replies are delivered to the thread waiting for
  # the corresponding request id; requests are dispatched to the owning
  # DRbServer, which may in turn issue further requests over this same
  # session while waiting for a reply.
  class DRbBidiSocket
    include MonitorMixin

    # +transport+ is the underlying protocol object.  +local_uri+ and
    # +remote_uri+ identify the two ends of the session.  +side+ is the side
    # this object represents (DRB_BIDI_SIDE_CLIENT or DRB_BIDI_SIDE_SERVER).
    def initialize(transport, local_uri, remote_uri, side, server, extra_keys=[])
      super()
      @transport = transport
      @local_uri = local_uri
      @remote_uri = remote_uri
      @extra_keys = extra_keys
      @side = side
      @server = server
      @msg = DRbMessage.new(server ? server.config : transport.config)
      @write_mutex = Thread::Mutex.new
      @pending = {}
      @request_seq = 0
      @closed = false
      @reader = nil
    end

    # The URI under which this session is known when opening it through
    # DRbConn.  That is always the *remote* end's URI.
    def uri
      @remote_uri
    end

    # The URI of the end represented by this object.  Objects local to this
    # end are exported under this URI.
    attr_reader :local_uri

    attr_reader :side

    # All keys under which the session is reachable in the session registry.
    def registry_keys
      [@remote_uri, *@extra_keys]
    end

    def config
      transport.config
    end

    # Full configuration of the owning server (includes limits).
    def server_config
      @server ? @server.config : transport.config
    end

    def peeraddr
      transport.peeraddr
    end

    def bidi?
      true
    end

    def shared?
      true
    end

    def alive?
      synchronize do
        return false if @closed
      end
      !transport.stream.closed?
    rescue IOError, Errno::ECONNRESET, Errno::EPIPE, IO::WaitReadable
      false
    end

    # Start the reader thread and attach the session to its owning server.
    def start
      DRbBidiProtocol.register(self)
      @reader = Thread.start do
        @server.grp.add(Thread.current) if @server
        begin
          reader_loop
        rescue Exception
          # the loop closes the session on any failure
        end
      end
      @reader.abort_on_exception = false
      @server.drbbidi_attach(self) if @server
      self
    end

    # Send a request on behalf of an application thread and wait for the
    # matching reply.  Incoming callback requests are processed by other
    # threads while this thread waits.
    def send_message(ref, msg_id, arg, block)
      id = synchronize do
        @request_seq += 1
      end
      queue = Queue.new
      synchronize do
        @pending[id] = queue
      end
      stream = StringIO.new
      payload = with_call_context do
        @msg.send_request(stream, ref, msg_id, arg, block)
        stream.string
      end
      write_frame(DRB_BIDI_FRAME_REQUEST, @side, id, payload)
      succ, result = queue.pop
      [succ, result]
    end

    # Deliver an incoming reply to the thread waiting for +id+.
    def deliver_reply(id, succ, result)
      queue = synchronize { @pending.delete(id) }
      queue << [succ, result] if queue
    end

    # Dispatch an incoming request on the owning server.
    def dispatch_request(id, payload)
      @server.drbbidi_dispatch(self, id, payload)
    end

    # Send the reply to request +id+.  Called from the server's worker
    # thread.
    def send_reply_frame(id, succ, result)
      stream = StringIO.new
      with_call_context do
        @msg.send_reply(stream, succ, result)
      end
      write_frame(DRB_BIDI_FRAME_REPLY, @side, id, stream.string)
    end

    def close
      close_transport = false
      pending = nil
      synchronize do
        return if @closed
        @closed = true
        pending = @pending
        @pending = {}
        close_transport = true
      end

      pending.each_value do |queue|
        error = DRbConnError.new('connection closed')
        error.set_backtrace(caller)
        queue << [false, error]
      end

      DRbBidiProtocol.unregister(self)
      @server.drbbidi_detach(self) if @server
      transport.close if close_transport
    end

    private

    attr_reader :transport

    def with_call_context
      drb = Thread.current['DRb']
      context = if drb
                  drb.dup
                else
                  {}
                end
      context['client'] = self
      context['server'] = @server if @server && !context['server']
      save = Thread.current['DRb']
      Thread.current['DRb'] = context
      begin
        yield
      ensure
        Thread.current['DRb'] = save
      end
    end

    def reader_loop
      loop do
        kind, from, id, payload = read_frame
        if kind.nil?
          close
          break
        end
        unless from != @side
          close
          break
        end

        case kind
        when DRB_BIDI_FRAME_REPLY
          begin
            io = DRbBidiPayloadIO.new(payload)
            succ = @msg.load(io)
            result = @msg.load(io)
            deliver_reply(id, succ, result)
          rescue
            close
            break
          end
        when DRB_BIDI_FRAME_REQUEST
          dispatch_request(id, payload)
        else
          close
          break
        end
      end
    rescue Exception
      close
    end

    def read_frame
      header = read_exact(10)
      return nil if header.nil?
      kind, from, id, size = header.unpack('CCNN')
      payload = read_exact(size)
      return nil if payload.nil?
      [kind, from, id, payload]
    end

    def read_exact(bytes)
      io = transport.stream
      data = String.new
      while data.bytesize < bytes
        chunk = io.read(bytes - data.bytesize)
        return nil if chunk.nil?
        data << chunk
      end
      data
    end

    def write_frame(kind, side, id, payload)
      @write_mutex.synchronize do
        data = [kind, side, id, payload.bytesize].pack('CCNN') + payload.b
        transport.stream.write(data)
      end
    rescue
      close
      raise DRbConnError, $!.message, $!.backtrace
    end
  end
end

module DRb
  class DRbTCPSocket
    # Server side of the bidirectional handshake.  Peeks at the first
    # byte to decide whether this connection speaks the classic DRb
    # message stream or the bidirectional protocol without consuming
    # any classic data.
    #
    # Returns a started DRbBidiSocket when upgraded, or nil for a
    # classic connection.  Bidirectional sessions must be enabled on
    # both sides; a bidi client talking to a classic-only server is
    # rejected during the handshake rather than failing later.
    def bidi_upgrade(server)
      first = begin
        @socket.recv(1, Socket::MSG_PEEK)
      rescue IOError, Errno::ECONNRESET, Errno::ENOTCONN
        nil
      end
      return nil if first.nil? || first.empty?
      return nil unless first.getbyte(0) == DRbBidiProtocol::HANDSHAKE_MAGIC.getbyte(0)

      hello = bidi_read_exact(13)
      if hello.nil? || hello.bytesize < 13
        raise DRbConnError, 'connection closed during bidirectional handshake'
      end
      magic = hello.byteslice(0, DRbBidiProtocol::HANDSHAKE_MAGIC.bytesize)
      version = hello.getbyte(DRbBidiProtocol::HANDSHAKE_MAGIC.bytesize)
      client_token = hello.byteslice(-4, 4)

      if magic != DRbBidiProtocol::HANDSHAKE_MAGIC
        raise DRbConnError, 'invalid bidirectional handshake'
      end

      unless @config[:bidi]
        # A bidirectional client reached a classic-only endpoint: reject
        # explicitly during the handshake instead of leaving the client
        # to misparse the classic message stream.
        reply = DRbBidiProtocol::HANDSHAKE_MAGIC +
                [DRbBidiProtocol::HANDSHAKE_VERSION].pack('C') +
                [DRbBidiProtocol::HANDSHAKE_UNSUPPORTED].pack('C') +
                "\x00\x00\x00\x00".b
        @socket.write(reply)
        close
        return nil
      end

      status = version == DRbBidiProtocol::HANDSHAKE_VERSION ?
               DRbBidiProtocol::HANDSHAKE_OK :
               DRbBidiProtocol::HANDSHAKE_BAD_VERSION

      server_token = DRbBidiProtocol.new_token
      reply = DRbBidiProtocol::HANDSHAKE_MAGIC +
              [DRbBidiProtocol::HANDSHAKE_VERSION].pack('C') +
              [status].pack('C') + server_token
      @socket.write(reply)

      unless status == DRbBidiProtocol::HANDSHAKE_OK
        close
        return nil
      end

      client_uri = DRbBidiProtocol.token_uri(client_token)
      server_uri = DRbBidiProtocol.token_uri(server_token)
      session = DRbBidiSocket.new(self, server_uri, client_uri,
                                 DRB_BIDI_SIDE_SERVER, server)
      session.start
    end

    private

    def bidi_read_exact(bytes)
      data = String.new
      while data.bytesize < bytes
        chunk = @socket.read(bytes - data.bytesize)
        return nil if chunk.nil?
        data << chunk
      end
      data
    end
  end
end
