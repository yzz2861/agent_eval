# frozen_string_literal: false
require 'drb/drb'
require 'socket'

# An in-process dRuby protocol for tests, using UNIX socket pairs
# instead of TCP sockets.  This exercises the full DRbMessage
# marshalling path without needing to bind real sockets, which some
# sandboxes forbid.
#
# URIs look like "drbloop://name".  A client may append a path (for
# example "drbloop://name/client-b"); the path is ignored when
# locating the listener but is kept as the connection's URI, so the
# client-side connection pool treats such clients as distinct
# connections, like two local clients would be.
module DRbLoopback
  @listeners = {}
  @listeners_mutex = Thread::Mutex.new

  class << self
    def register(listener)
      @listeners_mutex.synchronize { @listeners[listener.uri] = listener }
    end

    def unregister(listener)
      @listeners_mutex.synchronize { @listeners.delete(listener.uri) }
    end

    def listener_for(uri)
      key = uri[%r{\Adrbloop://[^/]*}]
      @listeners_mutex.synchronize { @listeners[key] }
    end
  end

  # A single connection, used on both the client and the server side.
  class Connection
    def initialize(uri, socket, config)
      @uri = uri
      @socket = socket
      @msg = DRb::DRbMessage.new(config)
    end

    attr_reader :uri

    def stream
      @socket
    end

    def send_request(ref, msg_id, arg, block)
      @msg.send_request(@socket, ref, msg_id, arg, block)
    end

    def recv_reply
      @msg.recv_reply(@socket)
    end

    def recv_request
      @msg.recv_request(@socket)
    end

    def send_reply(succ, result)
      @msg.send_reply(@socket, succ, result)
    end

    def close
      return unless @socket
      @socket.close
      @socket = nil
    end

    def alive?
      return false unless @socket
      if @socket.wait_readable(0)
        close
        return false
      end
      true
    end
  end

  # The server-side endpoint returned by Protocol.open_server.
  class Listener
    def initialize(uri, config)
      @uri = uri[%r{\Adrbloop://[^/]*}]
      @config = config
      @queue = Thread::Queue.new
      @closed = false
      DRbLoopback.register(self)
    end

    attr_reader :uri

    # Called by the client side of the protocol to open a connection
    # to this listener.  Returns the client side of the connection.
    def connect(client_uri)
      raise DRb::DRbConnError, 'listener is closed' if @closed
      client_side, server_side = Socket.pair(:UNIX, :STREAM, 0)
      @queue.push([server_side, client_uri])
      Connection.new(client_uri, client_side, @config)
    end

    def accept
      accepted = @queue.pop
      return nil unless accepted
      socket, client_uri = accepted
      Connection.new(client_uri, socket, @config)
    end

    def shutdown
      @closed = true
      @queue.push(nil)
    end

    def close
      shutdown
      DRbLoopback.unregister(self)
    end
  end

  module Protocol
    def self.open(uri, config)
      raise DRb::DRbBadScheme, 'not a drbloop uri' unless uri.start_with?('drbloop://')
      listener = DRbLoopback.listener_for(uri)
      raise DRb::DRbConnError, "no listener for #{uri}" unless listener
      listener.connect(uri)
    end

    def self.open_server(uri, config)
      raise DRb::DRbBadScheme, 'not a drbloop uri' unless uri.start_with?('drbloop://')
      DRbLoopback::Listener.new(uri, config)
    end

    def self.uri_option(uri, config)
      [uri, nil]
    end
  end
end

DRb::DRbProtocol.add_protocol(DRbLoopback::Protocol)
