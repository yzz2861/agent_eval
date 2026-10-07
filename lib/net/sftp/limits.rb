require 'net/ssh/buffer'

module Net; module SFTP

  # Represents the transfer limits negotiated with the server via the
  # +limits@openssh.com+ extension (see the OpenSSH SFTP protocol notes for
  # the extension's wire format). When a server advertises this extension
  # in its FXP_VERSION reply, its values are used to bound the size of
  # individual read/write requests and the number of concurrently open
  # file and directory handles.
  #
  # The byte limits advertised by the server apply to the size of complete
  # SFTP messages, so this class subtracts the fixed packet encoding
  # overhead (and, for write requests, the handle bytes) before reporting a
  # payload length. Simply using the advertised value as the payload size
  # would produce a packet that exceeds the limit and gets the connection
  # dropped by strict servers.
  class Limits
    # The name of the extension as it appears in the FXP_VERSION extensions.
    EXTENSION_NAME = "limits@openssh.com"

    # The only extension version understood by this client.
    EXTENSION_VERSION = 1

    # Local fallbacks used either when no +limits@openssh.com+ extension was
    # negotiated, or when the server reports zero for a field. Zero means
    # "no server limit", not zero capacity, so a documented local upper
    # bound is substituted instead.
    DEFAULT_MAX_READ_BYTES   = 32_000
    DEFAULT_MAX_WRITE_BYTES  = 32_000
    DEFAULT_MAX_OPEN_HANDLES = 256

    # SFTP message encoding overhead for a FXP_DATA reply carrying a payload:
    # the type byte, the request id, and the string length prefix.
    READ_PACKET_OVERHEAD = 1 + 4 + 4

    # Fixed SFTP message encoding overhead for a FXP_WRITE request, in
    # addition to the handle string (type byte, request id, offset, and the
    # data string length prefix).
    WRITE_PACKET_OVERHEAD = 1 + 4 + 4 + 8 + 4

    # The maximum payload size the server allows in a FXP_DATA reply.
    attr_reader :max_read_bytes

    # The maximum FXP_WRITE message size the server is willing to accept.
    attr_reader :max_write_bytes

    # The maximum number of concurrently open file and directory handles
    # the server allows.
    attr_reader :max_open_handles

    # Parses the raw extension +data+ advertised in FXP_VERSION. The blob is
    # four integers: a uint32 extension version followed by uint64 values
    # for the read, write, and open-handle limits. Returns a new Limits
    # instance, or nil when the blob is missing or cannot be understood.
    def self.parse(data)
      return nil if data.nil?

      buffer = Net::SSH::Buffer.from(:raw, data.to_s)
      version = buffer.read_long
      max_read_bytes = buffer.read_int64
      max_write_bytes = buffer.read_int64
      max_open_handles = buffer.read_int64
      return nil unless version == EXTENSION_VERSION &&
                        max_read_bytes && max_write_bytes && max_open_handles

      new(max_read_bytes, max_write_bytes, max_open_handles)
    end

    # Creates a new Limits instance with the given negotiated values. A zero
    # value for any field is replaced by the corresponding documented local
    # upper bound rather than being treated as zero capacity.
    def initialize(max_read_bytes, max_write_bytes, max_open_handles)
      @max_read_bytes   = positive_or_default(max_read_bytes,   DEFAULT_MAX_READ_BYTES)
      @max_write_bytes  = positive_or_default(max_write_bytes,  DEFAULT_MAX_WRITE_BYTES)
      @max_open_handles = positive_or_default(max_open_handles, DEFAULT_MAX_OPEN_HANDLES)
    end

    # Returns the number of payload bytes that may be requested from the
    # server in a single FXP_READ. The handle is not part of a FXP_DATA
    # reply, so the read payload only needs to leave room for the fixed
    # reply encoding overhead; +wanted+ is capped at that amount. The result
    # is never less than one byte.
    def read_length(wanted, handle=nil)
      cap = [max_read_bytes - READ_PACKET_OVERHEAD, 1].max
      [wanted, cap].min
    end

    # Returns the number of payload bytes that may be written in a single
    # FXP_WRITE message. The server limit covers the complete message, so
    # the handle bytes (whose length is only known after the server hands
    # the handle back) and all other packet encoding overhead are subtracted
    # before capping +wanted+. The result is never less than one byte.
    def write_length(wanted, handle)
      overhead = WRITE_PACKET_OVERHEAD + handle.to_s.bytesize
      cap = [max_write_bytes - overhead, 1].max
      [wanted, cap].min
    end

    private

      # Replaces zero (or any non-positive value) with the given local
      # default upper bound.
      def positive_or_default(value, default)
        value.to_i > 0 ? value.to_i : default
      end
  end

end; end
