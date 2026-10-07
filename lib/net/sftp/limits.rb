module Net; module SFTP

  # Represents the negotiated limits from the limits@openssh.com SFTP
  # extension. Each limit describes a complete SFTP message where possible,
  # rather than only the file data payload.
  class Limits
    EXTENSION_NAME = "limits@openssh.com"

    # The conservative local limits used when the server advertises the
    # extension but reports zero for an individual limit. Zero is treated
    # as an unspecified limit, never as zero capacity. Servers without the
    # extension remain uncapped here, preserving their original behavior.
    DEFAULT_PACKET_LENGTH = 32_768
    DEFAULT_READ_LENGTH   = 32_000
    DEFAULT_WRITE_LENGTH  = 32_000
    DEFAULT_OPEN_HANDLES  = 16

    # FXP_DATA contains: packet type, request id, string length, and data.
    READ_DATA_OVERHEAD = 1 + 4 + 4

    # FXP_WRITE contains: packet type, request id, handle string, offset,
    # data length, and data. The handle string's bytes are added separately.
    WRITE_PACKET_OVERHEAD = 1 + 4 + 4 + 8 + 4

    attr_reader :packet_length, :read_length, :write_length, :open_handles

    def self.default
      new(nil, nil, nil, nil)
    end

    def self.from_buffer(buffer)
      values = 4.times.map { buffer.read_int64 }
      new(*values)
    end

    def initialize(packet_length, read_length, write_length, open_handles)
      @packet_length = normalize(packet_length, DEFAULT_PACKET_LENGTH)
      @read_length   = normalize(read_length, DEFAULT_READ_LENGTH)
      @write_length  = normalize(write_length, DEFAULT_WRITE_LENGTH)
      @open_handles  = normalize(open_handles, DEFAULT_OPEN_HANDLES)
    end

    def maximum_read_length(desired = nil)
      limits = [read_length, packet_length && packet_length - READ_DATA_OVERHEAD]
      [desired || DEFAULT_READ_LENGTH, *limits].compact.min
    end

    def maximum_write_length(handle, desired = nil)
      overhead = WRITE_PACKET_OVERHEAD + handle.to_s.bytesize
      limits = [write_length, packet_length && packet_length - overhead]
      [desired || DEFAULT_WRITE_LENGTH, *limits].compact.min
    end

    def maximum_open_handles(desired = nil)
      [desired || DEFAULT_OPEN_HANDLES, open_handles].compact.min
    end

    private

      def normalize(value, default)
        return nil if value.nil?
        value > 0 ? value : default
      end
  end

end; end
