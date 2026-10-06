# frozen_string_literal: true

require 'monitor'
require_relative 'log_device'

class Logger
  # Writes complete log messages using RFC 6587 octet counting framing.
  class SyslogDevice < LogDevice
    def initialize(io, reraise_write_errors: [])
      unless io.respond_to?(:write) && io.respond_to?(:close)
        raise TypeError, "can't convert #{io.class} into IO"
      end
      @dev = io
      @filename = nil
      @shift_age = nil
      @shift_size = nil
      @shift_period_suffix = nil
      @reraise_write_errors = reraise_write_errors
      mon_initialize
    end

    def write(message)
      handle_write_errors("writing") do
        synchronize do
          framed = "#{message.bytesize} ".b
          framed << message.b
          write_all(framed)
        end
      end
    end

    def reopen(io = nil, **)
      if io
        synchronize do
          @dev = io
        end
      end
      self
    end

    private

    def write_all(message)
      offset = 0
      while offset < message.bytesize
        written = @dev.write(message.byteslice(offset, message.bytesize - offset))
        unless written.is_a?(Integer) && written > 0
          raise IOError, "log device wrote #{written.inspect} bytes"
        end
        offset += written
      end
      message.bytesize
    end
  end

  TcpDevice = SyslogDevice
end
