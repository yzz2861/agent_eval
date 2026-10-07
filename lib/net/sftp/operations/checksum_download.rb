require 'digest'

module Net; module SFTP; module Operations

  # Updates a local file with a server that supports the check-file SFTP
  # extension. Block checksums are compared before reading data, and the
  # completed local file is checked against one final whole-file checksum.
  #
  # check-file requests do not provide snapshot isolation. Matching stat data
  # therefore cannot prove that the remote file remained unchanged; only the
  # final checksum can decide whether the completed result is valid.
  class ChecksumDownload
    include Net::SSH::Loggable

    EXTENSION = "check-file"
    DEFAULT_ALGORITHMS = %w(sha512 sha384 sha256 sha1 md5).freeze
    DEFAULT_BLOCK_SIZE = 0

    STATUSES = {
      :success => 0,
      :retry => 1,
      :read_only => 2,
      :extension_unavailable => 3,
      :local_length_changed => 4,
      :unsupported_algorithm => 5,
      :invalid_checksum_response => 6
    }.freeze

    attr_reader :sftp, :remote, :local, :options, :status, :reason
    attr_reader :algorithm, :block_size, :read_ranges

    def initialize(sftp, local, remote, options={}, &progress)
      @sftp = sftp
      @local = local
      @remote = remote
      @options = options
      @progress = progress || options[:progress]
      @read_ranges = []
      @status = nil
      @reason = nil
      @handle = nil
      @remote_size = nil
      @local_io = nil
      @initial_local_size = nil
      @expected_local_size = nil
      @requested_block_size = nil
      @pending_status = nil
      self.logger = sftp.logger

      finish(:extension_unavailable) unless sftp.extensions.key?(EXTENSION)
      return unless active?

      begin
        open_local
        ensure_local_writable!
        @initial_local_size = local_size
        request = sftp.open(remote, "r", &method(:on_initial_open))
        request[:phase] = :open
      rescue Errno::EACCES, Errno::EROFS, IOError
        finish(:read_only)
      end
    end

    def on_initial_open(response)
      return fail_status(response) unless response.ok?
      @handle = response[:handle]
      request = sftp.stat(remote, &method(:on_initial_stat))
      request[:phase] = :initial
    end

    def active?
      status.nil?
    end

    def wait
      sftp.loop { active? }
      self
    end

    def ok?
      status == :success
    end

    def retry?
      status == :retry
    end

    def code
      STATUSES[status]
    end

    private

    Block = Struct.new(:offset, :length, :checksum, :index)

    def algorithms
      Array(options[:algorithms] || DEFAULT_ALGORITHMS).join(",")
    end

    def preferred_block_size
      options[:block_size] || DEFAULT_BLOCK_SIZE
    end

    def open_local
      @local_io = local.respond_to?(:read) ? local : ::File.open(local, "r+b")
    end

    def ensure_local_writable!
      unless @local_io.respond_to?(:write) &&
             (@local_io.respond_to?(:truncate) || @local_io.respond_to?(:stat))
        raise IOError, "destination is read-only"
      end
    end

    def local_size
      if @local_io.respond_to?(:stat)
        @local_io.stat.size
      elsif @local_io.respond_to?(:size)
        @local_io.size
      else
        @local_io.seek(0, IO::SEEK_END)
        @local_io.pos
      end
    end

    def on_initial_stat(response)
      return fail_status(response) unless response.ok?
      @remote_size = response[:attrs].size
      request_checksums(@remote_size, preferred_block_size, :on_initial_checksums)
    end

    def request_checksums(length, requested_block_size, callback)
      @requested_block_size = requested_block_size
      request = sftp.check_file(remote, algorithms, 0, length, requested_block_size, &method(callback))
      request[:length] = length
      request[:offset] = 0
      request[:block_size] = requested_block_size
      request
    end

    def on_initial_checksums(response)
      return fail_status(response) unless response.ok?
      blocks = parse_blocks(response)
      return finish(:local_length_changed) unless local_size == @initial_local_size
      return unless resize_local_to_remote
      return request_final_checksums if blocks.empty?
      differing = differing_blocks(blocks)
      differing.empty? ? request_final_checksums : read_blocks(differing, 0)
    rescue UnsupportedChecksumAlgorithm
      finish(:unsupported_algorithm)
    rescue ChecksumProtocolError
      finish(:invalid_checksum_response)
    end

    def parse_blocks(response, expected_length=response.request[:length])
      algorithm = response[:algorithm].to_s.downcase
      raise UnsupportedChecksumAlgorithm unless digest_class(algorithm)

      offset = response[:offset]
      end_offset = response[:end_offset]
      server_block_size = response[:block_size]
      checksums = response[:checksums]

      expected_offset = response.request[:offset]
      raise ChecksumProtocolError unless offset == expected_offset
      raise ChecksumProtocolError unless end_offset == expected_offset + expected_length
      raise ChecksumProtocolError unless server_block_size >= 0
      raise ChecksumProtocolError if expected_length > 0 && server_block_size == 0
      raise ChecksumProtocolError unless checksums.is_a?(Array)
      raise ChecksumProtocolError unless checksums.all?(String)

      count = checksums.length
      range_length = end_offset - offset
      expected_count = range_length.zero? ? 0 : (range_length + server_block_size - 1) / server_block_size
      raise ChecksumProtocolError unless count == expected_count

      if range_length.zero?
        last_length = 0
      elsif count == 1
        last_length = end_offset - offset
      else
        last_length = (end_offset - offset) - ((count - 1) * server_block_size)
      end
      raise ChecksumProtocolError unless expected_length.zero? || (last_length > 0 && last_length <= server_block_size)

      @algorithm = algorithm
      @block_size = server_block_size
      checksums.each_with_index.map do |checksum, index|
        block_offset = expected_offset + (index * server_block_size)
        block_length = index == count - 1 ? last_length : server_block_size
        decoded = decode_checksum(checksum, algorithm)
        raise ChecksumProtocolError unless decoded.is_a?(String) && decoded.bytesize == digest_length(algorithm)
        Block.new(block_offset, block_length, decoded, index)
      end
    end

    def digest_class(algorithm)
      case algorithm
      when "md5" then Digest::MD5
      when "sha1" then Digest::SHA1
      when "sha256" then Digest::SHA256
      when "sha384" then Digest::SHA384
      when "sha512" then Digest::SHA512
      end
    end

    def digest_length(algorithm)
      { "md5" => 16, "sha1" => 20, "sha256" => 32, "sha384" => 48, "sha512" => 64 }.fetch(algorithm)
    end

    def decode_checksum(value, algorithm)
      binary = if value.respond_to?(:bytesize) && value.bytesize == digest_length(algorithm)
        value.b
      elsif value.respond_to?(:match?) && value.match?(/\A[0-9a-fA-F]{#{digest_length(algorithm) * 2}}\z/)
        [value].pack("H*").b
      end
      binary
    end

    def differing_blocks(blocks)
      blocks.select do |block|
        return finish(:local_length_changed) unless local_size == @expected_local_size
        next true if block.offset >= @initial_local_size || block.offset + block.length > @initial_local_size
        local_digest(block) != block.checksum
      end
    end

    def resize_local_to_remote
      current_size = local_size
      return finish(:local_length_changed) unless current_size == @initial_local_size
      if current_size != @remote_size
        return finish(:read_only) unless @local_io.respond_to?(:truncate)
        @local_io.truncate(@remote_size)
      end
      @expected_local_size = @remote_size
      true
    end

    def local_digest(block)
      @local_io.seek(block.offset)
      data = @local_io.read(block.length)
      return nil unless data && data.bytesize == block.length
      digest_class(algorithm).digest(data)
    end

    def read_blocks(blocks, index)
      block = blocks[index]
      request = sftp.read(@handle, block.offset, block.length, &method(:on_block_read))
      request[:blocks] = blocks
      request[:index] = index
      request[:block] = block
    end

    def on_block_read(response)
      blocks = response.request[:blocks]
      index = response.request[:index]
      block = response.request[:block]
      return fail_status(response) unless response.ok?

      data = response[:data]
      return finish(:retry, :short_read) unless data.bytesize == block.length
      return finish(:local_length_changed) unless local_size == @expected_local_size

      @local_io.seek(block.offset)
      @local_io.write(String.new(data))
      @read_ranges << [block.offset, block.length]
      update_progress(:get, block.offset, data)

      next_index = index + 1
      if next_index < blocks.length
        read_blocks(blocks, next_index)
      else
        prepare_local_size
      end
    end

    def prepare_local_size
      return finish(:local_length_changed) unless local_size == @expected_local_size
      request = sftp.stat(remote, &method(:on_after_transfer_stat))
      request[:phase] = :after_transfer
    end

    def on_after_transfer_stat(response)
      return fail_status(response) unless response.ok?
      return finish(:retry, :stat_changed) unless response[:attrs].size == @remote_size
      request_final_checksums
    end

    def request_final_checksums
      request_checksums(@remote_size, block_size || 0, :on_final_checksums)
    end

    def on_final_checksums(response)
      return fail_status(response) unless response.ok?
      blocks = parse_blocks(response)
      return finish(:local_length_changed) unless local_size == @remote_size
      blocks.each do |block|
        return finish(:retry, :final_checksum_mismatch) unless local_digest(block) == block.checksum
      end

      request = sftp.stat(remote, &method(:on_final_stat))
      request[:phase] = :final
    rescue UnsupportedChecksumAlgorithm
      finish(:unsupported_algorithm)
    rescue ChecksumProtocolError
      finish(:retry, :invalid_checksum_response)
    end

    def on_final_stat(response)
      return fail_status(response) unless response.ok?
      return finish(:retry, :stat_changed) unless response[:attrs].size == @remote_size
      finish(:success)
    end

    def fail_status(response)
      if response.code == Net::SFTP::Constants::StatusCodes::FX_OP_UNSUPPORTED
        finish(:extension_unavailable)
      else
        finish(:retry, "status_#{response.code}")
      end
    end

    def finish(status, reason=nil)
      if @handle
        @pending_status = [status, reason || status]
        handle = @handle
        @handle = nil
        sftp.close(handle, &method(:on_remote_closed))
        return
      end

      finalize(status, reason || status)
    end

    def on_remote_closed(response)
      status, reason = @pending_status
      @pending_status = nil
      return finalize(status, reason) if response.ok?
      return finalize(status, reason) unless status == :success
      fail_status(response)
    end

    def finalize(status, reason)
      @status = status
      @reason = reason || status
      close_local
      update_progress(:finish, status, reason)
    end

    def close_local
      return unless @local_io && !local.respond_to?(:read)
      @local_io.close unless @local_io.closed?
    end

    def update_progress(event, *args)
      return unless @progress
      if @progress.respond_to?("on_#{event}")
        @progress.public_send("on_#{event}", self, *args)
      elsif @progress.respond_to?(:call)
        @progress.call(event, self, *args)
      end
    end
  end

end; end; end
