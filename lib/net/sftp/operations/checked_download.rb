require 'net/ssh/loggable'
require 'digest'
require 'net/sftp/errors'

module Net; module SFTP; module Operations

  # A block-level synchronizing downloader, built on top of the "check-file"
  # SFTP extension (see Net::SFTP::Session#check_file). It is intended for
  # the case where the caller already has a local copy of the remote file
  # and wants to avoid re-downloading the parts that have not changed.
  #
  # The operation works like this:
  #
  # 1. The server is asked to hash the remote file, one digest per
  #    fixed-size block (the server chooses the hash algorithm from the
  #    list offered by the client).
  # 2. Each remote digest is compared against a locally computed digest of
  #    the same byte range of the local file.
  # 3. Only the blocks that differ are downloaded and patched into the
  #    local file.
  # 4. Finally, a single whole-content digest is requested from the server
  #    and compared against the patched local file.
  #
  # The final step is what makes the result trustworthy: the server does
  # not provide any snapshot isolation, so the remote file may be modified
  # while the synchronization is running, and matching file attributes
  # before and after do not prove otherwise. If the final digests differ,
  # the result is reported as :retry (never :ok), and the caller may
  # simply run the operation again.
  #
  #   result = sftp.download_checked("/remote/path", "/local/path")
  #   if result.ok?
  #     puts "in sync (#{result.downloaded_blocks} blocks fetched)"
  #   else
  #     puts "file changed underneath us (#{result.reason}); try again"
  #   end
  #
  # This class is used via Net::SFTP::Session#download_checked.
  class CheckedDownload
    include Net::SSH::Loggable

    # The name of the SFTP extension this operation relies on.
    CHECK_FILE_EXTENSION = "check-file".freeze

    # The default size of the blocks that are hashed and compared.
    DEFAULT_BLOCK_SIZE = 256 * 1024

    # The hash algorithms the client can compute locally, in the order they
    # are offered to the server. If the server selects anything that is not
    # in this list, the operation aborts with an exception rather than
    # silently substituting a different algorithm.
    SUPPORTED_ALGORITHMS = {
      "sha256" => Digest::SHA256,
      "sha384" => Digest::SHA384,
      "sha512" => Digest::SHA512,
      "sha1"   => Digest::SHA1,
      "md5"    => Digest::MD5
    }.freeze

    # The outcome of a CheckedDownload run.
    #
    # * +status+ is :ok when the local file provably matches the remote
    #   content, or :retry when either side changed while the
    #   synchronization was in progress.
    # * +reason+ qualifies a :retry status, and is either :remote_changed
    #   or :local_changed (nil when the status is :ok).
    # * +algorithm+ is the name of the hash algorithm the server selected.
    # * +block_size+ is the block size that was used for the comparison.
    # * +block_count+ is the number of blocks the remote content was
    #   divided into.
    # * +downloaded_blocks+ is the number of blocks that actually had to be
    #   fetched, and +downloaded_bytes+ their total size.
    Result = Struct.new(:status, :reason, :algorithm, :block_size, :block_count, :downloaded_blocks, :downloaded_bytes) do
      # True when the local file provably matches the remote content.
      def ok?
        status == :ok
      end

      # True when the content changed during the synchronization and the
      # operation should be retried.
      def retry?
        status == :retry
      end
    end

    # The SFTP session driving this operation.
    attr_reader :sftp

    # The path of the file on the remote server.
    attr_reader :remote

    # The path of the existing local file.
    attr_reader :local

    # The options hash given when the operation was created.
    attr_reader :options

    def initialize(sftp, remote, local, options={}) #:nodoc:
      @sftp    = sftp
      @remote  = remote
      @local   = local
      @options = options

      self.logger = sftp.logger
    end

    # The offset of the first byte to synchronize.
    def start_offset
      options[:start] || 0
    end

    # The number of bytes to synchronize; zero means "to end of file".
    def range_length
      options[:length] || 0
    end

    # The block size used for the per-block comparison.
    def block_size
      options[:block_size] || DEFAULT_BLOCK_SIZE
    end

    # Runs the synchronization to completion and returns a Result. This
    # method blocks (it drives the SSH event loop internally).
    def run
      ensure_check_file_supported!
      ensure_local_file_usable!

      @remote_size       = sftp.stat!(remote).size
      @local_size_seen   = ::File.size(local)
      @downloaded_blocks = 0
      @downloaded_bytes  = 0

      handle = sftp.open!(remote, "r")
      begin
        failure = synchronize_blocks(handle)
        failure || verify_final_result(handle)
      ensure
        sftp.close!(handle)
      end
    end

    private

      # The hash algorithm names to offer the server.
      def offered_algorithms
        Array(options[:algorithms] || SUPPORTED_ALGORITHMS.keys)
      end

      # True when the requested range covers the entire file.
      def whole_file_range?
        start_offset.zero? && range_length.zero?
      end

      # The number of bytes in the range being synchronized.
      def effective_range_length
        length = range_length.zero? ? @remote_size - start_offset : range_length
        if length < 0
          raise ArgumentError, "start offset #{start_offset} is beyond the end of #{remote} (#{@remote_size} bytes)"
        end
        length
      end

      # The extension is not optional: without it there is no way to compare
      # block digests, so fail explicitly.
      def ensure_check_file_supported!
        unless sftp.extensions.key?(CHECK_FILE_EXTENSION)
          raise Net::SFTP::Exception, "cannot synchronize #{remote}: the server does not support the #{CHECK_FILE_EXTENSION} extension"
        end
      end

      # The local file is patched in place, so it must exist and be writable.
      def ensure_local_file_usable!
        raise ArgumentError, "local file does not exist: #{local}" unless ::File.file?(local)
        raise ArgumentError, "local file is read-only: #{local}" unless ::File.writable?(local)
      end

      # Compares the block digests and downloads the blocks that differ.
      # Returns nil on success, or a :retry Result if the remote file is
      # detected to have changed underneath us.
      def synchronize_blocks(handle)
        check = sftp.check_file!(handle, offered_algorithms, start_offset, range_length, block_size)
        digest_class = digest_class_for(check[:algorithm])
        @algorithm = check[:algorithm]

        blocks = block_layout(effective_range_length)
        @block_count = blocks.length
        verify_hash_layout!(check, blocks, digest_class)

        differing = differing_blocks(blocks, check[:hashes], digest_class)
        failure = fetch_differing_blocks(handle, blocks, differing, check[:hashes], digest_class)
        return failure if failure

        ::File.truncate(local, @remote_size) if whole_file_range? && ::File.size(local) != @remote_size
        nil
      end

      # The final, authoritative verification: asks the server for a single
      # digest of the synchronized range and compares it against the local
      # file. Anything else (matching sizes, matching mtimes) would not
      # prove the remote file stood still while we were reading it.
      def verify_final_result(handle)
        expected_local_size = whole_file_range? ? @remote_size : @local_size_seen
        if ::File.size(local) != expected_local_size
          debug { "local file #{local} changed length during synchronization" }
          return result(:retry, :local_changed)
        end

        check = sftp.check_file!(handle, [@algorithm], start_offset, range_length, 0)
        digest_class = digest_class_for(check[:algorithm])
        unless check[:hashes].length == 1
          raise Net::SFTP::Exception, "check-file returned #{check[:hashes].length} hash(es) for the whole-content verification of #{remote}; expected exactly 1"
        end

        if local_digest(digest_class) == check[:hashes].first
          result(:ok)
        else
          debug { "final check-file digest mismatch for #{remote}; the remote file changed during synchronization" }
          result(:retry, :remote_changed)
        end
      end

      # Maps a server-selected algorithm name to a Digest class. An unknown
      # algorithm is a hard error; it must never be replaced by an
      # arbitrary client-side choice.
      def digest_class_for(algorithm)
        SUPPORTED_ALGORITHMS.fetch(algorithm) do
          raise Net::SFTP::Exception, "server selected unsupported check-file hash algorithm #{algorithm.inspect}; refusing to substitute another"
        end
      end

      # Computes the [offset, length] pairs of the blocks covering a region
      # of the given length. The last block gets the remainder and may be
      # shorter than the others.
      def block_layout(length)
        return [] if length.zero?
        return [[start_offset, length]] if block_size.zero?

        blocks = []
        offset = start_offset
        remaining = length
        while remaining > 0
          size = [block_size, remaining].min
          blocks << [offset, size]
          offset += size
          remaining -= size
        end
        blocks
      end

      # Strictly validates the server's reply against the requested layout:
      # the number of digests must match the number of blocks exactly, and
      # every digest must have the exact byte length of the selected
      # algorithm's output.
      def verify_hash_layout!(check, blocks, digest_class)
        unless check[:hashes].length == blocks.length
          raise Net::SFTP::Exception, "check-file returned #{check[:hashes].length} hash(es) for #{remote}, but #{blocks.length} block(s) of #{block_size} byte(s) were requested"
        end

        digest_length = digest_class.new.digest_length
        check[:hashes].each_with_index do |hash, index|
          unless hash.bytesize == digest_length
            raise Net::SFTP::Exception, "check-file hash ##{index} for #{remote} is #{hash.bytesize} byte(s); #{check[:algorithm]} digests must be #{digest_length} bytes"
          end
        end
      end

      # Returns the indices of the blocks whose local content does not match
      # the server's digests. Blocks that reach beyond the end of the local
      # file always differ.
      def differing_blocks(blocks, remote_hashes, digest_class)
        differing = []
        ::File.open(local, "rb") do |io|
          blocks.each_with_index do |(offset, length), index|
            io.seek(offset, IO::SEEK_SET)
            data = io.read(length)
            local_hash = data && data.bytesize == length ? digest_class.digest(data) : nil
            differing << index unless local_hash == remote_hashes[index]
          end
        end
        differing
      end

      # Downloads each differing block and patches it into the local file.
      # Every block must arrive with exactly the requested length (including
      # the final, possibly shorter, block) and must hash to the digest the
      # server reported; otherwise the remote file has changed underneath
      # us and a :retry Result is returned.
      def fetch_differing_blocks(handle, blocks, differing, remote_hashes, digest_class)
        ::File.open(local, "r+b") do |io|
          differing.each do |index|
            offset, length = blocks[index]
            data = sftp.read!(handle, offset, length)

            if data.nil? || data.bytesize != length
              debug { "block #{index} of #{remote} read short (#{data ? data.bytesize : 'eof'} of #{length} bytes); the remote file changed during synchronization" }
              return result(:retry, :remote_changed)
            end

            unless digest_class.digest(data) == remote_hashes[index]
              debug { "block #{index} of #{remote} no longer matches its check-file digest; the remote file changed during synchronization" }
              return result(:retry, :remote_changed)
            end

            io.seek(offset, IO::SEEK_SET)
            io.write(data)
            @downloaded_blocks += 1
            @downloaded_bytes += length
          end
        end
        nil
      end

      # Computes the digest of the synchronized range of the local file.
      def local_digest(digest_class)
        digest = digest_class.new
        remaining = effective_range_length
        ::File.open(local, "rb") do |io|
          io.seek(start_offset, IO::SEEK_SET)
          while remaining > 0
            chunk = io.read([remaining, 64 * 1024].min)
            break unless chunk
            digest.update(chunk)
            remaining -= chunk.bytesize
          end
        end
        digest.digest
      end

      # Builds the Result object describing the outcome.
      def result(status, reason=nil)
        Result.new(status, reason, @algorithm, block_size, @block_count, @downloaded_blocks, @downloaded_bytes)
      end
  end

end; end; end

