# frozen_string_literal: true

module Net; module SFTP; module Operations

  # A reverse-lookup manifest written alongside a recursively downloaded
  # directory tree. Each record preserves the original remote entry name
  # as raw bytes (hex encoded in the file, so invalid UTF-8 is retained
  # exactly instead of being replaced with a substitution character) and
  # pairs it with the mapped local relative path.
  #
  # File format (line oriented):
  #
  #   # net-sftp name map v1
  #   # strategy: escape
  #   <local-relative-path>\t<hex-remote-full-path>\t<hex-remote-name>\t<kind>
  #
  # <kind> is "d" for directories and "f" for files. The columns are joined
  # with tabs, which are control bytes and therefore forbidden from mapped
  # names. Remote values are always hex encoded, byte for byte.
  class NameManifest

    FORMAT_VERSION = 1

    Record = Struct.new(:local_path, :remote_path, :remote_name, :kind)

    # The local destination directory the manifest is written into.
    attr_reader :local_root

    # The NameMapper in effect for the download.
    attr_reader :mapper

    def initialize(mapper, local_root)
      @mapper = mapper
      @local_root = local_root
      @records = []
    end

    # Records one downloaded entry. +local_path+ is the mapped path relative
    # to the destination root (UTF-8). +remote_path+ and +remote_name+ are
    # the original remote full path and entry name, as raw ASCII-8BIT bytes.
    # +kind+ is :directory or :file.
    def add(local_path, remote_path, remote_name, kind)
      @records << Record.new(
        String(local_path),
        as_bytes(remote_path),
        as_bytes(remote_name),
        kind == :directory ? "d" : "f"
      )
    end

    # Records as [local_path, remote_path_bytes, remote_name_bytes, kind].
    def records
      @records.dup
    end

    # Renders the manifest as text (UTF-8 with hex-encoded remote values).
    def to_s
      lines = [
        "# net-sftp name map v#{FORMAT_VERSION}",
        "# strategy: #{mapper.strategy}"
      ]
      @records.each do |record|
        lines << [
          record.local_path,
          hex(record.remote_path),
          hex(record.remote_name),
          record.kind
        ].join("\t")
      end
      lines.join("\n") + "\n"
    end

    # Writes the manifest into the destination root under the configured
    # manifest basename. Returns the full local path of the manifest.
    def write!
      raise ArgumentError, "manifest is disabled" unless mapper.manifest_name
      path = ::File.join(local_root, mapper.manifest_name)
      ::File.open(path, "wb") { |io| io.write(to_s) }
      path
    end

    # Parses a manifest previously produced by #write!. Returns an array of
    # Record instances with remote_path and remote_name as ASCII-8BIT
    # strings holding the exact original bytes.
    def self.read(io_or_path)
      text = io_or_path.respond_to?(:read) ? io_or_path.read : ::File.read(io_or_path, mode: "rb")
      records = []
      text.each_line do |line|
        line = line.chomp("\n")
        next if line.empty? || line.start_with?("#")
        local_path, remote_hex, name_hex, kind = line.split("\t", 4)
        records << Record.new(
          local_path,
          from_hex(remote_hex),
          from_hex(name_hex),
          kind
        )
      end
      records
    end

    # Convenience lookup: given a destination directory and a local relative
    # path, returns the original remote entry name as raw bytes, or nil.
    def self.original_name(local_root, local_relative, manifest_name = NameMapper::DEFAULT_MANIFEST_NAME)
      path = ::File.join(local_root, manifest_name)
      return nil unless ::File.file?(path)
      target = String(local_relative).dup.force_encoding(Encoding::UTF_8)
      read(path).each do |record|
        return record.remote_name if record.local_path == target
      end
      nil
    end

    private

      def as_bytes(value)
        String(value).dup.force_encoding(Encoding::ASCII_8BIT)
      end

      def hex(bytes)
        bytes.each_byte.map { |byte| "%02X" % byte }.join
      end

      def self.from_hex(hex)
        raise ArgumentError, "malformed hex in manifest" unless hex && hex =~ /\A(?:[0-9A-Fa-f]{2})*\z/
        [hex].pack("H*").force_encoding(Encoding::ASCII_8BIT)
      end

  end

end; end; end
