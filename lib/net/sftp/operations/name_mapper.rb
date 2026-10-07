require 'json'
require 'net/sftp/errors'

begin
  require 'unicode_normalize'
rescue LoadError
  # unicode_normalize is a default gem on supported Rubies; if it is not
  # available the default equivalence falls back to byte identity.
end

module Net; module SFTP; module Operations

  # Raised when a set of remote file names cannot be mapped to unique,
  # safe local file names with the chosen strategy.
  class NameMappingError < Net::SFTP::Exception; end

  # Maps remote file names (raw byte strings, kept exactly as the server
  # sent them) to safe local file names for recursive downloads.
  #
  # Names that coexist on the remote system may not be able to coexist on
  # the local file system: case folding, Unicode normalization, or
  # platform-specific reserved names can make distinct remote names collide
  # locally. This mapper makes the mapping explicit instead of relying on
  # whatever the local file system happens to do.
  #
  # Two strategies are supported (option +:strategy+):
  #
  # * +:reject+ - any remote name that is not already a safe, unique local
  #   name raises a NameMappingError. Nothing is written for that directory
  #   level, so existing local files are never clobbered by a failed
  #   download.
  # * +:escape+ - unsafe names are reversibly percent-escaped (each unsafe
  #   byte becomes %XX, and a literal percent becomes %25). Invalid UTF-8
  #   is preserved byte-for-byte instead of being silently replaced by a
  #   replacement character. If escaping introduces secondary collisions,
  #   the colliding names are fully escaped until the level is unique; if
  #   that is still not enough, a NameMappingError is raised.
  #
  # The equivalence of two local names is decided by an injectable
  # function (option +:equivalence+) so behavior can be matched to the
  # target file system (case-insensitive, NFD-normalizing, ...) instead of
  # to the host the check happens to run on. The default equivalence
  # NFC-normalizes and case-folds valid UTF-8 names, and treats invalid
  # UTF-8 names as opaque byte strings.
  #
  # For every mapped directory a manifest can be produced (see
  # #manifest_content and #write_manifest) that records, for every local
  # name, the exact original remote bytes, so the mapping can be reversed
  # later. The manifest's own file name takes part in the collision check
  # of its directory level.
  class NameMapper
    # The default file name of the per-directory mapping manifest.
    DEFAULT_MANIFEST_NAME = ".sftp-download-manifest.json".freeze

    # Device names reserved on Windows (matched case-insensitively on the
    # base name, before any extension).
    RESERVED_BASENAMES = %w[
      CON PRN AUX NUL
      COM1 COM2 COM3 COM4 COM5 COM6 COM7 COM8 COM9
      LPT1 LPT2 LPT3 LPT4 LPT5 LPT6 LPT7 LPT8 LPT9
    ].freeze

    # Bytes that may appear literally in a mapped local name. Everything
    # else (including "%" itself and any non-ASCII byte) is escaped by the
    # +:escape+ strategy.
    SAFE_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~'()@+,;=[]{}$&#^ ".freeze

    SAFE_BYTES = begin
      table = Array.new(256, false)
      SAFE_CHARACTERS.each_byte { |byte| table[byte] = true }
      table.freeze
    end

    # The default name-equivalence function. Valid UTF-8 names are
    # NFC-normalized and case-folded; names that are not valid UTF-8 keep
    # their raw bytes as their identity.
    DEFAULT_EQUIVALENCE = lambda do |name|
      utf8 = name.to_s.dup.force_encoding(Encoding::UTF_8)
      if utf8.valid_encoding? && utf8.respond_to?(:unicode_normalize)
        utf8.unicode_normalize(:nfc).downcase
      elsif utf8.valid_encoding?
        utf8.downcase
      else
        name.to_s.dup.force_encoding(Encoding::BINARY)
      end
    end

    # The mapping strategy, +:reject+ or +:escape+.
    attr_reader :strategy

    # The file name used for the per-directory manifest, or nil if no
    # manifest should be written.
    attr_reader :manifest_name

    # The name-equivalence function in effect.
    attr_reader :equivalence

    # Options:
    #
    # * <tt>:strategy</tt> - +:reject+ (default) or +:escape+.
    # * <tt>:equivalence</tt> - a callable mapping a local candidate name
    #   to a canonical key; two names colliding on the key are considered
    #   "the same name" for the simulated file system.
    # * <tt>:manifest</tt> - the file name for the per-directory manifest
    #   (defaults to DEFAULT_MANIFEST_NAME); +false+ or +nil+ disables the
    #   manifest.
    def initialize(options={})
      @strategy = (options[:strategy] || :reject).to_sym
      unless [:reject, :escape].include?(@strategy)
        raise ArgumentError, "unknown name mapping strategy: #{@strategy.inspect}"
      end

      @equivalence = options[:equivalence] || DEFAULT_EQUIVALENCE
      unless @equivalence.respond_to?(:call)
        raise ArgumentError, ":equivalence must be callable"
      end

      @manifest_name = options.key?(:manifest) ? options[:manifest] : DEFAULT_MANIFEST_NAME
      if @manifest_name
        @manifest_name = @manifest_name.to_s
        problems = validation_problems(@manifest_name)
        unless problems.empty?
          raise ArgumentError, "invalid manifest name #{@manifest_name.inspect}: #{problems.join(', ')}"
        end
      end
    end

    # Maps an array of remote names (the entries of a single remote
    # directory) to local names. Returns a Hash mapping each remote name
    # (as a binary String) to its local name. Raises NameMappingError if
    # the level cannot be mapped safely; in that case nothing may be
    # written for the level.
    def map(remote_names)
      names = remote_names.map { |name| name.to_s.dup.force_encoding(Encoding::BINARY) }

      seen = {}
      names.each do |name|
        if seen[name]
          raise NameMappingError, "duplicate remote name #{name.inspect} in directory level"
        end
        seen[name] = true
      end

      candidates = {}
      names.each { |name| candidates[name] = candidate_for(name) }

      resolve_collisions(candidates)
      candidates
    end

    # Returns the canonical equivalence key for a (local) candidate name.
    def equivalence_key(name)
      @equivalence.call(name.to_s.dup.force_encoding(Encoding::BINARY))
    end

    # Returns a list of symbols describing why +name+ is not a safe local
    # file name; an empty list means the name is safe.
    def validation_problems(name)
      name = name.to_s
      problems = []
      problems << :empty if name.empty?
      problems << :separator if name.include?("/") || name.include?("\\")
      problems << :dot_segment if name == "." || name == ".."
      problems << :control_character if name.each_byte.any? { |byte| byte < 0x20 || byte == 0x7f }
      problems << :trailing_dot_or_space if name.end_with?(".") || name.end_with?(" ")
      base = name.split(".", 2).first || name
      problems << :reserved_name if RESERVED_BASENAMES.include?(base.upcase)
      problems
    end

    # Percent-escapes every byte of +name+ that is not in SAFE_CHARACTERS
    # (a literal "%" is escaped as %25). Reversible via NameMapper.unescape.
    def escape_unsafe(name)
      name.to_s.each_byte.map { |byte| SAFE_BYTES[byte] ? byte.chr : ("%%%02X" % byte) }.join
    end

    # Percent-escapes every byte of +name+. Reversible via
    # NameMapper.unescape.
    def escape_full(name)
      name.to_s.each_byte.map { |byte| "%%%02X" % byte }.join
    end

    # Reverses escape_unsafe/escape_full, restoring the original bytes.
    def self.unescape(name)
      name.to_s.dup.force_encoding(Encoding::BINARY).gsub(/%([0-9A-Fa-f]{2})/) { [$1].pack("H2") }
    end

    # Returns the JSON manifest content for a directory level, recording
    # for every local name the exact original remote bytes (hex encoded),
    # so the original name can always be looked up.
    def manifest_content(mapping)
      entries = mapping.sort_by { |remote, _local| remote }.map do |remote, local|
        entry = {
          "local_hex" => local.unpack1("H*"),
          "remote_hex" => remote.unpack1("H*")
        }
        utf8 = local.dup.force_encoding(Encoding::UTF_8)
        entry["local"] = utf8 if utf8.valid_encoding?
        entry
      end
      JSON.pretty_generate(
        "version" => 1,
        "strategy" => strategy.to_s,
        "entries" => entries
      ) + "\n"
    end

    # Parses manifest content produced by #manifest_content and returns a
    # Hash mapping local names (binary Strings) to the original remote
    # names (binary Strings).
    def self.parse_manifest(content)
      data = JSON.parse(content)
      result = {}
      (data["entries"] || []).each do |entry|
        result[[entry["local_hex"]].pack("H*")] = [entry["remote_hex"]].pack("H*")
      end
      result
    end

    # Writes the manifest for +mapping+ into the local +directory+.
    # Returns the path written, or nil if manifests are disabled.
    def write_manifest(directory, mapping)
      return nil unless manifest_name
      path = ::File.join(directory, manifest_name)
      ::File.open(path, "wb") { |io| io.write(manifest_content(mapping)) }
      path
    end

    private

      # Computes the initial local candidate for a remote name according
      # to the strategy.
      def candidate_for(name)
        if strategy == :reject
          problems = validation_problems(name)
          unless problems.empty?
            raise NameMappingError, "remote name #{name.inspect} is not a safe local name (#{problems.join(', ')})"
          end
          name
        else
          if validation_problems(name).empty? && charset_safe?(name)
            name
          else
            escaped = escape_unsafe(name)
            if validation_problems(escaped).empty?
              escaped
            else
              escape_full(name)
            end
          end
        end
      end

      # True if every byte of +name+ is in the safe literal set (which
      # excludes "%", so escaped and literal namespaces never overlap).
      def charset_safe?(name)
        name.each_byte.all? { |byte| SAFE_BYTES[byte] }
      end

      # Ensures all candidates (plus the manifest's own name, which
      # reserves a slot in the same directory level) are unique under the
      # equivalence function. In +:escape+ mode, conflicts are resolved by
      # fully escaping all but the deterministically-first name of each
      # conflicting group; the check repeats until the level is unique or
      # proves unresolvable.
      def resolve_collisions(candidates)
        reserved_keys = {}
        reserved_keys[equivalence_key(manifest_name)] = manifest_name if manifest_name

        loop do
          groups = Hash.new { |hash, key| hash[key] = [] }
          candidates.each do |remote, local|
            groups[equivalence_key(local)] << remote
          end

          conflicts = groups.select do |key, remotes|
            remotes.length > 1 || (reserved_keys.key?(key) && remotes.any?)
          end
          return candidates if conflicts.empty?

          if strategy == :reject
            key, remotes = conflicts.first
            offender = reserved_keys.key?(key) ? reserved_keys[key] : nil
            names = remotes.sort.map { |remote| candidates[remote] }
            message = "remote names map to conflicting local names #{names.inspect}"
            message << " (also reserved by #{offender.inspect})" if offender
            raise NameMappingError, message
          end

          conflicts.each do |key, remotes|
            sorted = remotes.sort
            # When the conflict is with the manifest's reserved slot, no
            # remote name may keep its candidate.
            keep = reserved_keys.key?(key) ? [] : [sorted.first]
            (sorted - keep).each do |remote|
              escaped = escape_full(remote)
              if candidates[remote] == escaped
                raise NameMappingError,
                  "cannot resolve local name collision for #{remote.inspect} with the given equivalence function"
              end
              candidates[remote] = escaped
            end
          end
        end
      end
  end

end; end; end
