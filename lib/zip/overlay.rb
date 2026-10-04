# frozen_string_literal: true

module Zip
  # A read-only, merged view over several zip archives ("layers"), typically
  # a base deployment package plus a series of incremental update packages.
  # The overlay lets callers read the final file tree - as if every layer had
  # been applied on top of the previous one - without extracting or
  # recompressing anything.
  #
  # Layers are ordered lowest (base) first; entries in later layers override
  # entries with the same name in earlier layers. Removals are expressed
  # through a caller-supplied manifest of "tombstone" names (the +deletes+
  # option), since zip archives themselves have no deletion record.
  #
  #   ::Zip::Overlay.open(['base.zip', 'patch-1.zip', 'patch-2.zip'],
  #                       deletes: ['obsolete.txt', 'old-assets/']) do |overlay|
  #     overlay.read('app/config.yml')      # => contents from the topmost layer
  #     overlay.dir_entries('app')          # => merged immediate children of 'app'
  #   end
  #
  # == Merge rules
  #
  # The same rules drive every lookup method (#find_entry, #read, #entries,
  # #dir_entries, #glob, ...), so listing a directory and opening the things
  # it shows always agree:
  #
  # * A file in a higher layer replaces anything at the same name in lower
  #   layers. If lower layers held a directory at that name, the directory
  #   and all of its descendants from those layers are hidden.
  # * A directory in a higher layer (an explicit directory entry, or one
  #   implied by entries beneath it) replaces a file at the same name in
  #   lower layers. Directory contents from different layers are merged.
  # * A tombstone for 'name' hides the file 'name' in lower layers; a
  #   tombstone for 'name/' (trailing slash) hides the directory 'name' and
  #   all of its descendants in lower layers. A name deleted at one layer may
  #   be re-added by a higher layer.
  # * Within a single layer, names must be unambiguous: two entries sharing
  #   a name, or a file that also appears as the parent of another entry,
  #   raise Zip::OverlayError rather than being resolved arbitrarily.
  #
  # == The deletes manifest
  #
  # +deletes+ may be:
  #
  # * an Array of names - treated as deletions belonging to a virtual layer
  #   above the topmost real layer, hiding those names in every layer; or
  # * a Hash mapping a layer boundary (Integer, 1-based up to
  #   <tt>layers.size</tt>) to an Array of names - boundary +k+ hides those
  #   names in layers below layer +k+ (0-based indexing of layers), so a
  #   deletion can be placed exactly where the corresponding incremental
  #   package sits in the stack.
  #
  # == Reading and ownership
  #
  # Entry data is read lazily from the source archives on demand; the overlay
  # never copies or recompresses entry contents. Layers may be given as file
  # paths, IO-like objects, or already-open Zip::File instances. Archives the
  # overlay opens itself (paths and IO-likes) are closed by #close; Zip::File
  # instances supplied by the caller remain the caller's responsibility and
  # are left open. Use ::Zip::Overlay.open with a block to have the overlay
  # closed automatically.
  #
  # Note that for archives the overlay opens itself, duplicate names within
  # one archive are always detected and rejected. If you pass in Zip::File
  # objects you opened yourself, open them while
  # <tt>::Zip.allow_duplicate_entry_names</tt> is true for the same
  # strictness - otherwise rubyzip has already silently collapsed duplicates
  # before the overlay can see them.
  class Overlay
    include Enumerable

    class << self
      # Like ::new, but closes the overlay (and any archives it opened) when
      # the block finishes, just as with Zip::File.open.
      def open(layers, deletes: nil)
        overlay = new(layers, deletes: deletes)
        return overlay unless block_given?

        begin
          yield overlay
        ensure
          overlay.close
        end
      end
    end

    # Builds the merged view over +layers+ (ordered base-first). See the
    # class documentation for the accepted layer and +deletes+ forms.
    def initialize(layers, deletes: nil)
      unless layers.is_a?(Array) && !layers.empty?
        raise ArgumentError,
              'layers must be a non-empty Array of paths, IO-likes, or Zip::File objects'
      end

      @deletes = normalize_manifest(deletes, layers.size)
      @owned_layers = []
      @closed = false

      begin
        @layers = layers.map { |source| coerce_layer(source) }
        build_view
      rescue StandardError
        @owned_layers.each(&:close)
        @owned_layers.clear
        raise
      end
    end

    # Closes every archive the overlay opened itself. Archives supplied by
    # the caller as Zip::File objects are left open. Idempotent.
    def close
      return if @closed

      @closed = true
      @owned_layers.each(&:close)
      @owned_layers.clear
      nil
    end

    def closed?
      @closed
    end

    # All entries visible in the merged view - files and explicit directory
    # entries, sorted by name. Directories that exist only implicitly (as the
    # parents of other entries) are not listed, matching Zip::File#entries.
    def entries
      ensure_open
      (@files.values + @dirs.values).sort_by(&:name)
    end

    def each(&block)
      entries.each(&block)
    end

    # The number of entries in the merged view (see #entries).
    def size
      ensure_open
      @files.size + @dirs.size
    end

    # Returns the winning entry for +name+ (a file or an explicit directory
    # entry), or nil if the merged view has no entry under that name.
    def find_entry(name)
      ensure_open
      key = to_key(name)
      @files[key] || @dirs[key]
    end

    # Like #find_entry, but raises Errno::ENOENT if there is no such entry.
    def get_entry(name)
      find_entry(name) || raise(Errno::ENOENT, name.to_s)
    end

    # True if a non-directory entry is visible at +name+.
    def file?(name)
      ensure_open
      @files.key?(to_key(name))
    end

    # True if a directory - explicit or implied by entries beneath it - is
    # visible at +name+. The root ('') is always a directory.
    def directory?(name)
      ensure_open
      key = to_key(name)
      key.empty? || @dir_names.key?(key)
    end

    def exist?(name)
      file?(name) || directory?(name)
    end
    alias exists? exist?

    # Returns an input stream for the entry visible at +name+, lazily reading
    # from whichever layer provides it. Behaves like Zip::File#get_input_stream.
    def get_input_stream(name, &block)
      get_entry(name).get_input_stream(&block)
    end

    # Returns the full contents of the entry visible at +name+.
    def read(name)
      get_input_stream(name, &:read)
    end

    # The sorted base names of the immediate children of the directory at
    # +path+ ('' or a directory name), including directories that exist only
    # implicitly. Raises Errno::ENOENT if +path+ is not a visible directory.
    def dir_entries(path = '')
      ensure_open
      key = to_key(path)
      unless key.empty? || @dir_names.key?(key)
        raise Errno::ENOENT, "No such directory - #{path}"
      end

      prefix = key.empty? ? '' : "#{key}/"
      children = {}
      visible_names.each do |name_key, display|
        next unless name_key.start_with?(prefix)

        rest = name_key[prefix.length..]
        next if rest.empty? || rest.include?('/')

        children[display.split('/').last] = true
      end
      children.keys.sort
    end

    # Matches +pattern+ against the names of all visible entries, as
    # Zip::EntrySet#glob does.
    def glob(pattern, flags = ::File::FNM_PATHNAME | ::File::FNM_DOTMATCH | ::File::FNM_EXTGLOB)
      entries.filter_map do |entry|
        next nil unless ::File.fnmatch(pattern, entry.name.chomp('/'), flags)

        yield(entry) if block_given?
        entry
      end
    end

    private

    def ensure_open
      raise IOError, 'closed overlay' if @closed
    end

    def coerce_layer(source)
      return source if source.is_a?(::Zip::File)

      layer = open_owned_layer(source)
      @owned_layers << layer
      layer
    end

    # Opens an archive the overlay will own, with duplicate entry names
    # preserved so that build_view can reject them instead of letting
    # rubyzip silently collapse them.
    def open_owned_layer(source)
      previous = ::Zip.allow_duplicate_entry_names
      ::Zip.allow_duplicate_entry_names = true
      begin
        if source.is_a?(String) || source.respond_to?(:to_path)
          ::Zip::File.new(source.to_s)
        elsif source.respond_to?(:read)
          ::Zip::File.new(source, buffer: true)
        else
          raise ArgumentError,
                "overlay layers must be paths, IO-likes, or Zip::File objects (got #{source.class})"
        end
      ensure
        ::Zip.allow_duplicate_entry_names = previous
      end
    end

    def normalize_manifest(deletes, layer_count)
      by_boundary = {}
      case deletes
      when nil
        # No deletions.
      when Array
        by_boundary[layer_count] = deletes
      when Hash
        deletes.each do |boundary, names|
          unless boundary.is_a?(Integer) && boundary >= 1 && boundary <= layer_count
            message = "deletes manifest keys must be layer boundaries between 1 and #{layer_count}"
            raise ArgumentError, "#{message} (got #{boundary.inspect})"
          end
          by_boundary[boundary] = names
        end
      else
        raise ArgumentError,
              'deletes must be an Array of names or a Hash of layer boundary => names'
      end

      by_boundary.transform_values do |names|
        files = []
        dirs = []
        names.each do |name|
          string = name.to_s
          if string.empty? || string.start_with?('/')
            raise ArgumentError, "invalid name in deletes manifest: #{string.inspect}"
          end

          if string.end_with?('/')
            dirs << to_key(string)
          else
            files << to_key(string)
          end
        end
        { files: files, dirs: dirs }
      end
    end

    # Scans layers from top to bottom, keeping the first (highest) entry seen
    # for each name and recording what lower layers must hide.
    def build_view
      @files = {}
      @dirs = {}
      @dir_names = {} # key => display name (explicit and implicit directories)
      hidden_files = {}
      hidden_dirs = {}

      @layers.size.downto(1) do |boundary|
        apply_deletes(@deletes[boundary], hidden_files, hidden_dirs) if @deletes.key?(boundary)
        check_layer_entries(@layers[boundary - 1], boundary - 1).each do |entry|
          key = to_key(entry.name)
          next if covered_by?(key, hidden_dirs)

          if entry.directory?
            @dirs[key] = entry unless @dirs.key?(key)
            register_dir(key, entry.name)
          else
            next if hidden_files.key?(key) || @files.key?(key) || @dir_names.key?(key)

            @files[key] = entry
            hidden_dirs[key] = true # a file hides any lower directory (and its contents) here
            register_parents(entry.name)
          end
        end
      end
    end

    def apply_deletes(manifest, hidden_files, hidden_dirs)
      manifest[:files].each { |key| hidden_files[key] = true }
      manifest[:dirs].each { |key| hidden_dirs[key] = true }
    end

    # Validates one layer's entries: duplicate names, or a file that is also
    # the parent of another entry, are rejected rather than resolved
    # arbitrarily. Returns the layer's entries.
    def check_layer_entries(layer, index)
      entries = layer.entries
      seen = {}
      file_keys = {}
      entries.each do |entry|
        key = to_key(entry.name)
        if seen.key?(key)
          raise ::Zip::OverlayError,
                "layer #{index} (#{layer_name(layer)}) has duplicate entry '#{entry.name}'"
        end
        seen[key] = true
        file_keys[key] = entry.name unless entry.directory?
      end
      file_keys.each_key do |key|
        each_ancestor(key) do |ancestor|
          next unless file_keys.key?(ancestor)

          raise ::Zip::OverlayError,
                "layer #{index} (#{layer_name(layer)}) contains both file " +
                  "'#{file_keys[ancestor]}' and entry '#{key}' beneath it"
        end
      end
      entries
    end

    def layer_name(layer)
      layer.name.is_a?(String) ? layer.name : layer.name.inspect
    end

    def register_dir(key, display_name)
      @dir_names[key] = display_name.sub(%r{/+\z}, '')
      register_parents(display_name)
    end

    def register_parents(name)
      each_ancestor(name.sub(%r{/+\z}, '')) do |ancestor|
        @dir_names[to_key(ancestor)] = ancestor
      end
    end

    def each_ancestor(key)
      pos = key.index('/')
      while pos
        yield key[0...pos]
        pos = key.index('/', pos + 1)
      end
    end

    def covered_by?(key, dir_set)
      return true if dir_set.key?(key)

      each_ancestor(key) { |ancestor| return true if dir_set.key?(ancestor) }
      false
    end

    def visible_names
      names = {}
      @dir_names.each { |key, display| names[key] = display }
      @files.each { |key, entry| names[key] = entry.name }
      names
    end

    def to_key(name)
      key = name.to_s.sub(%r{/+\z}, '')
      ::Zip.case_insensitive_match ? key.downcase : key
    end
  end
end
