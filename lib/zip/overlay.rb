# frozen_string_literal: true

require 'pathname'
require_relative 'errors'
require_relative 'ioextras'
require_relative 'null_decompressor'
require_relative 'null_input_stream'

module Zip
  # A read-only union of ordered zip archives. Later layers override earlier
  # layers. Tombstone paths remove entries from the accumulated tree; deleting a
  # directory path also removes all of the directory's visible descendants.
  class Overlay
    include Enumerable

    Node = Struct.new(:name, :path, :entry, :children, keyword_init: true) do
      def directory?
        entry.nil? || entry.directory?
      end
    end

    Layer = Struct.new(:archive, :owned, keyword_init: true) do
      def close
        archive.close if owned && !archive.closed?
      end
    end

    private_constant :Node, :Layer

    # Opens layers from lowest to highest. A layer may be a path or Zip::File,
    # or a two-element array/hash containing an archive and its tombstones.
    # Archives opened by this method are closed by the overlay. Archives passed
    # as Zip::File instances remain owned by the caller.
    def self.open(*layers, tombstones: nil, manifest: nil)
      overlay = new(*layers, tombstones: tombstones || manifest)
      return overlay unless block_given?

      begin
        yield overlay
      ensure
        overlay.close
      end
    end

    def initialize(*layers, tombstones: nil, manifest: nil)
      @root = Node.new(name: '', path: '', entry: nil, children: {})
      @case_insensitive = Zip.case_insensitive_match
      @sources = {}
      @closed = false
      @layers = []

      begin
        layers.each { |layer| @layers << add_layer(layer) }
        apply_tombstones(tombstones || manifest)
      rescue StandardError
        close
        raise
      end
    end

    # Returns the entry at +path+. A directory inferred solely from descendant
    # paths is represented by a synthesized directory entry.
    def find_entry(path)
      ensure_open!
      node = node_for(path)
      return nil if node.nil? || node.equal?(@root)

      entry_for(node)
    end

    # Returns the entry at +path+ or raises Errno::ENOENT.
    def get_entry(path)
      find_entry(path) || raise(Errno::ENOENT, path)
    end

    def include?(path)
      ensure_open!
      !node_for(path).nil?
    end

    alias member? include?
    alias exist? include?
    alias exists? include?

    # Opens a file from the layer that currently owns it. Directory entries
    # behave like Zip::File and return Zip::NullInputStream.
    def get_input_stream(path_or_entry, &block)
      ensure_open!
      _node, entry = resolve_entry(path_or_entry)
      return open_directory_entry(&block) if entry.directory?

      source_for(entry).get_input_stream(entry, &block)
    end

    # Reads a file without extracting or rebuilding any layer.
    def read(path_or_entry)
      get_input_stream(path_or_entry, &:read)
    end

    # Returns true for explicit or inferred directory paths, including root.
    def directory?(path)
      ensure_open!
      node_for(path)&.directory? == true
    end

    # Returns true for a visible non-directory path.
    def file?(path)
      entry = find_entry(path)
      !entry.nil? && !entry.directory?
    end

    # Returns the immediate child names of +path+, from root by default.
    def children(path = '')
      ensure_open!
      node = require_directory_node(path)
      names = sorted_children(node).map { |_key, child| child.name }
      return names unless block_given?

      names.each { |name| yield name }
    end

    alias list children
    alias foreach children

    # With no argument, returns every final-tree entry. With a path, returns
    # the immediate child entries of that directory.
    def entries(path = nil)
      return to_a if path.nil?

      ensure_open!
      require_directory_node(path).children.sort_by(&:first).map do |_key, child|
        entry_for(child)
      end
    end

    # Yields every final-tree entry in sorted path order.
    def each(&block)
      return to_enum(:each) unless block_given?

      ensure_open!
      walk(@root, &block)
      self
    end

    def size
      to_a.size
    end

    alias length size

    def glob(pattern,
             flags = ::File::FNM_PATHNAME | ::File::FNM_DOTMATCH |
                     ::File::FNM_EXTGLOB,
             &block)
      ensure_open!
      select_entries do |entry|
        next false unless ::File.fnmatch(pattern, entry.name.chomp('/'), flags)

        yield(entry) if block
        true
      end
    end

    # Closes archives opened by this overlay. Caller-provided archives remain
    # open.
    def close
      return if @closed

      @layers.reverse_each(&:close)
      @sources.clear
      @closed = true
    end

    def closed?
      @closed
    end

    private

    def add_layer(layer)
      archive = nil
      owned = false
      archive_spec, layer_tombstones = normalize_layer(layer)
      archive, owned = open_archive(archive_spec)

      validate_layer(archive)
      apply_tombstones(layer_tombstones)
      entries = archive.entries
      entries.select(&:directory?).each { |entry| apply_entry(entry, archive) }
      entries.reject(&:directory?).each { |entry| apply_entry(entry, archive) }
      Layer.new(archive: archive, owned: owned)
    rescue StandardError
      archive.close if owned && archive.respond_to?(:closed?) && !archive.closed?
      raise
    end

    def normalize_layer(layer)
      case layer
      when Array
        unless layer.size == 2
          raise ArgumentError, 'a layer pair must contain an archive and tombstones'
        end

        [layer.first, layer.last]
      when Hash
        archive = layer.fetch(:archive) { layer.fetch('archive') }
        tombstones = layer.fetch(:tombstones, layer.fetch('tombstones', []))
        [archive, tombstones]
      else
        [layer, []]
      end
    end

    def open_archive(spec)
      spec = spec.to_path if spec.respond_to?(:to_path)
      return [spec, false] if spec.kind_of?(::Zip::File)
      return [::Zip::File.new(spec), true] if spec.kind_of?(::String)

      raise ArgumentError, "unsupported overlay archive: #{spec.inspect}"
    end

    def validate_layer(archive)
      groups = Hash.new { |hash, key| hash[key] = [] }

      read_raw_entries(archive).each do |entry|
        segments, label = normalize_path(entry.name, directory: entry.directory?)
        key = segments.map { |segment| key_for(segment) }.join('/')
        groups[key] << { label: label, directory: entry.directory? }
      end

      groups.each do |key, items|
        if items.size > 1
          raise OverlayConflictError.new(
            items.first[:label], 'duplicate path in one overlay layer'
          )
        end

        next if items.first[:directory]
        next unless groups.keys.any? { |other_key| other_key.start_with?("#{key}/") }

        raise OverlayConflictError.new(
          items.first[:label], 'path conflicts with a descendant in one overlay layer'
        )
      end
    end

    def read_raw_entries(archive)
      cdir = CentralDirectory.new
      source = archive.name
      source_path = source.respond_to?(:to_path) ? source.to_path : source

      if source_path.kind_of?(::String) && ::File.file?(source_path)
        ::File.open(source_path, 'rb') do |io|
          cdir.read_from_stream(io, preserve_duplicate_names: true)
        end
      elsif source.respond_to?(:seek)
        position = source.tell
        begin
          cdir.read_from_stream(source, preserve_duplicate_names: true)
        ensure
          source.seek(position)
        end
      else
        return archive.entries
      end

      cdir.entries
    end

    def apply_tombstones(tombstones)
      normalize_tombstones(tombstones).each do |segments, _label, _directory|
        remove_path(segments)
        prune_implicit_directories(@root)
      end
    end

    def normalize_tombstones(tombstones)
      return [] if tombstones.nil?
      tombstones = tombstones.tombstones if tombstones.respond_to?(:tombstones)

      Array(tombstones).map do |tombstone|
        path = tombstone.respond_to?(:to_path) ? tombstone.to_path : tombstone.to_s
        normalize_path(path)
      end
    end

    def normalize_path(path, directory: nil)
      path = path.to_path if path.respond_to?(:to_path)
      path = path.to_s.tr('\\', '/')
      trailing_slash = path.end_with?('/')
      directory = trailing_slash if directory.nil?

      clean_path = Pathname.new(path).cleanpath.to_s
      segments = clean_path.split('/').reject(&:empty?)
      unless valid_segments?(clean_path, segments)
        raise ArgumentError, "invalid overlay path: #{path.inspect}"
      end

      label = segments.join('/')
      label += '/' if directory
      [segments, label, trailing_slash]
    end

    def valid_segments?(clean_path, segments)
      !segments.empty? && !clean_path.start_with?('/') &&
        !segments.include?('..') && segments.none? { |segment| segment == '.' }
    end

    def apply_entry(entry, archive)
      segments, = normalize_path(entry.name, directory: entry.directory?)
      node = @root

      segments.each_with_index do |segment, index|
        key = key_for(segment)
        child = node.children[key]
        last = index == segments.size - 1

        if child.nil? || (!last && !child.directory?)
          child = Node.new(
            name: segment,
            path: segments[0..index].join('/'),
            entry: nil,
            children: {}
          )
          node.children[key] = child
        end

        replace_node(child, entry) if last
        child.name = segment
        child.path = segments[0..index].join('/')
        node = child
      end

      @sources[entry.object_id] = archive
    end

    def replace_node(node, entry)
      node.children = {} unless entry.directory? && node.directory?
      node.entry = entry
    end

    def remove_path(segments)
      parent = node_for_segments(segments[0...-1])
      return if parent.nil?

      parent.children.delete(key_for(segments.last))
    end

    def prune_implicit_directories(node)
      node.children.each do |key, child|
        prune_implicit_directories(child)
        node.children.delete(key) if child.entry.nil? && child.children.empty?
      end
    end

    def node_for(path)
      return @root if path.nil? || path.to_s.empty? || path.to_s == '/'

      segments, = normalize_path(path)
      node_for_segments(segments)
    end

    def node_for_segments(segments)
      segments.inject(@root) do |node, segment|
        return nil if node.nil? || !node.directory?

        node.children[key_for(segment)]
      end
    end

    def require_directory_node(path)
      node = node_for(path)
      raise Errno::ENOENT, path if node.nil?
      raise Errno::ENOTDIR, path unless node.directory?

      node
    end

    def resolve_entry(path_or_entry)
      if path_or_entry.kind_of?(Entry)
        node = node_for(path_or_entry.name)
        if node.nil? || node.equal?(@root)
          raise Errno::ENOENT, path_or_entry.name
        end
        visible_entry = node.entry
        if visible_entry.nil?
          unless path_or_entry.directory?
            raise Errno::ENOENT, path_or_entry.name
          end
        elsif !visible_entry.equal?(path_or_entry)
          raise Errno::ENOENT, path_or_entry.name
        end
        return [node, entry_for(node)]
      end

      node = node_for(path_or_entry)
      raise Errno::ENOENT, path_or_entry.to_s if node.nil? || node.equal?(@root)

      [node, entry_for(node)]
    end

    def source_for(entry)
      @sources.fetch(entry.object_id) { raise Errno::ENOENT, entry.name }
    end

    def open_directory_entry
      yield(::Zip::NullInputStream) if block_given?
      ::Zip::NullInputStream
    end

    def entry_for(node)
      node.entry || Entry.new('', "#{node.path}/")
    end

    def sorted_children(node)
      node.children.sort_by(&:first)
    end

    def walk(node, &block)
      sorted_children(node).each do |_key, child|
        yield entry_for(child)
        walk(child, &block) if child.directory?
      end
    end

    def select_entries(&block)
      each.select(&block)
    end

    def key_for(name)
      @case_insensitive ? name.downcase : name
    end

    def ensure_open!
      raise IOError, 'closed overlay' if @closed
    end
  end
end
