# frozen_string_literal: true

module Zip
  module FileSystem
    # All access to Zip::File from FileSystem::File and FileSystem::Dir
    # goes through a ZipFileNameMapper, which has one responsibility: ensure
    class ZipFileNameMapper # :nodoc:all
      include Enumerable

      def initialize(zip_file)
        @zip_file = zip_file
        @pwd = '/'
      end

      attr_accessor :pwd

      # Always returns a single entry (the first match), even when
      # Zip.allow_duplicate_entry_names is on, since this filesystem-style
      # API has no way to represent more than one entry per path.
      def find_entry(filename)
        entry = @zip_file.find_entry(expand_to_entry(filename))
        entry.kind_of?(Array) ? entry.first : entry
      end

      # See #find_entry.
      def get_entry(filename)
        entry = @zip_file.get_entry(expand_to_entry(filename))
        entry.kind_of?(Array) ? entry.first : entry
      end

      def get_input_stream(filename, &a_proc)
        @zip_file.get_input_stream(expand_to_entry(filename), &a_proc)
      end

      def get_output_stream(filename, permissions = nil, &a_proc)
        @zip_file.get_output_stream(
          expand_to_entry(filename), permissions: permissions, &a_proc
        )
      end

      def glob(pattern, *flags, &block)
        @zip_file.glob(expand_to_entry(pattern), *flags, &block)
      end

      def read(filename)
        @zip_file.read(expand_to_entry(filename))
      end

      def remove(filename)
        @zip_file.remove(expand_to_entry(filename))
      end

      def rename(filename, new_name, &continue_on_exists_proc)
        @zip_file.rename(
          expand_to_entry(filename),
          expand_to_entry(new_name),
          &continue_on_exists_proc
        )
      end

      def mkdir(filename, permissions = 0o755)
        @zip_file.mkdir(expand_to_entry(filename), permissions)
      end

      # Turns entries into strings and adds leading /
      # and removes trailing slash on directories
      def each
        @zip_file.each do |e|
          yield("/#{e.to_s.chomp('/')}")
        end
      end

      def expand_path(path)
        expanded = path.start_with?('/') ? path.dup : ::File.join(@pwd, path)
        expanded.gsub!(/\/\.(\/|$)/, '')
        expanded.gsub!(/[^\/]+\/\.\.(\/|$)/, '')
        expanded.empty? ? '/' : expanded
      end

      private

      def expand_to_entry(path)
        expand_path(path)[1..]
      end
    end
  end
end
