# frozen_string_literal: true

require 'English'
require 'delegate'
require 'singleton'
require 'tempfile'
require 'fileutils'
require 'stringio'
require 'zlib'
require 'zip/version'
require 'zip/constants'
require 'zip/dos_time'
require 'zip/ioextras'
require 'rbconfig'
require 'zip/entry'
require 'zip/extra_field'
require 'zip/entry_set'
require 'zip/central_directory'
require 'zip/file'
require 'zip/input_stream'
require 'zip/output_stream'
require 'zip/decompressor'
require 'zip/compressor'
require 'zip/null_decompressor'
require 'zip/null_compressor'
require 'zip/null_input_stream'
require 'zip/pass_thru_compressor'
require 'zip/pass_thru_decompressor'
require 'zip/crypto/decrypted_io'
require 'zip/crypto/encryption'
require 'zip/crypto/null_encryption'
require 'zip/crypto/traditional_encryption'
require 'zip/crypto/aes_encryption'
require 'zip/inflater'
require 'zip/deflater'
require 'zip/streamable_stream'
require 'zip/streamable_directory'
require 'zip/errors'

# Rubyzip is a ruby module for reading and writing zip files.
#
# The main entry points are File, InputStream and OutputStream. For a
# file/directory interface in the style of the standard ruby ::File and
# ::Dir APIs then `require 'zip/filesystem'` and see FileSystem.
module Zip
  extend self

  attr_accessor :unicode_names,
                :on_exists_proc,
                :continue_on_exists_proc,
                :sort_entries,
                :default_compression,
                :write_zip64_support,
                :warn_invalid_date,
                :case_insensitive_match,
                :allow_duplicate_entry_names,
                :force_entry_names_encoding,
                :validate_entry_sizes,
                :validate_declared_number_of_entries,
                :inflater_chunk_size

  # The current name audit mode. See `Zip.name_audit_mode=` for details.
  attr_reader :name_audit_mode

  # Valid values for `Zip.name_audit_mode`.
  NAME_AUDIT_MODES = %i[off lenient strict].freeze

  DEFAULT_RESTORE_OPTIONS = {
    restore_ownership:   false,
    restore_permissions: true,
    restore_times:       true
  }.freeze # :nodoc:

  # :nodoc:
  # Remove this when JRuby#3962 is fixed.
  ZLIB_FLUSHING_STRATEGY = defined?(JRUBY_VERSION) ? Zlib::SYNC_FLUSH : Zlib::NO_FLUSH

  def reset! # :nodoc:
    @_ran_once = false
    @unicode_names = false
    @on_exists_proc = false
    @continue_on_exists_proc = false
    @sort_entries = false
    @default_compression = Zlib::DEFAULT_COMPRESSION
    @write_zip64_support = true
    @warn_invalid_date = true
    @case_insensitive_match = false
    @allow_duplicate_entry_names = false
    @force_entry_names_encoding = nil
    @validate_entry_sizes = true
    @validate_declared_number_of_entries = false # Set this to `true` in v4.0.0?
    @inflater_chunk_size = 4096
    @name_audit_mode = :off
  end

  # Sets how strictly rubyzip audits entry names while reading archives.
  #
  # The same entry name can appear, byte-for-byte differently, in a zip
  # archive's local file header, its central directory, and the Info-ZIP
  # Unicode Path extra field (0x7075). The available modes are:
  #
  # * `:off` (default) - no auditing; historical behaviour.
  # * `:lenient` - collect a `Zip::NameAudit` for each entry (exposed via
  #   `Zip::Entry#name_audit`) recording the raw bytes, declared encoding
  #   and decoded result from each location, but keep reading exactly as
  #   before.
  # * `:strict` - like `:lenient`, but raise `Zip::EntryNameMismatchError`
  #   when inconsistencies are found (local/central name mismatch, invalid
  #   UTF-8 where UTF-8 is declared, a Unicode Path extra field whose CRC32
  #   does not match the accompanying header name, or several entries
  #   normalising to the same name), instead of silently trusting whichever
  #   name was read last.
  def name_audit_mode=(mode)
    mode = mode.to_sym if mode.respond_to?(:to_sym)
    return @name_audit_mode = mode if NAME_AUDIT_MODES.include?(mode)

    raise ArgumentError,
          "invalid name audit mode #{mode.inspect} " \
          "(expected one of: #{NAME_AUDIT_MODES.join(', ')})"
  end

  # Set options for RubyZip in one block.
  def setup
    yield self unless @_ran_once
    @_ran_once = true
  end

  reset!
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
