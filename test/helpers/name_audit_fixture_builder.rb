# frozen_string_literal: true

require 'fileutils'
require 'zlib'

# Builds zip archives byte-by-byte for the entry-name audit tests.
#
# These samples deliberately contain things that Zip::OutputStream would
# never produce (mismatched local/central names, bad Unicode Path CRCs,
# invalid UTF-8, ...), so they are constructed by hand here instead of via
# the library's own writer. The static fixtures in test/data/name_audit are
# generated from these same methods (see
# test/helpers/generate_name_audit_fixtures.rb), and the tests assert that
# the files on disk still match, so the two can never drift apart.
module NameAuditFixtureBuilder
  extend self

  EFS_FLAG = 0b1000_0000_0000 # Language encoding flag, gp flag bit 11.

  # A fixed, valid DOS date/time (2024-01-01 12:00:00) so that the
  # fixtures don't trip rubyzip's invalid-date warnings.
  DOS_TIME = (12 << 11)
  DOS_DATE = ((2024 - 1980) << 9) | (1 << 5) | 1

  # Assemble a complete archive from entry hashes. Each entry accepts:
  #   local_name:, central_name: (defaults to local_name),
  #   local_extra:, central_extra: (defaults to local_extra),
  #   gp_flags:, data:
  # All names/extras/data are binary strings.
  def build_zip(entries)
    out = +''
    cdir = +''
    entries.each do |entry|
      data          = (entry[:data] || '').b
      local_name    = entry.fetch(:local_name).b
      central_name  = (entry[:central_name] || local_name).b
      local_extra   = (entry[:local_extra] || '').b
      central_extra = (entry[:central_extra] || local_extra).b
      gp_flags      = entry[:gp_flags] || 0
      crc           = Zlib.crc32(data)

      offset = out.bytesize
      out << local_header(local_name, local_extra, gp_flags, crc, data.bytesize)
      out << data
      cdir << cdir_entry(central_name, central_extra, gp_flags, crc,
                         data.bytesize, offset)
    end
    (out + cdir + eocd(entries.size, cdir.bytesize, out.bytesize)).force_encoding(Encoding::BINARY)
  end

  # An Info-ZIP Unicode Path extra field (0x7075). Pass crc: to override
  # the CRC32 (e.g. to build a deliberately corrupt field).
  def unicode_path_field(header_name:, unicode_name:, version: 1, crc: nil)
    crc = Zlib.crc32(header_name.b) if crc.nil?
    content = [version, crc].pack('CV') + unicode_name.b
    [0x7075, content.bytesize].pack('vv') + content
  end

  # A well-formed archive whose names agree everywhere; the control sample.
  def consistent_unicode_path
    name = 'Résumé.txt'.dup.force_encoding(Encoding::UTF_8)
    field = unicode_path_field(header_name: name, unicode_name: name)
    build_zip([{ local_name: name, local_extra: field, gp_flags: EFS_FLAG,
                 data: 'hello' }])
  end

  # The local header and the central directory record different names.
  def local_central_mismatch
    build_zip([{ local_name: 'local-name.txt', central_name: 'central-name.txt',
                 data: 'hello' }])
  end

  # The Unicode Path extra field's CRC does not match the header name.
  def unicode_path_crc_mismatch
    field = unicode_path_field(header_name: 'report.txt', unicode_name: 'report.txt',
                               crc: 0xDEADBEEF)
    build_zip([{ local_name: 'report.txt', local_extra: field, data: 'hello' }])
  end

  # The EFS flag declares UTF-8, but the name bytes are not valid UTF-8.
  def invalid_utf8_efs
    build_zip([{ local_name: "\xFF\xFE-invalid.txt".b, gp_flags: EFS_FLAG,
                 data: 'hello' }])
  end

  # Two entries whose names differ in bytes but are equal after NFC
  # normalization (é as U+00E9 vs e + U+0301).
  def normalized_collision
    nfc = "caf\u00E9.txt"
    nfd = "cafe\u0301.txt"
    build_zip([{ local_name: nfc, gp_flags: EFS_FLAG, data: 'one' },
               { local_name: nfd, gp_flags: EFS_FLAG, data: 'two' }])
  end

  # The legitimate use of the Unicode Path extra field: the header name is
  # an ASCII placeholder, the real (UTF-8) name lives in the extra field,
  # and the CRC correctly matches the header name. No issues expected.
  def unicode_path_alias
    field = unicode_path_field(header_name: '____.txt', unicode_name: '日本語.txt')
    build_zip([{ local_name: '____.txt', local_extra: field, data: 'hello' }])
  end

  SAMPLES = {
    'consistent_unicode_path.zip'   => :consistent_unicode_path,
    'local_central_mismatch.zip'    => :local_central_mismatch,
    'unicode_path_crc_mismatch.zip' => :unicode_path_crc_mismatch,
    'invalid_utf8_efs.zip'          => :invalid_utf8_efs,
    'normalized_collision.zip'      => :normalized_collision,
    'unicode_path_alias.zip'        => :unicode_path_alias
  }.freeze

  def write_all(dir)
    FileUtils.mkdir_p(dir)
    SAMPLES.each do |filename, builder|
      File.binwrite(File.join(dir, filename), send(builder))
    end
  end

  private

  def local_header(name, extra, gp_flags, crc, data_size)
    [0x04034B50, 20, gp_flags, 0, DOS_TIME, DOS_DATE, crc, data_size, data_size,
     name.bytesize, extra.bytesize].pack('VvvvvvVVVvv') + name + extra
  end

  def cdir_entry(name, extra, gp_flags, crc, data_size, offset)
    [0x02014B50, 20, 20, gp_flags, 0, DOS_TIME, DOS_DATE, crc, data_size, data_size,
     name.bytesize, extra.bytesize, 0, 0, 0, 0, offset]
      .pack('VvvvvvvVVVvvvvvVV') + name + extra
  end

  def eocd(count, cdir_size, cdir_offset)
    [0x06054B50, 0, 0, count, count, cdir_size, cdir_offset, 0].pack('VvvvvVVv')
  end
end
