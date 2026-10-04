# frozen_string_literal: true

require_relative 'test_helper'

class ZipMultiVolumeTest < Minitest::Test
  SPLIT_SIGNATURE = [0x08074b50].pack('V')
  LOCAL_SIGNATURE = 0x04034b50
  CENTRAL_SIGNATURE = 0x02014b50
  ZIP64_EOCD_SIGNATURE = 0x06064b50
  ZIP64_LOCATOR_SIGNATURE = 0x07064b50
  EOCD_SIGNATURE = 0x06054b50
  VOLUME_COUNT = 5

  def teardown
    ::Zip.reset!
  end

  def test_reads_entries_with_zip64_central_directory_across_volumes
    provider = provider_for(spanned_volumes)

    ::Zip::File.open_volume(provider) do |zip_file|
      assert_equal(%w[first.txt second.txt], zip_file.entries.map(&:name))
      assert_equal([8, 0], zip_file.entries.map(&:compression_method))
      assert_equal('first contents', zip_file.read('first.txt'))
      assert_equal('second data', zip_file.read('second.txt'))
    end
  end

  def test_streams_sequentially_across_data_descriptor_boundary
    provider = provider_for(spanned_volumes)
    names = []
    contents = []

    ::Zip::InputStream.open(provider) do |input_stream|
      while (entry = input_stream.get_next_entry)
        names << entry.name
        contents << input_stream.read
      end
    end

    assert_equal(%w[first.txt second.txt], names)
    assert_equal(['first contents', 'second data'], contents)
  end

  def test_missing_volume_has_disk_number
    volumes = spanned_volumes
    volumes[2] = nil

    error = assert_raises(::Zip::MissingVolumeError) do
      ::Zip::File.open_volume(provider_for(volumes), &:size)
    end

    assert_equal(2, error.message[/disk (\d+)/, 1].to_i)
  end

  def test_duplicate_volume_has_both_disk_numbers
    volumes = spanned_volumes
    volumes[2] = volumes[1]
    provider = ::Zip::VolumeProvider.new(VOLUME_COUNT) { |disk| volumes.fetch(disk) }

    error = assert_raises(::Zip::DuplicateVolumeError) do
      ::Zip::File.open_volume(provider, &:size)
    end

    assert_match(/disk 2/, error.message)
    assert_match(/disk 1/, error.message)
  end

  def test_invalid_offset_names_disk_and_length
    provider = provider_for(spanned_volumes)
    io = provider.open_io

    error = assert_raises(::Zip::VolumeOffsetError) do
      io.seek_to(0, spanned_volumes[0].string.length - 4 + 100)
    end

    assert_match(/disk 0/, error.message)
    assert_match(/#{spanned_volumes[0].string.length - 4} bytes long/, error.message)
  ensure
    io&.close
  end

  def test_borrowed_volumes_are_not_closed_by_reader
    volumes = spanned_volumes
    provider = ::Zip::VolumeProvider.borrow(volumes)

    ::Zip::File.open_volume(provider, &:size)

    refute(volumes.any?(&:closed?))
  ensure
    volumes.each(&:close)
  end

  def test_owned_volumes_are_closed_by_reader
    opened_volumes = []
    volumes = spanned_volumes
    provider = ::Zip::VolumeProvider.new(VOLUME_COUNT) do |disk_number|
      io = volumes.fetch(disk_number).dup
      opened_volumes << io
      io
    end

    ::Zip::File.open_volume(provider, &:size)

    assert(opened_volumes.all?(&:closed?))
  end

  private

  def provider_for(volumes)
    ::Zip::VolumeProvider.new(VOLUME_COUNT) do |disk|
      volumes[disk]&.dup
    end
  end

  def spanned_volumes
    archive = logical_archive
    cuts = volume_cuts
    boundaries = [0, *cuts, archive.length]
    parts = boundaries.each_cons(2).map { |start, finish| archive[start...finish] }
    parts.each_with_index.map do |part, index|
      StringIO.new(index.zero? ? SPLIT_SIGNATURE + part : part)
    end
  end

  def logical_archive
    first = 'first contents'.b
    second = 'second data'.b
    first_compressed = Zlib::Deflate.deflate(first, Zlib::DEFAULT_COMPRESSION)[2..-5].b

    first_local = local_entry(
      'first.txt', first, first_compressed, 0, Zlib.crc32(first),
      compression_method: 8, gp_flags: 0b1000
    )
    first_descriptor = data_descriptor(first_compressed, Zlib.crc32(first))
    @volume_cuts = dynamic_volume_cuts(
      first_local.length, first_compressed.length, first_descriptor.length
    )
    second_offset = first_local.length + first_descriptor.length
    second_local = local_entry(
      'second.txt', second, second, second_offset, Zlib.crc32(second),
      gp_flags: 0b1000
    )
    second_descriptor = data_descriptor(second, Zlib.crc32(second))

    central_start = (first_local.length + first_descriptor.length +
                     second_local.length + second_descriptor.length)
    first_central = central_entry(
      'first.txt', first, first_compressed, Zlib.crc32(first),
      disk: 0, offset: 0, compression_method: 8, gp_flags: 0b1000
    )
    second_central = central_entry(
      'second.txt', second, second, Zlib.crc32(second),
      disk: disk_location(second_offset).first,
      offset: disk_location(second_offset).last,
      gp_flags: 0b1000
    )
    central_size = first_central.length + second_central.length

    cdir_disk, cdir_offset = disk_location(central_start)
    zip64_eocd = zip64_eocd(central_size, cdir_disk, cdir_offset)
    zip64_disk, zip64_offset = disk_location(central_start + central_size)
    locator = zip64_locator(zip64_disk, zip64_offset)
    eocd = eocd(cdir_disk, cdir_offset)

    first_local + first_descriptor + second_local + second_descriptor +
      first_central + second_central + zip64_eocd + locator + eocd
  end

  def disk_location(offset)
    cuts = volume_cuts
    disk = cuts.index { |cut| offset < cut } || cuts.length
    disk_offset = disk.zero? ? offset : offset - cuts[disk - 1]
    [disk, disk_offset]
  end

  def dynamic_volume_cuts(first_local_length, first_compressed_length,
                         first_descriptor_length)
    first_data_start = first_local_length - first_compressed_length
    first_data_end = first_local_length
    first_descriptor_end = first_data_end + first_descriptor_length
    second_local_length = 30 + 'second.txt'.bytesize + 20 + 11
    second_data_start = first_descriptor_end + second_local_length - 11
    central_start = first_descriptor_end + second_local_length + 16
    first_central_length = 46 + 'first.txt'.bytesize + 32
    [
      first_data_start + 4,
      first_data_end + 4,
      second_data_start + 4,
      central_start + first_central_length + 4
    ]
  end

  def volume_cuts
    @volume_cuts || [60, 166, 250]
  end

  def local_entry(name, data, compressed_data, offset, crc,
                 compression_method: 0, gp_flags:)
    zip64_extra = zip64_extra_fields(data.length, compressed_data.length)
    [
      LOCAL_SIGNATURE, 45, 0, gp_flags, compression_method, 0, 0, crc,
      0xFFFFFFFF, 0xFFFFFFFF, name.bytesize, zip64_extra.bytesize
    ].pack('VCCvvvvVVVvv') + name + zip64_extra + compressed_data
  end

  def data_descriptor(data, crc)
    [SPLIT_SIGNATURE.unpack1('V'), crc, data.length, data.length].pack('VVVV')
  end

  def central_entry(name, data, compressed_data, crc,
                   disk:, offset:, compression_method: 0, gp_flags:)
    zip64_extra = zip64_extra_fields(data.length, compressed_data.length, offset, disk)
    [
      CENTRAL_SIGNATURE, 52, 3, 45, gp_flags, compression_method, 0, 0, crc,
      0xFFFFFFFF, 0xFFFFFFFF, name.bytesize, zip64_extra.bytesize, 0,
      0xFFFF, 0, 0, 0xFFFFFFFF
    ].pack('VCCvvvvvVVVvvvvvVV') + name + zip64_extra
  end

  def zip64_extra_fields(size, compressed_size, offset = nil, disk = nil)
    content = [size, compressed_size].pack('Q<Q<')
    content << [offset, disk].pack('Q<V') if offset
    [1, content.bytesize].pack('vv') + content
  end

  def zip64_eocd(central_size, cdir_disk, cdir_offset)
    [
      ZIP64_EOCD_SIGNATURE, 44, 52, 45, VOLUME_COUNT - 1, cdir_disk,
      2, 2, central_size, cdir_offset
    ].pack('VQ<vvVVQ<Q<Q<Q<')
  end

  def zip64_locator(disk, offset)
    [ZIP64_LOCATOR_SIGNATURE, disk, offset, VOLUME_COUNT].pack('VVQ<V')
  end

  def eocd(cdir_disk, cdir_offset)
    [
      EOCD_SIGNATURE, VOLUME_COUNT - 1, cdir_disk, 0xFFFF, 0xFFFF,
      0xFFFFFFFF, cdir_offset, 0
    ].pack('VvvvvVVv')
  end
end
