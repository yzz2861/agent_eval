# frozen_string_literal: true

require_relative 'test_helper'

class MultiVolumeTest < Minitest::Test
  EOCD_SIG          = 0x06054b50
  ZIP64_EOCD_SIG    = 0x06064b50
  ZIP64_LOCATOR_SIG = 0x07064b50
  CDIR_ENTRY_SIG    = 0x02014b50
  LOCAL_ENTRY_SIG   = 0x04034b50
  DATA_DESC_SIG     = 0x08074b50

  ENTRIES = {
    'a.txt'     => 'Hello from a split archive! ' * 8,
    'dir/b.txt' => 'b' * 700,
    'c.bin'     => (0..255).to_a.pack('C*') * 3
  }.freeze

  SEGMENT_SIZE = 97

  def test_random_access_to_entries_across_volumes
    segments = split_archive(build_zip(ENTRIES), SEGMENT_SIZE)
    assert_operator segments.size, :>, 3 # sanity: genuinely multi-volume

    ::Zip::File.open('split.zip', volume_provider: io_provider(segments)) do |zf|
      assert_equal ENTRIES.keys.sort, zf.entries.map(&:name).sort

      # Random access: read the entries out of archive order.
      assert_equal ENTRIES['dir/b.txt'], zf.read('dir/b.txt')
      assert_equal ENTRIES['a.txt'], zf.read('a.txt')
      assert_equal ENTRIES['c.bin'].b, zf.read('c.bin').b
    end
  end

  def test_zip64_central_directory_across_volumes
    segments = split_archive(make_zip64(build_zip(ENTRIES)), SEGMENT_SIZE)
    assert_operator segments.size, :>, 3

    ::Zip::File.open('split64.zip', volume_provider: io_provider(segments)) do |zf|
      assert_equal ENTRIES.size, zf.size
      assert_equal ENTRIES['dir/b.txt'], zf.read('dir/b.txt')
      assert_equal ENTRIES['a.txt'], zf.read('a.txt')
    end
  end

  def test_entries_with_data_descriptors_spanning_volumes
    segments = split_archive(build_streamed_zip(ENTRIES), SEGMENT_SIZE)

    ::Zip::File.open('streamed.zip', volume_provider: io_provider(segments)) do |zf|
      ENTRIES.each do |name, content|
        assert_equal content.b, zf.read(name).b, "wrong content for #{name}"
      end
    end
  end

  def test_concurrent_entry_streams_with_owned_volumes
    segments = split_archive(build_zip(ENTRIES), SEGMENT_SIZE)

    Dir.mktmpdir do |dir|
      paths = segments.each_with_index.to_h do |segment, disk|
        path = ::File.join(dir, format('split.zip.%03d', disk))
        ::File.binwrite(path, segment)
        [disk, path]
      end

      provider = ::Zip::VolumeProvider.for_paths(paths)
      ::Zip::File.open('split.zip', volume_provider: provider) do |zf|
        stream_a = zf.get_input_stream('a.txt')
        stream_b = zf.get_input_stream('dir/b.txt')

        # Interleave reads from two entries: owned volumes give each stream
        # its own file handles, so the two cursors stay independent.
        assert_equal ENTRIES['a.txt'][0, 10], stream_a.read(10)
        assert_equal ENTRIES['dir/b.txt'][0, 10], stream_b.read(10)
        stream_a.close
        assert_equal ENTRIES['dir/b.txt'][10..], stream_b.read
        stream_b.close
      end
    end
  end

  def test_missing_volume_reports_disk_number
    segments = split_archive(build_zip(ENTRIES), SEGMENT_SIZE)
    ios = segments.each_with_index.to_h { |seg, disk| [disk, StringIO.new(seg)] }
    ios.delete(1) # drop an intermediate volume

    error = assert_raises(::Zip::MissingVolumeError) do
      ::Zip::File.open('split.zip', volume_provider: ::Zip::VolumeProvider.for_ios(ios))
    end
    assert_equal 1, error.disk_number
    assert_match(/Volume 1/, error.message)
  end

  def test_duplicate_volume_detected
    segments = split_archive(build_zip(ENTRIES), SEGMENT_SIZE)
    shared = StringIO.new(segments[0])
    provider = ::Zip::VolumeProvider.for_ios(
      0 => shared, 1 => shared, 2 => StringIO.new(segments[2])
    )

    error = assert_raises(::Zip::DuplicateVolumeError) do
      ::Zip::File.open('split.zip', volume_provider: provider)
    end
    assert_match(/Volumes 1 and 0/, error.message)
  end

  def test_out_of_bounds_offsets_are_reported
    io = ::Zip::SegmentedIO.new(::Zip::VolumeProvider.for_ios(0 => StringIO.new('abc')))

    assert_equal 0, io.logical_offset(0, 0)
    assert_equal 3, io.logical_offset(0, 3)

    error = assert_raises(::Zip::VolumeOffsetError) { io.logical_offset(0, 4) }
    assert_match(/Offset 4 is out of bounds for volume 0/, error.message)

    assert_raises(::Zip::VolumeOffsetError) { io.seek(4) }
    assert_raises(Errno::EINVAL) { io.seek(-1) }
    assert_raises(::Zip::MissingVolumeError) { io.logical_offset(1, 0) }
  end

  def test_segmented_io_seeks_and_reads_across_volumes
    provider = ::Zip::VolumeProvider.for_ios(
      0 => StringIO.new('abc'), 1 => StringIO.new('def'), 2 => StringIO.new('gh')
    )
    io = ::Zip::SegmentedIO.new(provider)

    assert_equal 8, io.size
    assert_equal 'abc', io.read(3)
    assert_equal 3, io.tell

    io.seek(2)
    assert_equal 'cdef', io.read(4) # crosses the volume boundary

    io.seek(-2, ::IO::SEEK_END)
    assert_equal 'gh', io.read
    assert io.eof?
    assert_nil io.read(1)

    io.seek(0)
    assert_equal 'abcdefgh', io.read

    io.close
    assert_raises(IOError) { io.read(1) }
  end

  def test_owned_volumes_are_closed_with_the_archive
    segments = split_archive(build_zip(ENTRIES), SEGMENT_SIZE)
    opened = []
    provider = ::Zip::VolumeProvider.new do |disk|
      segment = segments[disk]
      if segment
        io = StringIO.new(segment)
        opened << io
        ::Zip::VolumeProvider.owned(io)
      end
    end

    zf = ::Zip::File.open('split.zip', volume_provider: provider)
    zf.read('a.txt')
    zf.close

    assert_operator opened.size, :>=, segments.size
    assert opened.all?(&:closed?), 'owned volumes should be closed'
  end

  def test_borrowed_volumes_are_left_open
    segments = split_archive(build_zip(ENTRIES), SEGMENT_SIZE)
    ios = segments.map { |seg| StringIO.new(seg) }
    provider = ::Zip::VolumeProvider.new { |disk| ios[disk] }

    zf = ::Zip::File.open('split.zip', volume_provider: provider)
    zf.read('a.txt')
    zf.close

    assert ios.none?(&:closed?), 'borrowed volumes belong to the caller'
  end

  def test_split_archive_without_provider_raises_split_archive_error
    segments = split_archive(build_zip(ENTRIES), SEGMENT_SIZE)

    error = assert_raises(::Zip::SplitArchiveError) do
      ::Zip::File.open_buffer(StringIO.new(segments.join)) { |zf| zf.entries }
    end
    assert_match(/volume provider/, error.message)
  end

  def test_multi_volume_archive_is_read_only
    segments = split_archive(build_zip(ENTRIES), SEGMENT_SIZE)
    zf = ::Zip::File.open('split.zip', volume_provider: io_provider(segments))
    zf.get_output_stream('new.txt') { |io| io.write 'nope' }

    error = assert_raises(::Zip::Error) { zf.close }
    assert_match(/multi-volume/, error.message)
  end

  private

  # Builds a normal single-stream zip archive in memory.
  def build_zip(entries)
    ::Zip::OutputStream.write_buffer(StringIO.new) do |zos|
      entries.each do |name, content|
        zos.put_next_entry(name)
        zos.write(content)
      end
    end.string
  end

  # Builds a zip archive whose entries are streamed: the local headers carry
  # no sizes (general purpose flag bit 3) and each entry is followed by a
  # data descriptor.
  def build_streamed_zip(entries)
    body = +''.b
    cdir = +''.b
    entries.each do |name, content|
      deflater = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
      compressed = deflater.deflate(content.b) + deflater.finish
      deflater.close
      crc = Zlib.crc32(content.b)
      dos_date = (1 << 5) | 1 # 1 Jan 1980
      offset = body.bytesize

      body << [LOCAL_ENTRY_SIG, 20, 0x08, 8, 0, dos_date, 0, 0, 0,
               name.bytesize, 0].pack('VvvvvvVVVvv')
      body << name.b
      body << compressed
      body << [DATA_DESC_SIG, crc, compressed.bytesize, content.bytesize].pack('VVVV')

      cdir << [CDIR_ENTRY_SIG, 63, 20, 0x08, 8, 0, dos_date, crc,
               compressed.bytesize, content.bytesize, name.bytesize, 0, 0, 0,
               1, 0, offset].pack('VvvvvvvVVVvvvvvVV')
      cdir << name.b
    end
    body + cdir + [EOCD_SIG, 0, 0, entries.size, entries.size,
                   cdir.bytesize, body.bytesize, 0].pack('VvvvvVVv')
  end

  # Rewrites a normal archive's EOCD as a Zip64 EOCD record, locator and a
  # sentinel-filled EOCD, as a Zip64 writer would.
  def make_zip64(bytes)
    eocd_pos = bytes.rindex([EOCD_SIG].pack('V'))
    _, _, _, _, entries, cdir_size, cdir_offset, = bytes[eocd_pos, 22].unpack('VvvvvVVv')
    body = bytes[0...eocd_pos]
    zip64_eocd = [ZIP64_EOCD_SIG, 44, 45, 45, 0, 0, entries, entries,
                  cdir_size, cdir_offset].pack('VQ<vvVVQ<Q<Q<Q<')
    locator = [ZIP64_LOCATOR_SIG, 0, body.bytesize, 1].pack('VVQ<V')
    eocd = [EOCD_SIG, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0]
           .pack('VvvvvVVv')
    body + zip64_eocd + locator + eocd
  end

  # Splits a single-stream zip archive into numbered volumes, rewriting the
  # central directory, EOCD and Zip64 records so that all offsets are
  # expressed as (disk number, offset within disk) pairs, exactly as a real
  # splitting tool (e.g. zip -s) would produce.
  def split_archive(bytes, segment_size)
    bytes = bytes.b.dup
    eocd_pos = bytes.rindex([EOCD_SIG].pack('V'))
    _, _, _, _, entries_total, _, cdir_offset, comment_length =
      bytes[eocd_pos, 22].unpack('VvvvvVVv')
    raise 'unexpected data after EOCD' unless eocd_pos + 22 + comment_length == bytes.bytesize

    locator_pos = eocd_pos - ZIP64_LOCATOR_SIZE
    zip64 = locator_pos >= 0 &&
            bytes[locator_pos, 4] == [ZIP64_LOCATOR_SIG].pack('V')
    if zip64
      zip64_eocd_pos, = bytes[locator_pos + 8, 8].unpack('Q<')
      _, _, _, _, _, _, _, entries_total, _, cdir_offset =
        bytes[zip64_eocd_pos, 56].unpack('VQ<vvVVQ<Q<Q<Q<')
    end

    rewrite_cdir_entries(bytes, entries_total, cdir_offset, segment_size)

    if zip64
      rewrite_zip64_records(bytes, eocd_pos, locator_pos, zip64_eocd_pos,
                            cdir_offset, segment_size)
    else
      rewrite_eocd(bytes, eocd_pos, cdir_offset, segment_size)
    end

    0.step(bytes.bytesize - 1, segment_size).map { |i| bytes[i, segment_size] }
  end

  ZIP64_LOCATOR_SIZE = 20

  def rewrite_cdir_entries(bytes, entries_total, cdir_offset, segment_size)
    pos = cdir_offset
    entries_total.times do
      sig, = bytes[pos, 4].unpack('V')
      raise 'bad central directory entry' unless sig == CDIR_ENTRY_SIG

      name_length, extra_length, comment_length = bytes[pos + 28, 6].unpack('vvv')
      local_offset, = bytes[pos + 42, 4].unpack('V')
      disk, offset = locate_in_volumes(local_offset, segment_size)
      bytes[pos + 34, 2] = [disk].pack('v')
      bytes[pos + 42, 4] = [offset].pack('V')
      pos += 46 + name_length + extra_length + comment_length
    end
  end

  def rewrite_eocd(bytes, eocd_pos, cdir_offset, segment_size)
    cdir_disk, cdir_off = locate_in_volumes(cdir_offset, segment_size)
    last_disk = (bytes.bytesize - 1) / segment_size
    bytes[eocd_pos + 4, 2] = [last_disk].pack('v') # number of this disk
    bytes[eocd_pos + 6, 2] = [cdir_disk].pack('v') # disk with start of cdir
    bytes[eocd_pos + 16, 4] = [cdir_off].pack('V') # cdir offset within its disk
  end

  def rewrite_zip64_records(bytes, eocd_pos, locator_pos, zip64_eocd_pos, cdir_offset, segment_size)
    cdir_disk, cdir_off = locate_in_volumes(cdir_offset, segment_size)
    last_disk = (bytes.bytesize - 1) / segment_size
    bytes[zip64_eocd_pos + 16, 4] = [last_disk].pack('V') # number of this disk
    bytes[zip64_eocd_pos + 20, 4] = [cdir_disk].pack('V') # disk with start of cdir
    bytes[zip64_eocd_pos + 48, 8] = [cdir_off].pack('Q<') # cdir offset within its disk

    zip64_disk, zip64_off = locate_in_volumes(zip64_eocd_pos, segment_size)
    bytes[locator_pos + 4, 4] = [zip64_disk].pack('V') # disk with zip64 eocd
    bytes[locator_pos + 8, 8] = [zip64_off].pack('Q<') # its offset within that disk
    bytes[eocd_pos + 4, 2] = [0xFFFF].pack('v') # keep sentinel disk numbers
    bytes[eocd_pos + 6, 2] = [0xFFFF].pack('v')
  end

  def locate_in_volumes(logical_offset, segment_size)
    [logical_offset / segment_size, logical_offset % segment_size]
  end

  def io_provider(segments)
    ::Zip::VolumeProvider.for_ios(
      segments.each_with_index.to_h { |seg, disk| [disk, StringIO.new(seg)] }
    )
  end
end
