# frozen_string_literal: true

require_relative 'test_helper'

class OverlayTest < Minitest::Test
  GENERATED_DIR = 'test/data/generated'

  def teardown
    ::Zip.reset!
  end

  # Builds a zip archive (as a binary String) from a Hash of
  # entry name => content. Names ending in '/' become directory entries.
  def build_zip(entries = {})
    ::Zip::File.open_buffer(create: true) do |zf|
      entries.each do |name, content|
        if name.end_with?('/')
          zf.mkdir(name)
        else
          zf.get_output_stream(name) { |os| os.write content }
        end
      end
    end.string
  end

  def layer(entries = {})
    ::StringIO.new(build_zip(entries))
  end

  # Builds a zip archive (as a binary String) that deliberately contains
  # ambiguous entries, bypassing rubyzip's duplicate-name checks.
  def build_ambiguous_zip
    ::Zip.allow_duplicate_entry_names = true
    ::Zip::OutputStream.write_buffer do |zos|
      yield zos
    end.string
  ensure
    ::Zip.allow_duplicate_entry_names = false
  end

  def test_higher_layer_overrides_file
    overlay = ::Zip::Overlay.new([
                                   layer('a.txt' => 'base', 'b.txt' => 'base only'),
                                   layer('a.txt' => 'patched')
                                 ])

    assert_equal('patched', overlay.read('a.txt'))
    assert_equal('base only', overlay.read('b.txt'))
    assert_equal(%w[a.txt b.txt], overlay.entries.map(&:name))
    assert_equal(2, overlay.size)
  end

  def test_read_is_lazy_and_correct_per_layer
    overlay = ::Zip::Overlay.new([
                                   layer('big.txt' => 'x' * 100_000),
                                   layer('small.txt' => 'y')
                                 ])

    assert_equal('x' * 100_000, overlay.read('big.txt'))
    assert_equal('y', overlay.read('small.txt'))
  end

  def test_flat_deletes_hide_names_in_every_layer
    overlay = ::Zip::Overlay.new(
      [
        layer('gone.txt' => 'old', 'kept.txt' => 'kept'),
        layer('gone.txt' => 'new', 'other.txt' => 'other')
      ],
      deletes: ['gone.txt']
    )

    refute overlay.exist?('gone.txt')
    assert_raises(Errno::ENOENT) { overlay.get_entry('gone.txt') }
    assert_raises(Errno::ENOENT) { overlay.read('gone.txt') }
    assert_equal(%w[kept.txt other.txt], overlay.entries.map(&:name).sort)
  end

  def test_directory_tombstone_hides_descendants
    overlay = ::Zip::Overlay.new(
      [layer('old/junk.txt' => 'junk', 'old/deep/nest.txt' => 'nest', 'new/fresh.txt' => 'fresh')],
      deletes: ['old/']
    )

    refute overlay.exist?('old/junk.txt')
    refute overlay.exist?('old/deep/nest.txt')
    refute overlay.directory?('old')
    assert_equal('fresh', overlay.read('new/fresh.txt'))
    assert_raises(Errno::ENOENT) { overlay.dir_entries('old') }
  end

  def test_file_tombstone_does_not_hide_directory
    overlay = ::Zip::Overlay.new(
      [layer('thing/inner.txt' => 'inner')],
      deletes: ['thing']
    )

    assert overlay.directory?('thing')
    assert_equal('inner', overlay.read('thing/inner.txt'))
  end

  def test_boundary_deletes_hide_only_lower_layers
    base = layer('config.yml' => 'v1', 'legacy.txt' => 'legacy')
    patch = layer('config.yml' => 'v2')

    # Deletion at boundary 1 hides layer 0 only, so the layer 1 re-add wins.
    overlay = ::Zip::Overlay.new([base, patch], deletes: { 1 => ['config.yml', 'legacy.txt'] })
    assert_equal('v2', overlay.read('config.yml'))
    refute overlay.exist?('legacy.txt')

    # The same names deleted at boundary 2 hide them in both layers.
    overlay = ::Zip::Overlay.new(
      [::StringIO.new(build_zip('config.yml' => 'v1')), ::StringIO.new(build_zip('config.yml' => 'v2'))],
      deletes: { 2 => ['config.yml'] }
    )
    refute overlay.exist?('config.yml')
  end

  def test_file_replaces_directory
    overlay = ::Zip::Overlay.new([
                                   layer('asset/data.txt' => 'dir contents'),
                                   layer('asset' => 'now a file')
                                 ])

    assert overlay.file?('asset')
    refute overlay.directory?('asset')
    refute overlay.exist?('asset/data.txt')
    assert_equal('now a file', overlay.read('asset'))
  end

  def test_directory_replaces_file
    overlay = ::Zip::Overlay.new([
                                   layer('asset' => 'was a file'),
                                   layer('asset/data.txt' => 'dir contents')
                                 ])

    assert overlay.directory?('asset')
    refute overlay.file?('asset')
    assert_equal('dir contents', overlay.read('asset/data.txt'))
  end

  def test_directory_contents_merge_across_layers
    overlay = ::Zip::Overlay.new([
                                   layer('app/models/user.rb' => 'user', 'app/config.yml' => 'cfg'),
                                   layer('app/controllers/home.rb' => 'home')
                                 ])

    assert_equal(%w[config.yml controllers models], overlay.dir_entries('app'))
    assert_equal(%w[user.rb], overlay.dir_entries('app/models'))
    assert_equal('home', overlay.read('app/controllers/home.rb'))
    assert_equal('user', overlay.read('app/models/user.rb'))
  end

  def test_duplicate_names_within_a_layer_raise
    dup_zip = build_ambiguous_zip do |zos|
      zos.put_next_entry('dup.txt')
      zos.write 'one'
      zos.put_next_entry('dup.txt')
      zos.write 'two'
    end

    error = assert_raises(::Zip::OverlayError) do
      ::Zip::Overlay.new([::StringIO.new(dup_zip)])
    end
    assert_match(/dup.txt/, error.message)
  end

  def test_file_and_directory_with_same_name_within_a_layer_raise
    conflict_zip = build_ambiguous_zip do |zos|
      zos.put_next_entry('thing')
      zos.write 'file'
      zos.put_next_entry('thing/')
    end

    assert_raises(::Zip::OverlayError) do
      ::Zip::Overlay.new([::StringIO.new(conflict_zip)])
    end
  end

  def test_file_that_is_parent_of_another_entry_within_a_layer_raises
    conflict_zip = build_ambiguous_zip do |zos|
      zos.put_next_entry('a')
      zos.write 'file'
      zos.put_next_entry('a/b')
      zos.write 'nested'
    end

    assert_raises(::Zip::OverlayError) do
      ::Zip::Overlay.new([::StringIO.new(conflict_zip)])
    end
  end

  def test_listing_and_opening_see_the_same_view
    overlay = ::Zip::Overlay.new(
      [
        layer('app/old.rb' => 'old', 'app/kept.rb' => 'kept', 'gone/x.rb' => 'x'),
        layer('app/new.rb' => 'new')
      ],
      deletes: ['gone/', 'app/old.rb']
    )

    listed = overlay.dir_entries('app')
    assert_equal(%w[kept.rb new.rb], listed)
    listed.each { |name| overlay.read("app/#{name}") } # must all be openable

    assert_equal(%w[app/kept.rb app/new.rb], overlay.glob('app/*.rb').map(&:name).sort)
    refute overlay.exist?('gone')
  end

  def test_dir_entries_includes_implicit_directories
    overlay = ::Zip::Overlay.new([layer('a/b/c.txt' => 'deep', 'a/top.txt' => 'top')])

    assert_equal(%w[a], overlay.dir_entries)
    assert_equal(%w[b top.txt], overlay.dir_entries('a'))
    assert_equal(%w[c.txt], overlay.dir_entries('a/b'))
    assert_raises(Errno::ENOENT) { overlay.dir_entries('nope') }
    assert_raises(Errno::ENOENT) { overlay.dir_entries('a/top.txt') }
  end

  def test_explicit_directory_entries_are_listed
    overlay = ::Zip::Overlay.new([layer('docs/' => nil, 'docs/readme.txt' => 'readme')])

    entry = overlay.find_entry('docs')
    assert entry
    assert entry.directory?
    assert_includes overlay.entries.map(&:name), 'docs/'
    assert_equal('readme', overlay.read('docs/readme.txt'))
  end

  def test_predicates
    overlay = ::Zip::Overlay.new([layer('dir/file.txt' => 'x')])

    assert overlay.file?('dir/file.txt')
    refute overlay.directory?('dir/file.txt')
    assert overlay.directory?('dir')
    assert overlay.directory?('')
    assert overlay.exist?('dir/file.txt')
    refute overlay.exist?('dir/other.txt')
  end

  def test_get_input_stream_reads_from_winning_layer
    overlay = ::Zip::Overlay.new([
                                   layer('data.bin' => 'base'),
                                   layer('data.bin' => 'top')
                                 ])

    contents = overlay.get_input_stream('data.bin', &:read)
    assert_equal('top', contents)
  end

  def test_path_layers_and_block_form
    base_path = ::File.join(GENERATED_DIR, 'overlay_base.zip')
    patch_path = ::File.join(GENERATED_DIR, 'overlay_patch.zip')
    ::File.binwrite(base_path, build_zip('hello.txt' => 'hello'))
    ::File.binwrite(patch_path, build_zip('hello.txt' => 'goodbye'))

    result = ::Zip::Overlay.open([base_path, patch_path]) do |overlay|
      assert_equal('goodbye', overlay.read('hello.txt'))
      'block result'
    end

    assert_equal('block result', result)
  end

  def test_close_closes_owned_layers_and_forbids_further_reads
    overlay = ::Zip::Overlay.new([layer('a.txt' => 'a')])
    assert_equal('a', overlay.read('a.txt'))

    overlay.close
    assert overlay.closed?
    assert_raises(IOError) { overlay.read('a.txt') }
    assert_raises(IOError) { overlay.entries }
    overlay.close # idempotent
  end

  def test_caller_supplied_zip_files_are_not_closed
    path = ::File.join(GENERATED_DIR, 'overlay_caller_supplied.zip')
    ::File.binwrite(path, build_zip('a.txt' => 'a'))
    zf = ::Zip::File.new(path)

    overlay = ::Zip::Overlay.new([zf])
    assert_equal('a', overlay.read('a.txt'))
    overlay.close

    assert_equal('a', zf.read('a.txt')) # still usable: ownership stayed with the caller
  end

  def test_deletes_manifest_validation
    assert_raises(ArgumentError) { ::Zip::Overlay.new([layer], deletes: 'oops') }
    assert_raises(ArgumentError) { ::Zip::Overlay.new([layer], deletes: { 0 => ['a'] }) }
    assert_raises(ArgumentError) { ::Zip::Overlay.new([layer], deletes: { 2 => ['a'] }) }
    assert_raises(ArgumentError) { ::Zip::Overlay.new([layer], deletes: ['/absolute']) }
    assert_raises(ArgumentError) { ::Zip::Overlay.new([layer], deletes: ['']) }
  end

  def test_layers_must_be_a_non_empty_array
    assert_raises(ArgumentError) { ::Zip::Overlay.new([]) }
    assert_raises(ArgumentError) { ::Zip::Overlay.new('not-an-array') }
    assert_raises(ArgumentError) { ::Zip::Overlay.new([42]) }
  end

  def test_case_insensitive_matching_is_respected
    ::Zip.case_insensitive_match = true
    overlay = ::Zip::Overlay.new([
                                   layer('ReadMe.txt' => 'base'),
                                   layer('readme.TXT' => 'top')
                                 ])

    assert_equal('top', overlay.read('README.txt'))
    assert_equal(1, overlay.size)
  end
end
