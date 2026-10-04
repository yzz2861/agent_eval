# frozen_string_literal: true

require_relative 'test_helper'

class ZipOverlayTest < Minitest::Test
  OVERLAY_DIR = 'test/data/generated/overlay'

  Manifest = Struct.new(:tombstones)

  def setup
    FileUtils.mkdir_p(OVERLAY_DIR)
  end

  def teardown
    ::Zip.reset!
    FileUtils.rm_rf(OVERLAY_DIR)
  end

  def test_later_layers_override_files_and_tombstones_hide_descendants
    base = write_zip('base.zip') do |zip|
      zip.get_output_stream('same.txt') { |io| io.write 'base' }
      zip.get_output_stream('removed/file.txt') { |io| io.write 'removed' }
    end
    top = write_zip('top.zip') do |zip|
      zip.get_output_stream('same.txt') { |io| io.write 'top' }
      zip.get_output_stream('added.txt') { |io| io.write 'added' }
    end

    Zip::Overlay.open(base, [top, ['removed/']]) do |overlay|
      assert_equal(%w[added.txt same.txt], overlay.children)
      assert_equal(%w[added.txt same.txt], overlay.glob('*').map(&:name))
      refute(overlay.include?('removed'))
      refute(overlay.include?('removed/file.txt'))
      assert_equal('top', overlay.read('same.txt'))
    end
  end

  def test_directory_tombstone_allows_replacement_by_a_file
    base = write_zip('base.zip') do |zip|
      zip.mkdir('switch')
      zip.get_output_stream('switch/child.txt') { |io| io.write 'child' }
    end
    top = write_zip('top.zip') do |zip|
      zip.get_output_stream('switch') { |io| io.write 'file' }
    end

    Zip::Overlay.open([base, ['switch/']], top) do |overlay|
      refute(overlay.directory?('switch'))
      assert(overlay.file?('switch'))
      refute(overlay.include?('switch/child.txt'))
      assert_equal('file', overlay.read('switch'))
    end
  end

  def test_directory_replaces_file_and_then_file_replaces_directory
    base = write_zip('base.zip') do |zip|
      zip.get_output_stream('switch') { |io| io.write 'file' }
    end
    middle = write_zip('middle.zip') do |zip|
      zip.get_output_stream('switch/child.txt') { |io| io.write 'child' }
    end
    top = write_zip('top.zip') do |zip|
      zip.get_output_stream('switch') { |io| io.write 'replacement' }
    end

    Zip::Overlay.open(base, middle) do |overlay|
      assert(overlay.directory?('switch'))
      assert_equal('child', overlay.read('switch/child.txt'))
    end

    Zip::Overlay.open(base, middle, top) do |overlay|
      refute(overlay.directory?('switch'))
      refute(overlay.include?('switch/child.txt'))
      assert_equal('replacement', overlay.read('switch'))
    end
  end

  def test_explicit_directory_layer_merges_old_and_new_descendants
    base = write_zip('base.zip') do |zip|
      zip.get_output_stream('dir/old.txt') { |io| io.write 'old' }
    end
    top = write_zip('top.zip') do |zip|
      zip.mkdir('dir')
      zip.get_output_stream('dir/new.txt') { |io| io.write 'new' }
    end

    Zip::Overlay.open(base, top) do |overlay|
      assert(overlay.directory?('dir'))
      assert_equal('old', overlay.read('dir/old.txt'))
      assert_equal('new', overlay.read('dir/new.txt'))
    end
  end

  def test_tombstone_then_directory_recreation_keeps_only_new_descendants
    base = write_zip('base.zip') do |zip|
      zip.mkdir('dir')
      zip.get_output_stream('dir/old.txt') { |io| io.write 'old' }
    end
    top = write_zip('top.zip') do |zip|
      zip.mkdir('dir')
      zip.get_output_stream('dir/new.txt') { |io| io.write 'new' }
    end

    Zip::Overlay.open([base, []], [top, ['dir/']]) do |overlay|
      assert_equal(%w[new.txt], overlay.children('dir'))
      refute(overlay.include?('dir/old.txt'))
    end
  end

  def test_inferred_directories_are_visible_to_listing_and_lookup
    base = write_zip('base.zip') do |zip|
      zip.get_output_stream('a/b/file.txt') { |io| io.write 'content' }
    end

    Zip::Overlay.open(base) do |overlay|
      assert_equal(%w[a], overlay.children)
      assert(overlay.directory?('a'))
      assert(overlay.directory?('a/b/'))
      assert_equal('a/', overlay.get_entry('a').name)
      assert_equal(%w[a/ a/b/ a/b/file.txt], overlay.map(&:name))
    end
  end

  def test_duplicate_names_in_one_layer_raise
    error = assert_raises(Zip::OverlayConflictError) do
      Zip::Overlay.new('test/data/DuplicateEntryNames.zip')
    end

    assert_match(/duplicate path in one overlay layer/, error.message)
  end

  def test_file_and_descendant_in_one_layer_raise
    path = write_zip('invalid.zip') do |zip|
      zip.get_output_stream('path') { |io| io.write 'file' }
      zip.get_output_stream('path/child.txt') { |io| io.write 'child' }
    end

    assert_raises(Zip::OverlayConflictError) do
      Zip::Overlay.new(path)
    end
  ensure
    FileUtils.rm_f(path)
  end

  def test_caller_owned_archives_are_not_closed
    path = write_zip('owned.zip') do |zip|
      zip.get_output_stream('file.txt') { |io| io.write 'content' }
    end

    Zip::File.open(path) do |archive|
      Zip::Overlay.open(archive) { |overlay| assert_equal('content', overlay.read('file.txt')) }
      refute(archive.closed?)
    end
  end

  def test_path_archives_are_closed_with_overlay
    path = write_zip('owned.zip') do |zip|
      zip.get_output_stream('file.txt') { |io| io.write 'content' }
    end

    overlay = Zip::Overlay.new(path)
    archive = overlay.instance_variable_get(:@layers).first.archive
    refute(archive.closed?)

    overlay.close
    assert(archive.closed?)
    assert(overlay.closed?)
    assert_raises(IOError) { overlay.children }
  end

  def test_manifest_tombstones_apply_after_all_layers
    base = write_zip('base.zip') do |zip|
      zip.get_output_stream('file.txt') { |io| io.write 'base' }
    end
    top = write_zip('top.zip') do |zip|
      zip.get_output_stream('file.txt') { |io| io.write 'top' }
    end

    overlay = Zip::Overlay.new(base, top, manifest: Manifest.new(['file.txt']))
    refute(overlay.include?('file.txt'))
  ensure
    overlay&.close
  end

  def test_directory_tombstone_without_trailing_slash_removes_descendants
    base = write_zip('base.zip') do |zip|
      zip.mkdir('dir')
      zip.get_output_stream('dir/child.txt') { |io| io.write 'child' }
    end
    top = write_zip('top.zip') do |zip|
      zip.get_output_stream('other.txt') { |io| io.write 'other' }
    end

    Zip::Overlay.open(base, [top, ['dir']]) do |overlay|
      refute(overlay.include?('dir'))
      refute(overlay.include?('dir/child.txt'))
      assert_equal('other', overlay.read('other.txt'))
    end
  end

  def test_invalid_tombstone_path_raises
    base = write_zip('base.zip') do |zip|
      zip.get_output_stream('file.txt') { |io| io.write 'content' }
    end

    assert_raises(ArgumentError) do
      Zip::Overlay.new([base, ['../escape.txt']])
    end
  ensure
    FileUtils.rm_f(base)
  end

  private

  def write_zip(name)
    path = File.join(OVERLAY_DIR, name)
    Zip::File.open(path, create: true) { |zip| yield zip }
    path
  end
end
