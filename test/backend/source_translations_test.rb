require 'test_helper'

class I18nBackendSourceTranslationsTest < I18n::TestCase
  class MemoizedBackend < I18n::Backend::Simple
    include I18n::Backend::Memoize
  end

  def setup
    super
    I18n.backend = I18n::Backend::Simple.new
  end

  def layer_one
    locales_dir + '/source/layer_one.yml'
  end

  def layer_two
    locales_dir + '/source/layer_two.yml'
  end

  def layer_three
    locales_dir + '/source/layer_three.yml'
  end

  def load_three_sources
    I18n.backend.load_source(:one, layer_one)
    I18n.backend.load_source(:two, layer_two)
    I18n.backend.load_source(:three, layer_three)
  end

  test "load_source: sources override each other in the order they were loaded" do
    load_three_sources
    assert_equal 'Hello from three', I18n.t(:greeting)
  end

  test "load_source: nested hashes are deep merged across sources" do
    load_three_sources
    assert_equal 'one a', I18n.t(:'nested.a')
    assert_equal 'two b', I18n.t(:'nested.b')
  end

  test "load_source: a non-hash value replaces a whole subtree" do
    load_three_sources
    assert_equal 'two replaced tree', I18n.t(:tree)
  end

  test "load_source: translations from the load path sit below all sources" do
    I18n.load_path = [locales_dir + '/en.yml']
    I18n.backend.load_source(:one, layer_one)
    assert_equal 'baz', I18n.t(:'foo.bar')
    I18n.backend.remove_source(:one)
    assert_equal 'baz', I18n.t(:'foo.bar')
  end

  test "remove_source: translations overridden by the removed source become visible again" do
    load_three_sources
    assert I18n.backend.remove_source(:two)

    assert_equal 'Hello from three', I18n.t(:greeting)
    assert_equal 'one b', I18n.t(:'nested.b')
    assert_equal 'one a', I18n.t(:'nested.a')
    assert_equal({ :leaf => 'one leaf' }, I18n.t(:tree))
  end

  test "remove_source: locales contributed only by the removed source disappear" do
    load_three_sources
    assert_includes I18n.available_locales, :fr

    I18n.backend.remove_source(:two)
    refute_includes I18n.available_locales, :fr
    assert_equal 'deux', I18n.t(:only_in_two, :locale => :fr, :default => 'deux')
  end

  test "remove_source: returns false and changes nothing for an unknown source" do
    load_three_sources
    assert_equal false, I18n.backend.remove_source(:nope)
    assert_equal 'Hello from three', I18n.t(:greeting)
    assert_equal 'two b', I18n.t(:'nested.b')
  end

  test "reload_source: replaces the translations in place, keeping the override order" do
    load_three_sources
    I18n.backend.reload_source(:one, locales_dir + '/source/layer_one_reloaded.yml')

    assert_equal 'Hello from three', I18n.t(:greeting)
    assert_equal 'one a reloaded', I18n.t(:'nested.a')
    assert_equal 'two b', I18n.t(:'nested.b')
  end

  test "reload_source: without filenames re-reads the files the source was loaded with" do
    load_three_sources
    I18n.backend.reload_source(:one)
    assert_equal 'one a', I18n.t(:'nested.a')
    assert_equal 'Hello from three', I18n.t(:greeting)
  end

  test "reload_source: raises for an unknown source when no filenames are given" do
    assert_raises(ArgumentError) { I18n.backend.reload_source(:nope) }
  end

  test "reload_source: a broken file raises and leaves the old translations untouched" do
    load_three_sources
    assert_raises(I18n::InvalidLocaleData) do
      I18n.backend.reload_source(:two, locales_dir + '/invalid/syntax.yml')
    end
    assert_equal 'two b', I18n.t(:'nested.b')
    assert_equal 'Hello from three', I18n.t(:greeting)
  end

  test "reload_source: a broken file among valid ones does not store half of the new translations" do
    load_three_sources
    assert_raises(I18n::InvalidLocaleData) do
      I18n.backend.reload_source(:two, layer_three, locales_dir + '/invalid/syntax.yml')
    end
    assert_equal 'two b', I18n.t(:'nested.b')
    assert_equal 'two replaced tree', I18n.t(:tree)
    assert_includes I18n.available_locales, :fr
  end

  test "memoize: memoized lookups and available_locales are reset when a source is removed" do
    I18n.backend = MemoizedBackend.new
    load_three_sources

    assert_equal 'two b', I18n.t(:'nested.b')
    assert_includes I18n.available_locales, :fr

    I18n.backend.remove_source(:two)
    assert_equal 'one b', I18n.t(:'nested.b')
    refute_includes I18n.available_locales, :fr
  end

  test "reload!: sources are replayed on top of the load path" do
    I18n.load_path = [locales_dir + '/en.yml']
    load_three_sources
    I18n.backend.reload!

    assert_equal 'baz', I18n.t(:'foo.bar')
    assert_equal 'Hello from three', I18n.t(:greeting)
    assert_equal 'two b', I18n.t(:'nested.b')
  end
end
