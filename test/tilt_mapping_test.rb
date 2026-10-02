require_relative 'test_helper'
require 'timeout'

describe 'tilt/mapping' do
  _Stub = Class.new
  _Stub2 = Class.new

  before do
    @mapping = Tilt::Mapping.new
  end

  it "registered?" do
    @mapping.register(_Stub, 'foo', 'bar')
    assert @mapping.registered?('foo')
    assert @mapping.registered?('bar')
    refute @mapping.registered?('baz')
  end

  it "unregister" do
    @mapping.register(_Stub, 'foo', 'bar', 'baz')
    @mapping.unregister('baz')
    assert @mapping.registered?('foo')
    assert @mapping.registered?('bar')
    refute @mapping.registered?('baz')
  end

  it "lookups on registered" do
    @mapping.register(_Stub, 'foo', 'bar')
    assert_equal _Stub, @mapping['foo']
    assert_equal _Stub, @mapping['bar']
    assert_equal _Stub, @mapping['hello.foo']
    assert_nil @mapping['foo.baz']
  end

  it "creates templates through the mapping" do
    template_class = Class.new do
      attr_reader :file
      def initialize(file, *)
        @file = file
      end
    end
    @mapping.register(template_class, 'fake')
    template = @mapping.new('hello.fake')

    assert_kind_of template_class, template
    assert_equal 'hello.fake', template.file
  end

  it "can be dup'd" do
    @mapping.register(_Stub, 'foo')
    other = @mapping.dup
    assert other.registered?('foo')

    # @mapping doesn't leak to other
    @mapping.register(_Stub, 'bar')
    refute other.registered?('bar')

    # other doesn't leak to @mapping
    other.register(_Stub, 'baz')
    refute @mapping.registered?('baz')
  end

  it "snapshots lazy candidate lists independently of the source mapping" do
    @mapping.register_lazy('SnapshotFakeA', 'snapshot_fake_a', 'fake')
    @mapping.register_lazy('SnapshotFakeB', 'snapshot_fake_b', 'fake')
    snapshot = @mapping.snapshot

    snapshot.prefer_lazy('SnapshotFakeA', 'fake')

    assert_equal ['SnapshotFakeB', 'SnapshotFakeA'],
      @mapping.lazy_map['fake'].map(&:first)
    assert_equal ['SnapshotFakeA', 'SnapshotFakeB'],
      snapshot.lazy_map['fake'].map(&:first)
  end

  it "creates an independent snapshot from another mapping" do
    source = Tilt::Mapping.new(@mapping)
    source.register(_Stub, 'source')
    snapshot = Tilt::Mapping.new(source, :fallback_policy => :raise)

    snapshot.register(_Stub2, 'snapshot')

    assert source.registered?('source')
    refute @mapping.registered?('source')
    refute source.registered?('snapshot')
    assert snapshot.registered?('snapshot')
    assert_equal :raise, snapshot.fallback_policy
  end

  it "does not snapshot a runtime-resolved lazy engine" do
    @mapping.register_lazy('ResolvedFakeB', 'resolved_fake_b', 'fake')
    @mapping.register_lazy('ResolvedFakeA', 'resolved_fake_a', 'fake')

    require_fake = proc do |file|
      raise LoadError, file unless file == 'resolved_fake_b'
      Object.const_set(:ResolvedFakeB, Class.new) if file == 'resolved_fake_b'
      true
    end
    @mapping.stub(:require, require_fake) { @mapping['hello.fake'] }
    snapshot = @mapping.snapshot
    refute snapshot.template_map.key?('fake')

    require_fake = proc do |file|
      raise LoadError, file unless file == 'resolved_fake_a'
      Object.const_set(:ResolvedFakeA, Class.new)
      true
    end
    template_class = nil
    snapshot.stub(:require, require_fake) do
      template_class = snapshot['hello.fake']
    end

    assert_equal Object.const_get(:ResolvedFakeA), template_class
  ensure
    Object.send :remove_const, :ResolvedFakeA if defined?(::ResolvedFakeA)
    Object.send :remove_const, :ResolvedFakeB if defined?(::ResolvedFakeB)
  end

  it "snapshots the global mapping without changing its configuration" do
    snapshot = Tilt.default_mapping.snapshot
    assert Tilt.default_mapping.registered?('md')
    assert snapshot.registered?('md')

    snapshot.unregister('md')
    refute snapshot.registered?('md')
    assert Tilt.default_mapping.registered?('md')
  end

  it "rejects an unknown lazy load fallback policy" do
    assert_raises(ArgumentError) do
      @mapping.fallback_policy = :sometimes
    end
  end

  it "accepts :fallback as the fallback policy option" do
    mapping = Tilt::Mapping.new(:fallback => :raise)
    assert_equal :raise, mapping.fallback_policy
  end

  it "reorders lazy candidates without duplicating them" do
    @mapping.register_lazy('OrderFakeA', 'order_fake_a', 'fake')
    @mapping.register_lazy('OrderFakeB', 'order_fake_b', 'fake')

    @mapping.prefer_lazy('OrderFakeA', 'fake')

    assert_equal [['OrderFakeA', 'order_fake_a'],
                  ['OrderFakeB', 'order_fake_b']], @mapping.lazy_map['fake']
  end

  it "orders multiple lazy candidates" do
    @mapping.register_lazy('OrderFakeC', 'order_fake_c', 'fake')
    @mapping.register_lazy('OrderFakeB', 'order_fake_b', 'fake')
    @mapping.register_lazy('OrderFakeA', 'order_fake_a', 'fake')

    @mapping.order_lazy('fake', 'OrderFakeA', 'OrderFakeC')

    assert_equal ['OrderFakeA', 'OrderFakeC', 'OrderFakeB'],
      @mapping.lazy_map['fake'].map(&:first)
  end

  it "disables one lazy candidate while retaining other candidates" do
    @mapping.register_lazy('DisableFakeA', 'disable_fake_a', 'fake')
    @mapping.register_lazy('DisableFakeB', 'disable_fake_b', 'fake')

    @mapping.unregister_lazy('DisableFakeA', 'fake')

    assert_equal [['DisableFakeB', 'disable_fake_b']],
      @mapping.lazy_map['fake']
  end

  it "disables all lazy candidates for an extension" do
    @mapping.register_lazy('DisableFakeA', 'disable_fake_a', 'fake')
    @mapping.register(_Stub, 'fake')

    @mapping.unregister_lazy(nil, 'fake')

    assert_equal _Stub, @mapping['fake']
    assert_empty @mapping.lazy_map['fake']
  end

  it "disables lazy candidates with the extension-only form" do
    @mapping.register_lazy('DisableFakeA', 'disable_fake_a', 'fake')

    @mapping.unregister_lazy('fake')

    refute @mapping.registered?('fake')
  end

  it "#extensions_for" do
    @mapping.register(_Stub, 'foo', 'bar')
    assert_equal ['foo', 'bar'].sort, @mapping.extensions_for(_Stub).sort
  end

  it "supports old-style #register" do
    @mapping.register('foo', _Stub)
    assert_equal _Stub, @mapping['foo']
  end

  describe "lazy with one template class" do
    before do
      @mapping.register_lazy('MyTemplate', 'my_template', 'mt')
      @loaded_before = $LOADED_FEATURES.dup
    end

    after do
      Object.send :remove_const, :MyTemplate if defined? ::MyTemplate
      $LOADED_FEATURES.replace(@loaded_before)
    end

    it "registered?" do
      assert @mapping.registered?('mt')
    end

    it "unregister" do
      @mapping.unregister('mt')
      refute @mapping.registered?('mt')
    end

    it "#extensions_for" do
      assert_equal ['mt'], @mapping.extensions_for('MyTemplate')
    end

    it "basic lookup" do
      req = proc do |file|
        assert_equal 'my_template', file
        class ::MyTemplate; end
        true
      end

      @mapping.stub :require, req do
        klass = @mapping['hello.mt']
        assert_equal ::MyTemplate, klass
      end
    end

    it "doesn't require when template class is present" do
      class ::MyTemplate; end

      req = proc do |file|
        flunk "#require shouldn't be called"
      end

      @mapping.stub :require, req do
        klass = @mapping['hello.mt']
        assert_equal ::MyTemplate, klass
      end
    end

    it "doesn't require when the template class is autoloaded, and then defined" do
      $LOAD_PATH << __dir__
      begin
        Object.autoload :MyTemplate, 'mytemplate'
        did_load = require 'mytemplate'
      ensure
        $LOAD_PATH.delete(__dir__)
      end
      assert did_load, "mytemplate wasn't freshly required"

      req = proc do |file|
        flunk "#require shouldn't be called"
      end

      @mapping.stub :require, req do
        klass = @mapping['hello.mt']
        assert_equal ::MyTemplate, klass
      end
    end

    it "raises NameError when the class name is defined" do
      req = proc do |file|
        # do nothing
      end

      @mapping.stub :require, req do
        assert_raises(NameError) do
          @mapping['hello.mt']
        end
      end
    end
  end

  describe "lazy with two template classes" do
    before do
      @mapping.register_lazy('MyTemplate1', 'my_template1', 'mt')
      @mapping.register_lazy('MyTemplate2', 'my_template2', 'mt')
    end

    after do
      Object.send :remove_const, :MyTemplate1 if defined? ::MyTemplate1
      Object.send :remove_const, :MyTemplate2 if defined? ::MyTemplate2
    end

    it "registered?" do
      assert @mapping.registered?('mt')
    end

    it "only attempt to load the last template" do
      req = proc do |file|
        assert_equal 'my_template2', file
        class ::MyTemplate2; end
        true
      end

      @mapping.stub :require, req do
        klass = @mapping['hello.mt']
        assert_equal ::MyTemplate2, klass
      end
    end

    it "uses the first template if it's present" do
      class ::MyTemplate1; end

      req = proc do |file|
        flunk
      end

      @mapping.stub :require, req do
        klass = @mapping['hello.mt']
        assert_equal ::MyTemplate1, klass
      end
    end

    it "falls back when LoadError is thrown" do
      req = proc do |file|
        raise LoadError unless file == 'my_template1'
        class ::MyTemplate1; end
        true
      end

      @mapping.stub :require, req do
        klass = @mapping['hello.mt']
        assert_equal ::MyTemplate1, klass
      end
    end

    it "raises the first LoadError when everything fails" do
      req = proc do |file|
        raise LoadError, file
      end

      @mapping.stub :require, req do
        err = assert_raises(LoadError) do
          @mapping['hello.mt']
        end

        assert_equal 'my_template2', err.message
      end
    end

    it "handles autoloaded constants" do
      Object.autoload :MyTemplate2, 'my_template2'
      class ::MyTemplate1; end

      assert_equal MyTemplate1, @mapping['hello.mt']
    end
  end

  describe "lazy fallback policy" do
    before do
      @mapping = Tilt::Mapping.new
      @mapping.register_lazy('FallbackFakeB', 'fallback_fake_b', 'fake')
      @mapping.register_lazy('FallbackFakeA', 'fallback_fake_a', 'fake')
      @snapshot = @mapping.snapshot
    end

    after do
      Object.send :remove_const, :FallbackFakeA if defined?(::FallbackFakeA)
      Object.send :remove_const, :FallbackFakeB if defined?(::FallbackFakeB)
    end

    it "falls back from LoadError by default" do
      require_fake = proc do |file|
        if file == 'fallback_fake_b'
          Object.const_set(:FallbackFakeB, Class.new)
          true
        else
          raise LoadError, file
        end
      end

      @snapshot.stub :require, require_fake do
        template_class = @snapshot['hello.fake']
        assert_equal Object.const_get(:FallbackFakeB), template_class
      end
    end

    it "does not treat other errors as fallback candidates by default" do
      require_fake = proc do |file|
        raise RuntimeError, file if file == 'fallback_fake_a'
        Object.const_set(:FallbackFakeB, Class.new)
      end

      @snapshot.stub :require, require_fake do
        err = assert_raises(RuntimeError) { @snapshot['hello.fake'] }
        assert_equal 'fallback_fake_a', err.message
      end

      refute @snapshot.template_map.key?('fake')
    end

    it "can fall back from any standard error" do
      @snapshot.fallback_policy = :any
      require_fake = proc do |file|
        if file == 'fallback_fake_b'
          Object.const_set(:FallbackFakeB, Class.new)
        else
          raise RuntimeError, file
        end
        true
      end

      @snapshot.stub :require, require_fake do
        template_class = @snapshot['hello.fake']
        assert_equal Object.const_get(:FallbackFakeB), template_class
      end
    end

    it "can disable fallback" do
      @snapshot.fallback_policy = :raise
      require_fake = proc do |file|
        raise LoadError, file if file == 'fallback_fake_a'
        Object.const_set(:FallbackFakeB, Class.new)
      end

      @snapshot.stub :require, require_fake do
        err = assert_raises(LoadError) { @snapshot['hello.fake'] }
        assert_equal 'fallback_fake_a', err.message
      end
    end

    it "passes the failure and candidate to a callable policy" do
      policy_candidates = nil
      @snapshot.fallback_policy = proc do |error, class_name, file, ext|
        policy_candidates = [error.class, class_name, file, ext]
        true
      end
      require_fake = proc do |file|
        if file == 'fallback_fake_b'
          Object.const_set(:FallbackFakeB, Class.new)
        else
          raise LoadError, file
        end
        true
      end

      @snapshot.stub :require, require_fake do
        template_class = @snapshot['hello.fake']
        assert_equal Object.const_get(:FallbackFakeB), template_class
      end
      assert_equal [LoadError, 'FallbackFakeA', 'fallback_fake_a', 'fake'],
        policy_candidates
    end

    it "raises the preferred candidate error and leaves no resolved mapping" do
      require_fake = proc { |file| raise LoadError, file }

      @snapshot.stub :require, require_fake do
        err = assert_raises(LoadError) { @snapshot['hello.fake'] }
        assert_equal 'fallback_fake_a', err.message
      end

      refute @snapshot.template_map.key?('fake')
      assert_equal [['FallbackFakeA', 'fallback_fake_a'],
                    ['FallbackFakeB', 'fallback_fake_b']],
        @snapshot.lazy_map['fake']
    end
  end

  it "keeps concurrent first loads on each snapshot's own preference" do
    concurrent_mapping = Class.new(Tilt::Mapping) do
      attr_accessor :require_callback

      def require(file)
        @require_callback.call(file)
      end
    end

    base = Tilt::Mapping.new
    base.register_lazy('ConcurrentFakeB', 'concurrent_fake_b', 'fake')
    base.register_lazy('ConcurrentFakeA', 'concurrent_fake_a', 'fake')
    app_a = concurrent_mapping.new(base)
    app_b = concurrent_mapping.new(base)
    app_b.prefer_lazy('ConcurrentFakeB', 'fake')

    started = Queue.new
    release = Queue.new
    calls = {:a => [], :b => []}
    lock = Mutex.new

    loader = proc do |app, file|
      lock.synchronize { calls[app] << file }
      started << app
      release.pop

      case file
      when 'concurrent_fake_a'
        Object.const_set(:ConcurrentFakeA, Class.new)
      when 'concurrent_fake_b'
        Object.const_set(:ConcurrentFakeB, Class.new)
      end
      true
    end

    app_a.require_callback = proc { |file| loader.call(:a, file) }
    app_b.require_callback = proc { |file| loader.call(:b, file) }

    result = nil
    Timeout.timeout(2) do
      thread_a = Thread.new { app_a['hello.fake'] }
      thread_b = Thread.new { app_b['hello.fake'] }
      2.times { started.pop }
      2.times { release << :continue }
      result = [thread_a.value, thread_b.value]
    end

    assert_equal [Object.const_get(:ConcurrentFakeA),
                  Object.const_get(:ConcurrentFakeB)], result
    assert_equal ['concurrent_fake_a'], calls[:a]
    assert_equal ['concurrent_fake_b'], calls[:b]
  ensure
    Object.send :remove_const, :ConcurrentFakeA if defined?(::ConcurrentFakeA)
    Object.send :remove_const, :ConcurrentFakeB if defined?(::ConcurrentFakeB)
  end

  it "raises NameError on invalid class name" do
    @mapping.register_lazy '#foo', 'my_template', 'mt'

    req = proc do |file|
      # do nothing
    end

    @mapping.stub :require, req do
      assert_raises(NameError) do
        @mapping['hello.mt']
      end
    end
  end

  describe "#templates_for" do
    before do
      @mapping.register _Stub, 'a'
      @mapping.register _Stub2, 'b'
    end

    it "handles multiple engines" do
      assert_equal [_Stub2, _Stub], @mapping.templates_for('hello/world.a.b')
    end
  end
end
