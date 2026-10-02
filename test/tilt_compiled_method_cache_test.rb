require_relative 'test_helper'
require 'thread'

describe 'tilt compiled method cache' do
  _CachingTemplate = Class.new(Tilt::Template) do
    def prepare
    end

    def precompiled_template(locals)
      data.inspect
    end
  end

  # A template whose compilation can be paused by the test, allowing other
  # threads to stack up on the same (template, locals) key.
  _BarrierCompileTemplate = Class.new(_CachingTemplate) do
    COMPILE_COUNT_MUTEX = Mutex.new

    def self.compile_count
      COMPILE_COUNT_MUTEX.synchronize { @compile_count ||= 0 }
    end

    def self.bump_compile_count!
      COMPILE_COUNT_MUTEX.synchronize { @compile_count = (@compile_count || 0) + 1 }
    end

    def compile_template_method(local_keys, scope_class=nil)
      gate = options[:compile_gate]
      if gate && local_keys == [:synchronized]
        gate[:entered] << Thread.current
        gate[:released].pop
      end
      self.class.bump_compile_count! if local_keys == [:synchronized]
      super
    end
  end

  before do
    @previous_default = Tilt.default_compiled_method_cache_size
    Tilt.default_compiled_method_cache_size = nil
  end

  after do
    Tilt.default_compiled_method_cache_size = @previous_default
  end

  it "keeps the cache unbounded when no capacity is configured" do
    template = _CachingTemplate.new { 'hey' }
    assert_nil template.compiled_method_cache_size

    50.times { |i| template.render(Object.new, "local#{i}" => 1) }

    stats = template.compiled_method_stats
    assert_equal 50, stats[:count]
    assert_equal 0, stats[:hits]
    assert_equal 50, stats[:misses]
    assert_equal 0, stats[:evictions]
  end

  it "bounds the resident method count and evicts least recently used methods" do
    untouched = _CachingTemplate.new(:compiled_method_cache_size => 2) { 'hey' }
    2.times { |i| untouched.render(Object.new, "u#{i}" => 1) }
    untouched.render(Object.new, 'u2' => 1) # evicts u0 (never touched)
    assert_equal 2, untouched.compiled_methods_count
    assert_equal 1, untouched.compiled_methods_evicted
    untouched.render(Object.new, 'u0' => 1) # u0 recompiles (miss), evicts u1
    assert_equal 2, untouched.compiled_methods_evicted

    touched = _CachingTemplate.new(:compiled_method_cache_size => 2) { 'hey' }
    2.times { |i| touched.render(Object.new, "t#{i}" => 1) }
    touched.render(Object.new, 't0' => 1)   # t0 is now most recently used
    assert_equal 1, touched.compiled_method_hits
    touched.render(Object.new, 't2' => 1)   # must evict t1, not t0
    touched.render(Object.new, 't0' => 1)   # t0 retained -> a hit
    assert_equal 2, touched.compiled_method_hits
    assert_equal 1, touched.compiled_methods_evicted
    assert_equal 2, touched.compiled_methods_count
  end

  it "falls back to the global default capacity" do
    Tilt.default_compiled_method_cache_size = 3

    template = _CachingTemplate.new { 'hey' }
    assert_equal 3, template.compiled_method_cache_size

    10.times { |i| template.render(Object.new, "local#{i}" => 1) }
    assert_operator template.compiled_methods_count, :<=, 3
    assert_equal 7, template.compiled_methods_evicted
  end

  it "lets per-template capacity override the global default" do
    Tilt.default_compiled_method_cache_size = 100
    template = _CachingTemplate.new(:max_compiled_methods => 2) { 'hey' }

    5.times { |i| template.render(Object.new, "local#{i}" => 1) }
    assert_equal 2, template.compiled_methods_count
    assert_equal 3, template.compiled_method_evictions
  end

  it "accepts capacity changes at runtime and immediately evicts" do
    template = _CachingTemplate.new { 'hey' }
    8.times { |i| template.render(Object.new, "local#{i}" => 1) }
    assert_equal 8, template.compiled_methods_count

    template.compiled_method_cache_size = 3
    assert_equal 3, template.compiled_methods_count
    assert_equal 5, template.compiled_methods_evicted

    template.compiled_method_cache_size = nil
    5.times { |i| template.render(Object.new, "new#{i}" => 1) }
    assert_equal 8, template.compiled_methods_count
  end

  it "clears compiled methods but keeps the template renderable" do
    template = _CachingTemplate.new(:compiled_method_cache_size => 10) { 'hey' }
    3.times { |i| template.render(Object.new, "local#{i}" => 1) }
    template.render(Object.new, 'local0' => 1)
    assert_equal 1, template.compiled_method_hits

    assert_same template, template.clear_compiled_methods
    assert_equal 0, template.compiled_methods_count
    stats = template.compiled_method_stats
    assert_equal 0, stats[:count]
    assert_equal 0, stats[:hits]
    assert_equal 0, stats[:evictions]

    # Old Template object recompiles on demand and keeps working.
    assert_equal 'hey', template.render(Object.new, 'local0' => 1)
    assert_equal 1, template.compiled_methods_count
  end

  it "does not let a failed compilation occupy capacity" do
    failing = Class.new(Tilt::Template) do
      def prepare
      end

      def precompiled_template(locals)
        raise 'boom' if locals.map(&:to_s).include?('bad')
        data.inspect
      end
    end

    template = failing.new(:compiled_method_cache_size => 3) { 'hey' }
    template.render(Object.new, 'good' => 1)

    10.times do
      assert_raises(RuntimeError) { template.render(Object.new, 'bad' => 1) }
    end

    stats = template.compiled_method_stats
    assert_equal 1, stats[:count]
    assert_equal 0, stats[:evictions]
    assert_equal 11, stats[:misses]
    assert_equal 'hey', template.render(Object.new, 'good' => 1)
    assert_equal 1, template.compiled_method_hits
  end

  it "publishes a single result for concurrent first compilation" do
    gate = {
      :entered  => Queue.new,
      :released => Queue.new,
    }
    template = _BarrierCompileTemplate.new(:compile_gate => gate) { 'once' }
    main_thread = Thread.current
    compile_attempts = Queue.new

    threads = Array.new(8) do
      Thread.new do
        begin
          # Compilation of this key pauses inside compile_template_method.
          result = template.render(Object.new, :synchronized => 1)
          compile_attempts << result
        rescue => boom
          main_thread.raise(boom)
        end
      end
    end

    # Wait for the single compilation to start, then prove no other thread
    # is compiling (the barrier template enters compilation exactly once).
    gate[:entered].pop
    sleep 0.1
    assert_equal 0, gate[:entered].size

    gate[:released] << true
    threads.each(&:join)

    results = Array.new(8) { compile_attempts.pop }
    assert_equal Array.new(8, 'once'), results
    assert_equal 1, template.compiled_methods_count
    assert_equal 1, template.compiled_method_stats[:misses]
    assert_equal 7, template.compiled_method_stats[:hits]
    assert_equal 1, _BarrierCompileTemplate.compile_count
  end

  it "keeps an in-progress render usable while the cache is evicted" do
    $tilt_cache_hold = Queue.new
    $tilt_cache_proceed = Queue.new

    blocking = Class.new(Tilt::Template) do
      def prepare
      end

      def precompiled_template(locals)
        # Pause during evaluation, after compiled_method returned and the
        # cache lock was released. The running thread already holds the
        # (now possibly evicted) UnboundMethod on its stack.
        "($tilt_cache_hold << true; $tilt_cache_proceed.pop) if locals.key?(:hold); " + data.inspect
      end
    end

    template = blocking.new(:compiled_method_cache_size => 1) { 'held' }

    render_thread = Thread.new { template.render(Object.new, :hold => 1) }
    $tilt_cache_hold.pop

    # Evict the method the paused render is using, repeatedly.
    10.times { |i| template.render(Object.new, "flood#{i}" => 1) }
    assert_equal 1, template.compiled_methods_count
    assert_operator template.compiled_methods_evicted, :>=, 9
    template.clear_compiled_methods

    $tilt_cache_proceed << true
    assert_equal 'held', render_thread.value
  end

  it "survives interleaved renders and clears across many threads" do
    template = _CachingTemplate.new(:compiled_method_cache_size => 8) { 'x' }
    stop = Class.new { attr_accessor :flag }.new
    errors = Queue.new

    workers = Array.new(6) do |worker|
      Thread.new do
        begin
          i = 0
          until stop.flag
            locals = { "w#{worker}_l#{i % 25}" => 1 }
            unless template.render(Object.new, locals) == 'x'
              raise 'unexpected render result'
            end
            template.clear_compiled_methods if (i += 1) % 37 == 0
          end
        rescue => boom
          errors << boom
          stop.flag = true
        end
      end
    end

    sleep 1.0
    stop.flag = true
    workers.each(&:join)
    collected = []
    collected << errors.pop until errors.empty?
    assert_empty collected

    assert_operator template.compiled_methods_count, :<=, 8
  end

  it "returns the resident count to the capacity after a locals flood" do
    template = _CachingTemplate.new(:compiled_method_cache_size => 5) { 'flood' }

    1_000.times { |i| template.render(Object.new, "local#{i}" => 1) }

    assert_equal 5, template.compiled_methods_count
    assert_equal 995, template.compiled_methods_evicted

    200.times { |i| template.render(Object.new, "local#{800 + i}" => 1) }
    assert_equal 5, template.compiled_methods_count
  end
end
