require_relative 'test_helper'

describe 'Tilt::Template compile cache' do
  # Simple two-phase barrier for synchronizing threads in tests.
  class CompileCacheBarrier
    def initialize(count)
      @count = count
      @waiting = 0
      @mutex = Mutex.new
      @cv = ConditionVariable.new
    end

    def wait
      @mutex.synchronize do
        @waiting += 1
        if @waiting >= @count
          @waiting = 0
          @cv.broadcast
        else
          @cv.wait(@mutex)
        end
      end
    end
  end

  def new_template(&block)
    Tilt::StringTemplate.new(&block)
  end

  it "is unbounded by default and does not evict" do
    template = new_template { 'x' }
    assert_nil template.compile_cache_capacity
    50.times { |i| template.render(Object.new, "k#{i}".to_sym => i) }
    stats = template.compile_cache_stats
    assert_equal 50, stats[:size]
    assert_equal 0, stats[:evictions]
  end

  it "limits cached compiled methods to the configured capacity" do
    template = new_template { 'x' }
    template.compile_cache_capacity = 5
    20.times { |i| template.render(Object.new, "k#{i}".to_sym => i) }
    stats = template.compile_cache_stats
    assert_equal 5, stats[:size]
    assert_equal 15, stats[:evictions]
  end

  it "does not cache compiled methods when capacity is 0" do
    template = new_template { 'x' }
    template.compile_cache_capacity = 0
    3.times { template.render }
    stats = template.compile_cache_stats
    assert_equal 0, stats[:size]
    assert_equal 0, stats[:hits]
  end

  it "counts cache hits" do
    template = new_template { 'x' }
    3.times { template.render }
    assert_equal 2, template.compile_cache_stats[:hits]
  end

  it "evicts the least recently used entry" do
    template = new_template { 'x' }
    template.compile_cache_capacity = 2
    template.render(Object.new, :a => 1)
    template.render(Object.new, :b => 1)
    template.render(Object.new, :a => 1) # refresh :a
    template.render(Object.new, :c => 1) # evicts :b
    stats = template.compile_cache_stats
    assert_equal 2, stats[:size]
    assert_equal 1, stats[:evictions]
    assert_equal 1, stats[:hits]

    template.render(Object.new, :a => 1) # still cached
    assert_equal 2, template.compile_cache_stats[:hits]
    template.render(Object.new, :b => 1) # was evicted, recompiles
    assert_equal 2, template.compile_cache_stats[:evictions]
  end

  it "supports a class-level default capacity inherited by subclasses" do
    klass = Class.new(Tilt::StringTemplate)
    klass.compile_cache_capacity = 2
    template = klass.new { 'x' }
    assert_equal 2, template.compile_cache_capacity
    5.times { |i| template.render(Object.new, "k#{i}".to_sym => i) }
    assert_equal 2, template.compile_cache_stats[:size]
  end

  it "allows a per-instance capacity to override the class-level setting" do
    klass = Class.new(Tilt::StringTemplate)
    klass.compile_cache_capacity = 1
    template = klass.new { 'x' }
    template.compile_cache_capacity = 3
    3.times { |i| template.render(Object.new, "k#{i}".to_sym => i) }
    assert_equal 3, template.compile_cache_stats[:size]
  end

  it "does not store failed compilations or evict existing entries" do
    template = new_template { 'x' }
    template.compile_cache_capacity = 1
    template.render
    assert_raises(RuntimeError) { template.render(Object.new, :"not-valid" => 1) }
    stats = template.compile_cache_stats
    assert_equal 1, stats[:size]
    assert_equal 0, stats[:evictions]
    assert_equal 'x', template.render
  end

  it "recompiles after clear so the template still renders" do
    template = new_template { 'hello' }
    assert_equal 'hello', template.render
    template.clear_compile_cache
    assert_equal 0, template.compile_cache_stats[:size]
    assert_equal 'hello', template.render
    assert_equal 1, template.compile_cache_stats[:size]
  end

  it "publishes a single compiled method for concurrent first compiles" do
    barrier = CompileCacheBarrier.new(8)
    compiles = 0
    compiles_lock = Mutex.new
    klass = Class.new(Tilt::StringTemplate) do
      define_method(:compiled_method) do |*args|
        barrier.wait # line all threads up before the cache lookup
        super(*args)
      end
      define_method(:compile_template_method) do |*args|
        compiles_lock.synchronize { compiles += 1 }
        super(*args)
      end
    end
    template = klass.new { 'hello' }
    results = 8.times.map do
      Thread.new { template.render(Object.new, :name => 'world') }
    end.map(&:value)
    assert_equal ['hello'] * 8, results
    assert_equal 1, compiles
    assert_equal 1, template.compile_cache_stats[:size]
    assert_equal 7, template.compile_cache_stats[:hits]
  end

  it "does not break in-flight renders when entries are evicted or cleared" do
    fetched = CompileCacheBarrier.new(2)
    release = CompileCacheBarrier.new(2)
    first = true
    klass = Class.new(Tilt::StringTemplate) do
      define_method(:compiled_method) do |*args|
        method = super(*args)
        if first
          first = false
          fetched.wait # method is in hand, but not yet bound/called
          release.wait # let the other thread clear and evict
        end
        method
      end
    end
    template = klass.new { 'hello' }
    template.compile_cache_capacity = 1

    result = nil
    thread = Thread.new { result = template.render }
    fetched.wait
    template.clear_compile_cache
    template.render(Object.new, :a => 1) # refills and would evict the old entry
    release.wait
    assert_equal 'hello', thread.value
    assert_equal 1, template.compile_cache_stats[:size]
  end

  it "keeps the method count at capacity under many locals combinations" do
    template = new_template { 'x' }
    template.compile_cache_capacity = 4
    threads = 4.times.map do |t|
      Thread.new do
        25.times { |i| template.render(Object.new, "k#{t * 25 + i}".to_sym => i) }
      end
    end
    threads.each(&:join)
    stats = template.compile_cache_stats
    assert_equal 4, stats[:size]
    assert stats[:evictions] > 0
  end
end
