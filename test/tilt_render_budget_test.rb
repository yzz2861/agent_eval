require_relative 'test_helper'
require 'tilt/erb'

describe 'tilt/render_budget' do
  it "is not active outside of a budget context" do
    assert_nil Tilt.render_budget
    template = Tilt::ERBTemplate.new { 'plain' }
    assert_equal 'plain', template.render
  end

  it "is active inside the context and restored afterwards" do
    budget = Tilt::RenderBudget.new(:max_depth => 5)
    seen = nil
    Tilt.with_render_budget(budget) do
      seen = Tilt.render_budget
      Tilt::ERBTemplate.new { 'ok' }.render
    end
    assert_same budget, seen
    assert_nil Tilt.render_budget
  end

  it "counts a single render against the cumulative limit" do
    budget = Tilt::RenderBudget.new(:max_renders => 2)
    template = Tilt::ERBTemplate.new { 'x' }

    Tilt.with_render_budget(budget) do
      template.render
      assert_equal 1, budget.render_count
      template.render
      assert_equal 2, budget.render_count
      assert_raises(Tilt::RenderBudgetExceeded) { template.render }
    end

    assert_equal 2, budget.render_count
  end

  it "stops mutual recursion immediately via a small depth budget" do
    $rb_mutual_templates = {}
    $rb_mutual_templates[:outer] =
      Tilt::ERBTemplate.new { '<%= $rb_mutual_templates[:inner].render %>' }
    $rb_mutual_templates[:inner] =
      Tilt::ERBTemplate.new { '<%= $rb_mutual_templates[:outer].render %>' }

    budget = Tilt::RenderBudget.new(:max_depth => 3)

    error = assert_raises(Tilt::RenderBudgetExceeded) do
      Tilt.with_render_budget(budget) { $rb_mutual_templates[:outer].render }
    end

    assert_equal :depth, error.reason
    assert_equal 4, error.call_chain.length
    assert_equal 3, budget.render_count
    assert_equal 0, budget.current_depth
  ensure
    $rb_mutual_templates = nil
  end

  it "includes a bounded call chain on the exception" do
    budget = Tilt::RenderBudget.new(:max_depth => 10,
                                   :max_chain_entries => 5)

    link_class = Class.new(Tilt::Template) do
      attr_accessor :child

      def evaluate(scope, locals, &block)
        child ? child.render(scope, locals, &block) : ''
      end

      def prepare; end
    end

    deep = Array.new(20) { link_class.new { 'link' } }
    deep.each_with_index { |tmpl, i| tmpl.child = deep[i + 1] }

    error = assert_raises(Tilt::RenderBudgetExceeded) do
      Tilt.with_render_budget(budget) { deep.first.render }
    end

    assert_equal 5, error.call_chain.length
    assert_equal '...', error.call_chain.first
    assert_includes error.message, '...'
    assert_equal :depth, error.reason
    assert_equal 0, budget.current_depth
  end

  it "returns depth after an ordinary exception during rendering" do
    raising = Tilt::ERBTemplate.new { '<% raise ArgumentError, "boom" %>' }
    budget = Tilt::RenderBudget.new(:max_depth => 5)

    assert_raises(ArgumentError) do
      Tilt.with_render_budget(budget) { raising.render }
    end

    assert_equal 0, budget.current_depth
    assert_equal 1, budget.render_count

    # The released depth is available again; the depth budget is not
    # permanently consumed.
    Tilt.with_render_budget(budget) do
      Tilt::ERBTemplate.new { 'ok' }.render
    end
  end

  it "cannot bypass the cumulative limit by repeatedly entering/exiting" do
    budget = Tilt::RenderBudget.new(:max_renders => 1)
    template = Tilt::ERBTemplate.new { 'x' }

    Tilt.with_render_budget(budget) do
      template.render
      assert_raises(Tilt::RenderBudgetExceeded) { template.render }
    end

    # A later context with the same budget is still capped.
    assert_raises(Tilt::RenderBudgetExceeded) do
      Tilt.with_render_budget(budget) { template.render }
    end
  end

  it "is re-entrant for the same budget and keeps one chain" do
    budget = Tilt::RenderBudget.new(:max_depth => 3)
    scope = Object.new
    template = Tilt::ERBTemplate.new do
      '<% @depth_during = Tilt.render_budget.current_depth %>nested'
    end

    Tilt.with_render_budget(budget) do
      Tilt.with_render_budget(budget) do
        assert_same budget, Tilt.render_budget
        template.render(scope)
      end
      assert_equal 1, scope.instance_variable_get(:@depth_during)
      assert_equal 0, budget.current_depth
    end

    assert_equal 0, budget.current_depth
  end

  describe 'pipeline' do
    before do
      @mapping = Tilt.default_mapping.dup
      @pipeline_class = @mapping.register_pipeline('str.erb')
    end

    it "counts every pipeline stage as a render" do
      template = @pipeline_class.new { |t| "<%= '\#{1}' %>" }
      budget = Tilt::RenderBudget.new(:max_renders => 1)

      error = assert_raises(Tilt::RenderBudgetExceeded) do
        Tilt.with_render_budget(budget) { template.render }
      end

      assert_equal :renders, error.reason
      assert_equal 1, budget.render_count
    end

    it "allows a complete pipeline within a sufficient depth budget" do
      template = @pipeline_class.new { |t| "<%= '\#{7}' %>" }
      budget = Tilt::RenderBudget.new(:max_depth => 3, :max_renders => 10)

      result = Tilt.with_render_budget(budget) { template.render }
      assert_equal '7', result
      assert_equal 3, budget.render_count
      assert_equal 0, budget.current_depth
    end
  end

  describe 'fibers' do
    it "keeps separate budgets and chains for concurrent fibers" do
      budget_a = Tilt::RenderBudget.new(:max_renders => 2)
      budget_b = Tilt::RenderBudget.new(:max_depth => 10)
      template = Tilt::ERBTemplate.new { 'x' }

      fiber_a = Fiber.new do
        Tilt.with_render_budget(budget_a) do
          2.times { template.render }
          assert_raises(Tilt::RenderBudgetExceeded) { template.render }
        end
      end

      fiber_b = Fiber.new do
        Tilt.with_render_budget(budget_b) do
          5.times { template.render }
          assert_equal 5, budget_b.render_count
        end
      end

      fiber_a.resume
      fiber_b.resume

      assert_equal 2, budget_a.render_count
      assert_equal 5, budget_b.render_count
      assert_nil Tilt.render_budget
    end

    it "does not inherit the parent fiber's budget by default" do
      budget = Tilt::RenderBudget.new(:max_depth => 5)
      captured = nil

      Tilt.with_render_budget(budget) do
        Fiber.new { captured = Tilt.render_budget }.resume
      end

      assert_nil captured
    end

    it "can share one budget explicitly across fibers" do
      budget = Tilt::RenderBudget.new(:max_renders => 5)
      template = Tilt::ERBTemplate.new { 'x' }

      fibers = Array.new(3) do
        Fiber.new do
          Tilt.with_render_budget(budget) do
            template.render
          end
        end
      end

      fibers.each(&:resume)
      assert_equal 3, budget.render_count

      budget = Tilt::RenderBudget.new(:max_renders => 3)
      error = nil
      counter = Mutex.new
      fibers = Array.new(5) do
        Fiber.new do
          Tilt.with_render_budget(budget) do
            begin
              template.render
            rescue Tilt::RenderBudgetExceeded => e
              counter.synchronize { error ||= e }
            end
          end
        end
      end

      fibers.each(&:resume)
      assert_equal 3, budget.render_count
      refute_nil error
    end

    it "restores depth per fiber while sharing the count" do
      budget = Tilt::RenderBudget.new(:max_depth => 2, :max_renders => 10)
      template = Tilt::ERBTemplate.new { 'x' }

      fiber = Fiber.new do
        Tilt.with_render_budget(budget) do
          template.render
          assert_equal 0, budget.current_depth
        end
      end

      Tilt.with_render_budget(budget) do
        template.render
        fiber.resume
        assert_equal 0, budget.current_depth
      end

      assert_equal 2, budget.render_count
    end

    it "shares a single budget across threads when passed explicitly" do
      budget = Tilt::RenderBudget.new(:max_renders => 10)
      template = Tilt::ERBTemplate.new { 'x' }

      threads = Array.new(4) do
        Thread.new do
          Tilt.with_render_budget(budget) do
            2.times { template.render }
          end
        end
      end
      threads.each(&:join)

      assert_equal 8, budget.render_count
      assert_nil Tilt.render_budget
    end

    it "keeps depth local to each thread while sharing the count" do
      budget = Tilt::RenderBudget.new(:max_depth => 1, :max_renders => 10)
      depths = []
      template = Tilt::ERBTemplate.new { 'x' }

      threads = Array.new(2) do
        Thread.new do
          Tilt.with_render_budget(budget) do
            template.render
            depths << budget.current_depth
          end
        end
      end
      threads.each(&:join)

      assert_equal [0, 0], depths.sort
      assert_equal 2, budget.render_count
    end
  end

  it "requires at least one limit" do
    assert_raises(ArgumentError) { Tilt::RenderBudget.new }
  end

  it "rejects negative and non-integer limits" do
    assert_raises(ArgumentError) do
      Tilt::RenderBudget.new(:max_depth => -1)
    end
    assert_raises(TypeError) do
      Tilt::RenderBudget.new(:max_renders => 'lots')
    end
    assert_raises(ArgumentError) do
      Tilt::RenderBudget.new(:max_depth => 1, :max_chain_entries => 0)
    end
  end

  it "identifies the exceeded reason and budget on the exception" do
    budget = Tilt::RenderBudget.new(:max_renders => 1)
    template = Tilt::ERBTemplate.new { 'x' }

    error = assert_raises(Tilt::RenderBudgetExceeded) do
      Tilt.with_render_budget(budget) do
        template.render
        template.render
      end
    end

    assert_same budget, error.budget
    assert_equal :renders, error.reason
    assert_kind_of StandardError, error
  end
end
