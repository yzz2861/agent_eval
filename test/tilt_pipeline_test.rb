require_relative 'test_helper'

describe 'tilt/pipeline' do
  before do
    @mapping = Tilt.default_mapping.dup
    @pipeline_class = @mapping.register_pipeline('str.erb')
  end

  it "returns a template class" do
    assert_equal Tilt::Pipeline, @pipeline_class.superclass
  end

  it "registers itself for the given extension" do
    assert_equal @pipeline_class, @mapping['test.str.erb']
  end

  it "renders templates starting with final extension to inner extensions" do
    template = @pipeline_class.new { |t| '#<%= \'{a = 1}\' %><%= \'#{a}\' %>' }
    assert_equal "11", template.render
  end

  it "can be rendered more than once" do
    template = @pipeline_class.new { |t| '<%= \'#{1}\' %>' }
    3.times { assert_equal "1", template.render }
  end

  it "passing locals" do
    template = @pipeline_class.new { |t| '<%= \'#{a}\' * a %>' }
    assert_equal "333", template.render(Object.new, :a => 3)
  end

  it "evaluating in an object scope" do
    template = @pipeline_class.new { |t| '<%= \'#{a}\' * a %>' }
    o = Object.new
    def o.a; 3 end
    assert_equal "333", template.render(o)
  end

  it "passing a block for yield" do
    template = @pipeline_class.new { |t| '<%= \'#{yield}\' * yield %>' }
    assert_equal "333", template.render { 3 }
    assert_equal "22", template.render { 2 }
  end
end

describe 'tilt/pipeline (options)' do
  before do
    @mapping = Tilt.default_mapping.dup
  end

  it "supports :templates option for specifying templates to use in order" do
    pipeline = @mapping.register_pipeline('setrrb', :templates=>['erb', 'str'])
    template = pipeline.new { |t| '#<%= \'{a = 1}\' %><%= \'#{a}\' %>' }
    assert_equal "11", template.render
  end

  it "supports :extra_exts option for specifying additional extensions to register" do
    @mapping.register_pipeline('str.erb', :extra_exts=>['setrrb', 'asdfoa'])
    ['str.erb', 'setrrb', 'asdfoa'].each do |ext|
      template = @mapping[ext].new { |t| '#<%= \'{a = 1}\' %><%= \'#{a}\' %>' }
      assert_equal "11", template.render
    end
  end

  it "supports per template class options" do
    pipeline = @mapping.register_pipeline('str.erb', 'erb'=>{:outvar=>'@foo'})
    template = pipeline.new { |t| '#<% @foo << \'{a = 1}\' %><%= \'#{a}\' %>' }
    assert_equal "11", template.render
  end
end

describe 'tilt/pipeline (stage diagnostics)' do
  before do
    @mapping = Tilt.default_mapping.dup

    # Fake adapter that transforms markup by inserting a header
    # comment line, and provides a line mapping from its output lines
    # back to its input lines.
    @mapping.register(Class.new(Tilt::Template) {
      def prepare; end
      def evaluate(scope, locals, &block)
        "# header\n" + data
      end
      def line_mapping
        lambda{|output_line| output_line - 1}
      end
    }, 'markup')

    # Fake adapter that executes its input as Ruby code, similar to
    # how the ERB template executes the final template output.
    @mapping.register(Class.new(Tilt::Template) {
      def prepare; end
      def evaluate(scope, locals, &block)
        eval(data, TOPLEVEL_BINDING, eval_file, line)
      end
    }, 'exec')
  end

  it "reports stage, input position, and output position for final execution errors" do
    pipeline = @mapping.register_pipeline('exec.markup')
    template = pipeline.new('test.exec.markup') { |t| "# one\n# two\nraise 'boom'\n" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }

    assert_equal 'exec', error.stage_name
    assert_kind_of RuntimeError, error.cause
    assert_equal 'boom', error.cause.message

    assert_equal 3, error.input_position.line
    assert_equal 'test.exec.markup', error.input_position.source
    refute error.input_position.intermediate?

    assert_equal 4, error.output_position.line
    assert error.output_position.intermediate?
    assert_match(/intermediate text/, error.output_position.source)
    assert_match(/markup/, error.output_position.source)
  end

  it "gives each stage a stable name" do
    pipeline = @mapping.register_pipeline('exec.markup')
    2.times do
      template = pipeline.new('test.exec.markup') { |t| "raise 'boom'\n" }
      error = assert_raises(Tilt::Pipeline::StageError) { template.render }
      assert_equal 'exec', error.stage_name
    end
  end

  it "marks positions as intermediate text when a stage provides no line mapping" do
    @mapping.register(Class.new(Tilt::Template) {
      def prepare; end
      def evaluate(scope, locals, &block)
        "# header\n" + data
      end
    }, 'nomap')
    pipeline = @mapping.register_pipeline('exec.nomap')
    template = pipeline.new('test.exec.nomap') { |t| "# one\n# two\nraise 'boom'\n" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }

    assert_equal 'exec', error.stage_name
    assert_equal 4, error.input_position.line
    assert error.input_position.intermediate?
    assert_match(/intermediate text/, error.input_position.source)
    refute_equal 'test.exec.nomap', error.input_position.source
  end

  it "reports the failing stage for errors raised while transforming" do
    @mapping.register(Class.new(Tilt::Template) {
      def prepare; end
      def evaluate(scope, locals, &block)
        raise "bad markup"
      end
    }, 'raiser')
    pipeline = @mapping.register_pipeline('exec.raiser')
    template = pipeline.new('test.exec.raiser') { |t| "data" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }

    assert_equal 'raiser', error.stage_name
    assert_kind_of RuntimeError, error.cause
    assert_equal 'bad markup', error.cause.message
    assert_nil error.input_position.line
    assert_nil error.output_position.line
  end

  it "confirms the original file line for errors in the first stage" do
    @mapping.register(Class.new(Tilt::Template) {
      def prepare; end
      def evaluate(scope, locals, &block)
        error = RuntimeError.new("bad markup")
        error.set_backtrace(["#{eval_file}:#{line + 1}:in evaluate"])
        raise error
      end
    }, 'raiser')
    pipeline = @mapping.register_pipeline('exec.raiser')
    template = pipeline.new('test.exec.raiser') { |t| "one\ntwo\n" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }

    assert_equal 2, error.input_position.line
    refute error.input_position.intermediate?
    assert_equal 2, error.output_position.line
    refute error.output_position.intermediate?
  end

  it "reports nested pipeline stages and preserves the original cause" do
    @mapping.register_pipeline('innerpipe', :templates=>['markup', 'exec'])
    outer = @mapping.register_pipeline('outerpipe', :templates=>['innerpipe'])
    template = outer.new('test.outerpipe') { |t| "# one\n# two\nraise 'boom'\n" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }

    assert_equal 'innerpipe>exec', error.stage_name
    assert_equal 3, error.input_position.line
    refute error.input_position.intermediate?
    assert_equal 4, error.output_position.line
    assert error.output_position.intermediate?

    assert_kind_of Tilt::Pipeline::StageError, error.cause
    assert_equal 'exec', error.cause.stage_name
    assert_kind_of RuntimeError, error.cause.cause
    assert_equal 'boom', error.cause.cause.message
  end

  it "does not include the full template content in the error message" do
    pipeline = @mapping.register_pipeline('exec.markup')
    template = pipeline.new('test.exec.markup') { |t| "# one\n# two\nraise 'boom'\n" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }

    refute_includes error.message, "# one\n# two"
    refute_includes error.message, "# header\n# one"
    assert_match(/exec/, error.message)
    assert_match(/boom/, error.message)
  end
end
