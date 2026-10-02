require_relative 'test_helper'

_PipelinePassTemplate = Class.new(Tilt::Template) do
  def prepare; end

  def evaluate(scope, locals, &block)
    if options[:calls]
      options[:calls] << options.fetch(:name, data)
    end

    output = options[:output].is_a?(Proc) ? options[:output].call(data) : options[:output]
    output || data
  end
end

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

describe 'tilt/pipeline (encoding)' do
  before do
    @mapping = Tilt.default_mapping.dup
    @mapping.register(_PipelinePassTemplate, 'a', 'b', 'c')
  end

  def build_pipeline(options={})
    @mapping.register_pipeline('c.pass.b.pass.a.pass', {
      :templates => %w[a b c],
      'a' => options['a'] || {},
      'b' => options['b'] || {},
      'c' => options['c'] || {}})
  end

  it "keeps binary output of engines with no encoding declarations" do
    pipeline = build_pipeline(
      'a' => {:output => "h\xe9".b})
    assert_equal "h\xe9".b, pipeline.new { 'x' }.render
  end

  it "labels binary bytes with the declared input encoding and validates them" do
    pipeline = build_pipeline(
      'a' => {:output => "h\xc3\xa9".b},
      'b' => {:input_encoding => 'UTF-8'})
    result = pipeline.new { 'x' }.render
    assert_equal Encoding::UTF_8, result.encoding
    assert_equal "h\u00e9", result
  end

  it "does not use force_encoding to disguise invalid binary bytes as text" do
    pipeline = build_pipeline(
      'a' => {:output_encoding => 'UTF-8', :output => lambda { |input|
        # Emulate an engine that tags binary output as UTF-8 by hand
        # instead of really producing UTF-8 text.
        "h\xff".b
      }})
    error = assert_raises(Tilt::Pipeline::EncodingError) do
      pipeline.new { 'x' }.render
    end
    assert_equal 1, error.stage
    assert_equal 'a', error.extension
    assert_equal :output, error.phase
    assert_equal 1, error.byte_offset
    assert_match(/stage 1 .a. output .* byte 1/, error.message)
  end

  it "transcodes declared stage inputs and outputs through two valid conversions" do
    pipeline = build_pipeline(
      'a' => {:input_encoding => 'UTF-8', :output_encoding => 'UTF-16LE',
              :output => lambda { |input| input.encode('UTF-16LE') }},
      'b' => {:input_encoding => 'UTF-16LE', :output_encoding => 'ISO-8859-1',
              :output => lambda { |input| input.encode('ISO-8859-1') }},
      'c' => {:input_encoding => 'ISO-8859-1'})
    result = pipeline.new { "h\u00e9" }.render
    assert_equal Encoding::ISO_8859_1, result.encoding
    assert_equal "h\xe9".dup.force_encoding('ISO-8859-1'), result
  end

  it "runs two valid transcodes, then stops after an illegal output without later stages" do
    calls = []
    @mapping.register(_PipelinePassTemplate, 'd')
    pipeline = @mapping.register_pipeline('d.c.b.a', {
      :templates => %w[a b c d],
      'a' => {:calls => calls, :name => 'a',
              :input_encoding => 'UTF-8', :output_encoding => 'UTF-16LE',
              :output => lambda { |input| input.encode('UTF-16LE') }},
      'b' => {:calls => calls, :name => 'b',
              :input_encoding => 'UTF-16LE', :output_encoding => 'UTF-8',
              :output => lambda { |input| input.encode('UTF-8') }},
      'c' => {:calls => calls, :name => 'c', :input_encoding => 'UTF-8',
              :output_encoding => 'UTF-8', :output => "ab\xff".b},
      'd' => {:calls => calls, :name => 'd', :input_encoding => 'UTF-8'}})
    error = assert_raises(Tilt::Pipeline::EncodingError) do
      pipeline.new { "h\u00e9" }.render
    end
    assert_equal 3, error.stage
    assert_equal 'c', error.extension
    assert_equal :output, error.phase
    assert_equal 2, error.byte_offset
    assert_equal %w[a b c], calls
  end

  it "does not replace unconvertible bytes and reports their byte position" do
    pipeline = build_pipeline(
      'a' => {:output_encoding => 'ISO-8859-1',
              :output => "ab\u3042".dup.force_encoding('UTF-8')},
      'b' => {:input_encoding => 'ISO-8859-1'})
    error = assert_raises(Tilt::Pipeline::EncodingError) do
      pipeline.new { 'x' }.render
    end
    assert_equal 1, error.stage
    assert_equal :output, error.phase
    assert_equal 2, error.byte_offset
  end

  it "preserves a BOM carried in binary output labeled by the next stage" do
    bom = "\uFEFFh\u00e9".encode('UTF-8').b
    pipeline = build_pipeline(
      'a' => {:output => bom},
      'b' => {:input_encoding => 'UTF-8'})
    result = pipeline.new { 'x' }.render
    assert_equal Encoding::UTF_8, result.encoding
    assert_equal "\uFEFFh\u00e9", result
  end

  it "transcodes binary output labeled with a non-ascii compatible encoding with BOM" do
    pipeline = build_pipeline(
      'a' => {:output => "h\u00e9".encode('UTF-16').b},
      'b' => {:input_encoding => 'UTF-16',
              :output => lambda { |input| input.encode('UTF-8') }},
      'c' => {:input_encoding => 'UTF-8'})
    result = pipeline.new { 'x' }.render
    assert_equal Encoding::UTF_8, result.encoding
    assert_equal "h\u00e9", result
  end

  it "handles empty output with a declared encoding" do
    pipeline = build_pipeline(
      'a' => {:output_encoding => 'UTF-16LE', :output => "".b},
      'b' => {:input_encoding => 'UTF-16LE', :output_encoding => 'UTF-8',
              :output => lambda { |input| input.encode('UTF-8') }},
      'c' => {:input_encoding => 'UTF-8'})
    result = pipeline.new { 'x' }.render
    assert_equal Encoding::UTF_8, result.encoding
    assert_equal "", result
  end

  it "does not mutate frozen strings when no transcoding is needed" do
    frozen = "h\u00e9".freeze
    pipeline = build_pipeline(
      'a' => {:output => frozen, :output_encoding => 'UTF-8'},
      'b' => {:input_encoding => 'UTF-8'})
    result = pipeline.new { 'x' }.render
    assert_equal frozen, result
    assert result.equal?(frozen)
  end

  it "duplicates frozen binary strings before labeling them" do
    frozen = "h\xc3\xa9".b.freeze
    pipeline = build_pipeline(
      'a' => {:output => frozen},
      'b' => {:input_encoding => 'UTF-8'})
    result = pipeline.new { 'x' }.render
    assert_equal "h\u00e9", result
    refute result.equal?(frozen)
    assert_equal Encoding::BINARY, frozen.encoding
  end

  it "does not mutate the original binary output when labeling" do
    output = "h\xc3\xa9".b
    pipeline = build_pipeline(
      'a' => {:output => output},
      'b' => {:input_encoding => 'UTF-8'})
    result = pipeline.new { 'x' }.render
    assert_equal "h\u00e9", result
    assert_equal Encoding::BINARY, output.encoding
  end

  it "accepts Encoding objects as declarations" do
    pipeline = build_pipeline(
      'a' => {:output_encoding => Encoding::UTF_8, :output => "h\u00e9".b},
      'b' => {:input_encoding => Encoding::UTF_8})
    result = pipeline.new { 'x' }.render
    assert_equal Encoding::UTF_8, result.encoding
  end

  it "raises ArgumentError for an unknown encoding declaration" do
    pipeline = build_pipeline('b' => {:input_encoding => 'X-NONE'})
    error = assert_raises(ArgumentError) do
      pipeline.new { 'x' }.render
    end
    assert_match(/stage 2 .b./, error.message)
  end
end
