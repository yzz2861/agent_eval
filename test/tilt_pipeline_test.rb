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

class PipelineEncodingTemplate < Tilt::Template
  def prepare
  end

  def evaluate(scope, locals, &block)
    output = options[:output].call(data, locals[:record])
    output = output.dup.force_encoding(Encoding::BINARY) if options[:return_binary]
    output
  end
end

describe 'tilt/pipeline (encoding)' do
  before do
    @mapping = Tilt.default_mapping.dup
    %w'enc1 enc2 enc3 enc4'.each do |ext|
      @mapping.register(PipelineEncodingTemplate, ext)
    end
  end

  def render_pipeline(pipeline, source, record=nil)
    pipeline.new { source }.render(Object.new, :record => record)
  end

  it "transcodes twice, validates binary declarations, and leaves undeclared stages untouched" do
    record = {:calls => [], :inputs => [nil, nil, nil]}
    pipeline = @mapping.register_pipeline('x.enc3.enc2.enc1',
      'enc1' => {
        :input_encoding => 'UTF-8',
        :output => lambda { |data, log| log[:calls] << 1; log[:inputs][0] = data; data }
      },
      'enc2' => {
        :input_encoding => 'ISO-8859-1',
        :output => lambda { |data, log| log[:calls] << 2; log[:inputs][1] = data; data }
      },
      'enc3' => {
        :input_encoding => 'UTF-16BE',
        :output => lambda { |data, log| log[:calls] << 3; log[:inputs][2] = data; data }
      })
    source = "\xC3\xA9".b.freeze

    result = render_pipeline(pipeline, source, record)

    assert_equal [1, 2, 3], record[:calls]
    assert_equal Encoding::UTF_8, record[:inputs][0].encoding
    assert_equal Encoding::ISO_8859_1, record[:inputs][1].encoding
    assert_equal Encoding::UTF_16BE, record[:inputs][2].encoding
    assert_equal Encoding::UTF_16BE, result.encoding
    assert_equal "\u00e9", result.encode(Encoding::UTF_8)
    assert_equal Encoding::BINARY, source.encoding
  end

  it "strips BOMs and passes empty output and frozen source through safely" do
    record = {}
    pipeline = @mapping.register_pipeline('z.enc2.enc1',
      'enc1' => {
        :input_encoding => 'UTF-8',
        :output_encoding => 'UTF-8',
        :output => lambda { |data, log| log[:input] = data; "" }
      },
      'enc2' => {
        :input_encoding => 'UTF-8',
        :output_encoding => 'BINARY',
        :output => lambda { |data, log| data }
      })

    assert_equal "", render_pipeline(pipeline, "\uFEFFhello".freeze, record)
    assert_equal "hello", record[:input]
    assert_equal Encoding::UTF_8, record[:input].encoding
  end

  it "keeps an explicitly declared non-ASCII-compatible encoding and removes its BOM" do
    pipeline = @mapping.register_pipeline('bom.enc1',
      'enc1' => {
        :input_encoding => 'UTF-16BE',
        :output_encoding => 'UTF-16BE',
        :output => lambda { |data, log| data }
      })
    source = "\xFE\xFF\x00a".b.freeze

    result = render_pipeline(pipeline, source)

    assert_equal Encoding::UTF_16BE, result.encoding
    assert_equal "a", result.encode(Encoding::UTF_8)
    assert_equal Encoding::BINARY, source.encoding
  end

  it "stops after invalid stage output and reports the stage and byte position" do
    record = {:calls => [], :input => nil}
    pipeline = @mapping.register_pipeline('bad.enc4.enc3.enc2.enc1',
      'enc1' => {
        :input_encoding => 'UTF-8',
        :output => lambda { |data, log| log[:calls] << 1; data }
      },
      'enc2' => {
        :input_encoding => 'ISO-8859-1',
        :output => lambda { |data, log| log[:calls] << 2; data }
      },
      'enc3' => {
        :input_encoding => 'UTF-16BE',
        :output_encoding => 'UTF-8',
        :return_binary => true,
        :output => lambda { |data, log| log[:calls] << 3; "ab\xffc" }
      },
      'enc4' => {
        :input_encoding => 'UTF-8',
        :output => lambda { |data, log| log[:input] = data; log[:calls] << 4; data }
      })

    error = assert_raises(Encoding::InvalidByteSequenceError) { render_pipeline(pipeline, "\xC3\xA9".b, record) }

    assert_equal [1, 2, 3], record[:calls]
    assert_nil record[:input]
    assert_match(/stage 3/, error.message)
    assert_match(/output/, error.message)
    assert_match(/byte 2/, error.message)
  end

  it "stops before a stage with invalid input and reports the stage and byte position" do
    record = {:calls => []}
    pipeline = @mapping.register_pipeline('badinput.enc1',
      'enc1' => {
        :input_encoding => 'UTF-8',
        :output => lambda { |data, log| log[:calls] << 1; data }
      })

    error = assert_raises(Encoding::InvalidByteSequenceError) { render_pipeline(pipeline, "ab\xffc".b, record) }

    assert_empty record[:calls]
    assert_match(/stage 1/, error.message)
    assert_match(/input/, error.message)
    assert_match(/byte 2/, error.message)
  end

  it "does not replace unmappable characters when transcoding to binary" do
    pipeline = @mapping.register_pipeline('binary.enc1',
      'enc1' => {
        :output_encoding => 'BINARY',
        :output => lambda { |data, log| "ab\u00e9c" }
      })

    error = assert_raises(Encoding::UndefinedConversionError) do
      render_pipeline(pipeline, "initial")
    end

    assert_match(/stage 1/, error.message)
    assert_match(/output/, error.message)
    assert_match(/byte 2/, error.message)
  end
end
