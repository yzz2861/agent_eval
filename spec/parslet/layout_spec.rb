require 'spec_helper'
require 'parslet/layout'

describe Parslet::Layout do
  class LayoutConfigParser < Parslet::Parser
    layout = Parslet::Layout.new(comment: Parslet.str('#'))

    rule(:space) { match(/[ \t]/).repeat(1) }
    rule(:spaces) { match(/[ \t]/).repeat }
    rule(:newline) { str("\r\n") | match(/[\r\n]/) }
    rule(:bracket_space) { match(/[\s]/).repeat }
    rule(:word) { match(/[A-Za-z0-9_\-\.]/).repeat(1) }
    rule(:key) { word.as(:key) }

    rule(:bracket_content) do
      str('[') >>
        bracket_space >> word.maybe >>
        (bracket_space >> str(',') >> bracket_space >> word).repeat >>
        bracket_space >> str(']')
    end

    rule(:scalar) do
      (word | layout.without(bracket_content)).as(:value)
    end

    rule(:block_value) do
      continuation = newline.maybe >> layout.same >> item_body
      layout.block((item_body >> continuation.repeat)).as(:block)
    end

    rule(:entry_body) do
      key >>
        spaces >> str(':') >>
        (block_value | space >> scalar)
    end

    rule(:list_body) do
      str('-') >>
        spaces >>
        (block_value | scalar)
    end

    rule(:item_body) { entry_body | list_body }
    rule(:root_item) do
      layout.same >> item_body >> newline.maybe
    end

    root(:root)
    rule(:root) { layout.wrap(root_item >> root_item.repeat >> layout.end_event) }
  end

  let(:parser) { LayoutConfigParser.new }
  let(:entries) { ->(value) { value.is_a?(Array) ? value : [value] } }

  it 'parses lists and nested objects from indentation events' do
    source = <<~CONFIG
      name: app
      servers:
        primary: [a, b]
        tags:
          env: prod
          region: cn
      ports:
        - 8080
        - 9090
    CONFIG

    result = parser.parse(source)

    expect(result.map { |item| item[:key].str }).to eq(%w[name servers ports])
    servers = result[1][:block]
    expect(servers.map { |item| item[:key].str }).to eq(%w[primary tags])
    expect(servers[0][:value].str).to eq('[a, b]')
    expect(servers[1][:block].map { |item| item[:key].str }).to eq(%w[env region])
    ports = result[2][:block]
    expect(ports.map { |item| item[:value].str }).to eq(%w[8080 9090])
  end

  it 'skips blank lines and caller-defined full-line comments' do
    source = <<~CONFIG
      # top comment

      name: app

          # ignored comment
      ports:
        - 8080

        - 9090
      # trailing comment
    CONFIG

    result = parser.parse(source)

    expect(result.map { |item| item[:key].str }).to eq(%w[name ports])
    expect(result[1][:block].map { |item| item[:value].str }).to eq(%w[8080 9090])
  end

  it 'suspends layout recognition inside bracket expressions' do
    source = <<~CONFIG
      servers: [
        a,
        b
      ]
    CONFIG

    expect(parser).to parse(source)
  end

  it 'accepts CRLF line endings' do
    source = "name: app\r\nports:\r\n  - 8080\r\n"

    expect(parser).to parse(source)
  end

  it 'handles several consecutive dedents' do
    source = <<~CONFIG
      outer:
        middle:
          inner: yes
      next: ok
    CONFIG

    result = parser.parse(source)

    expect(result.map { |item| item[:key].str }).to eq(%w[outer next])
    outer = entries.call(result).first
    middle = entries.call(outer[:block]).first
    inner = entries.call(middle[:block]).first
    expect(inner[:key].str).to eq('inner')
  end

  it 'allows every open layout block to close at end of file' do
    source = <<~CONFIG
      outer:
        middle:
          inner: yes
    CONFIG

    result = parser.parse(source)

    outer = entries.call(result).first
    middle = entries.call(outer[:block]).first
    inner = entries.call(middle[:block]).first
    expect(inner[:value].str).to eq('yes')
  end

  it 'restores layout state when an ordered choice backtracks' do
    source = <<~CONFIG
      ports:
        - 8080
    CONFIG

    expect(parser).to parse(source)
  end

  it 'rejects tabs after spaces' do
    source = "name: app\nports:\n  - 8080\n\t- 9090\n"

    expect { parser.parse(source) }.to raise_error(
      Parslet::ParseFailed, /Tab policy changed/
    )
  end

  it 'rejects tabs and spaces in one indentation run' do
    source = "name: app\n \tports: 8080\n"

    expect { parser.parse(source) }.to raise_error(
      Parslet::ParseFailed, /mixes tabs and spaces/
    )
  end

  it 'keeps token positions tied to original source' do
    source = "# comment\n\nname: app\n"

    result = parser.parse(source)

    first = entries.call(result).first
    expect(first[:key].line_and_column).to eq([3, 1])
  end

  it 'restores indentation stack after an alternative pushes a level' do
    layout = Parslet::Layout.new
    newline = Parslet.str("\r\n") | Parslet.match(/[\r\n]/)
    word = Parslet.match(/[a-z]/).repeat(1)
    bad_branch = word >> newline >> layout.indent >> word >> word
    successful = word >> newline >> layout.indent >> word >> layout.dedent
    parser = layout.wrap(
      bad_branch | successful >> layout.end_event
    )

    expect(parser.parse("yes\n  ok")).to eq("yes\nok")
  end

  it 'restores layout recognition after a suspended expression fails' do
    layout = Parslet::Layout.new
    newline_skip = (Parslet.str("\r\n") | Parslet.match(/[\r\n]/)).maybe
    bracket = layout.without(Parslet.str('()'))
    word = Parslet.match(/[a-z]/).repeat(1)
    parser = layout.wrap(
      layout.same >> ((bracket >> word) | word.as(:fallback)) >>
        newline_skip >> layout.end_event
    )

    expect(parser.parse('abc')).to eq(fallback: 'abc')
  end

  it 'locks the tab policy for one parse and accepts explicit tabs' do
    layout = Parslet::Layout.new(tabs: :tabs)
    word = Parslet.match(/[a-z]/).repeat(1)
    newline = (Parslet.str("\r\n") | Parslet.match(/[\r\n]/)).maybe
    parser = layout.wrap(layout.same >> word >> newline >> layout.end_event)

    expect(parser.parse("abc")).to eq("abc")
  end
end
