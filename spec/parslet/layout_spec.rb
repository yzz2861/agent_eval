require 'spec_helper'

describe Parslet::Layout do
  # Builds a small indentation sensitive config grammar on top of the given
  # layout factory. The grammar never counts spaces itself; it only
  # consumes layout events (start/same/enter/exit/finish).
  def build_parser(layout)
    Class.new(Parslet::Parser) do
      define_method(:layout) { layout }

      root(:document)
      rule(:document) do
        layout.start >> node >> (layout.same >> node).repeat >> layout.finish
      end
      rule(:node)   { (pair | item) >> nested.maybe }
      rule(:nested) do
        layout.scope(
          layout.enter >> node >> (layout.same >> node).repeat >> layout.exit
        ).as(:children)
      end
      rule(:pair) do
        (key.as(:key) >> str(':') >> (str(' ') >> value).maybe).as(:pair)
      end
      rule(:item)   { (str('- ') >> value).as(:item) }
      rule(:value) do
        str('[') >> match('[^\]]').repeat.as(:ilist) >> str(']') |
          match('[^\n]').repeat(1).as(:scalar)
      end
      rule(:key)    { match('[A-Za-z0-9_]').repeat(1) }
    end
  end

  def analyze(source, **options)
    Parslet::Layout::Analyzer.new(source, **options).analyze
  end

  let(:layout) { Parslet::Layout.new(comment: '#') }
  let(:parser) { build_parser(layout).new }

  describe 'same / enter / exit events' do
    it 'parses sibling, child and parent transitions' do
      result = parser.parse(<<~CFG)
        server:
          host: example.com
          ports:
            - 80
            - 443
        db:
          host: localhost
      CFG

      result.should == [
        { pair: { key: 'server' },
          children: [
            { pair: { key: 'host', scalar: 'example.com' } },
            { pair: { key: 'ports' },
              children: [
                { item: { scalar: '80' } },
                { item: { scalar: '443' } }
              ] }
          ] },
        { pair: { key: 'db' },
          children: { pair: { key: 'host', scalar: 'localhost' } } }
      ]
    end

    it 'handles consecutive dedents across several levels at once' do
      result = parser.parse("a:\n  b:\n    c: 1\nd: 2\n")

      result.should == [
        { pair: { key: 'a' },
          children: { pair: { key: 'b' },
            children: { pair: { key: 'c', scalar: '1' } } } },
        { pair: { key: 'd', scalar: '2' } }
      ]
    end

    it 'closes blocks that are still open at end of input' do
      result = parser.parse("a:\n  b:\n    c: 1\n")

      result.should == {
        pair: { key: 'a' },
        children: { pair: { key: 'b' },
          children: { pair: { key: 'c', scalar: '1' } } }
      }
    end

    it 'computes events and depths during analysis' do
      lines, base_width = analyze("a\n  b\n    c\nd\n")

      lines.map(&:event).should == [:same, :enter, :enter, :exit]
      lines.map(&:depth).should == [0, 1, 2, 0]
      base_width.should == 0
    end
  end

  describe 'blank lines and comments' do
    it 'does not count blank lines or whole line comments for indentation' do
      result = parser.parse("# header\na: 1\n\n  # indented comment\nb: 2\n")

      result.should == [
        { pair: { key: 'a', scalar: '1' } },
        { pair: { key: 'b', scalar: '2' } }
      ]
    end

    it 'supports regexp comment definitions' do
      lines, = analyze("a\n// c\n  b\n", comment: %r{//})
      lines.map(&:width).should == [0, 2]
    end

    it 'lets comment lines contain brackets without effect' do
      lines, = analyze("a\n# (((\nb\n", comment: '#')
      lines.size.should == 2
    end
  end

  describe 'brackets' do
    it 'suspends layout recognition inside bracket expressions' do
      result = parser.parse("list: [a,\n     b,\n     c]\nnext: 1\n")

      result.should == [
        { pair: { key: 'list', ilist: "a,\n     b,\n     c" } },
        { pair: { key: 'next', scalar: '1' } }
      ]
    end

    it 'ignores brackets inside strings' do
      lines, = analyze(%Q(a: "{"\nb: 1\n))
      lines.size.should == 2
    end
  end

  describe 'tab policy' do
    it 'parses tab indented input' do
      tab_parser = build_parser(Parslet::Layout.new).new
      result = tab_parser.parse("a:\n\tb: 1\n")

      result.should == {
        pair: { key: 'a' },
        children: { pair: { key: 'b', scalar: '1' } }
      }
    end

    it 'detects the policy once from the first indented line' do
      lines, = analyze("a\n  b\n    c\n")
      lines.map(&:width).should == [0, 2, 4]

      lines, = analyze("a\n\tb\n\t\tc\n")
      lines.map(&:width).should == [0, 1, 2]
    end

    it 'rejects tabs after spaces were established' do
      expect { analyze("a\n  b\n\tc\n") }.
        to raise_error(Parslet::Layout::TabError, /tab/)
    end

    it 'rejects spaces after tabs were established' do
      expect { analyze("a\n\tb\n  c\n") }.
        to raise_error(Parslet::Layout::TabError, /space/)
    end

    it 'rejects tabs and spaces mixed within one indentation' do
      expect { analyze("a\n \tb\n") }.
        to raise_error(Parslet::Layout::TabError, /mixed/)
    end

    it 'rejects any tab when policy is :forbid' do
      expect { analyze("a\n\tb\n", tabs: :forbid) }.
        to raise_error(Parslet::Layout::TabError)
    end

    it 'rejects tabs when policy is :spaces' do
      expect { analyze("a\n\tb\n", tabs: :spaces) }.
        to raise_error(Parslet::Layout::TabError)
    end

    it 'rejects spaces when policy is :tabs' do
      expect { analyze("a\n\tb\n  c\n", tabs: :tabs) }.
        to raise_error(Parslet::Layout::TabError)
    end

    it 'fixes the policy per parse, not globally' do
      any_parser = build_parser(Parslet::Layout.new).new
      any_parser.parse("a:\n  b: 1\n")
      any_parser.parse("a:\n\tb: 1\n")
    end
  end

  describe 'inconsistent dedents' do
    it 'rejects dedents to a level that was never established' do
      expect { analyze("a\n    b\n  c\n") }.
        to raise_error(Parslet::Layout::DedentError, /dedent/)
    end
  end

  describe 'backtracking' do
    let(:bt_parser) do
      bt_layout = Parslet::Layout.new
      Class.new(Parslet::Parser) do
        define_method(:layout) { bt_layout }

        root(:top)
        rule(:top) do
          layout.start >> (attempt_one | attempt_two) >>
            layout.same >> str('s') >> layout.finish
        end
        rule(:attempt_one) do
          str('k:') >> layout.scope(layout.enter >> str('z') >> layout.exit)
        end
        rule(:attempt_two) do
          str('k:') >> layout.scope(layout.enter >> str('q') >> layout.exit)
        end
      end.new
    end

    it 'restores layout state when a choice backtracks' do
      # attempt_one enters the block, fails on 'q', and must leave the
      # layout stack untouched for attempt_two and the following same.
      bt_parser.parse("k:\n  q\ns").should_not be_nil
    end

    it 'restores layout state when a maybe backtracks' do
      # The nested block of 'a:' does not exist; after the failed enter
      # the sibling 'b: 2' must still be seen at top level.
      result = parser.parse("a:\nb: 2\n")
      result.should == [
        { pair: { key: 'a' } },
        { pair: { key: 'b', scalar: '2' } }
      ]
    end
  end

  describe 'positions' do
    it 'keeps slices tied to the original text' do
      source = "a:\n  b: 12\n"
      result = parser.parse(source)

      slice = result[:children][:pair][:scalar]
      slice.to_s.should == '12'
      slice.offset.should == source.index('12')
      slice.line_and_column.should == [2, 6]
    end

    it 'handles multibyte content without confusing positions' do
      source = "a:\n  n: \u00e4\u00f6\u00fc\n  m: x\n"
      result = parser.parse(source)

      first, second = result[:children]
      first[:pair][:scalar].to_s.should == "\u00e4\u00f6\u00fc"
      second[:pair][:scalar].offset.should == source.index('x')
    end
  end

  describe 'combinators' do
    it 'offers a ready-made transactional block combinator' do
      block_layout = Parslet::Layout.new
      klass = Class.new(Parslet::Parser) do
        define_method(:layout) { block_layout }

        root(:top)
        rule(:top) do
          layout.start >> layout.block(head, item) >> layout.finish
        end
        rule(:head) { str('h') }
        rule(:item) { match('[a-z]').repeat(1).as(:w) }
      end

      klass.new.parse("h\n  a\n  b\n").should == [{ w: 'a' }, { w: 'b' }]
    end

    it 'is never packrat cached, since results depend on layout state' do
      factory = Parslet::Layout.new
      [
        factory.enter, factory.same, factory.exit,
        factory.start, factory.finish, factory.scope(Parslet.any)
      ].each do |atom|
        atom.cached?.should == false
      end
    end
  end
end
