# Encoding: UTF-8

require 'spec_helper'

describe Parslet::Incremental::Session do
  # A small "rules file" grammar, typical of an editor-like use case where
  # a document is reparsed after every keystroke. Exercises sequences,
  # alternatives, repetitions, named captures, lookahead and end-of-input
  # handling.
  #
  class RulesFileParser < Parslet::Parser
    rule(:space)  { match('\\s').repeat(1) }
    rule(:space?) { space.maybe }
    rule(:ident)  { match('[a-z_]').repeat(1) }
    rule(:number) { match('[0-9]').repeat(1) }
    rule(:string) { str('"') >> (str('"').absent? >> any).repeat >> str('"') }
    rule(:value)  { string | number | ident }
    rule(:rule_line) do
      ident.as(:name) >> space? >> str('=') >> space? >>
        value.as(:value) >> str(';')
    end
    rule(:line)  { rule_line.as(:rule) }
    rule(:file)  { (space? >> line).repeat >> space? }
    root(:file)
  end

  let(:parser) { RulesFileParser.new }
  let(:initial_text) do
    <<-'TEXT'
alpha = 1;
beta = "two";
gamma = ninety;
delta = 4;
epsilon = "five";
    TEXT
  end
  let(:session) { described_class.new(parser, initial_text) }

  def parse_full(parser, text)
    parser.parse(text)
  rescue Parslet::ParseFailed => error
    error
  end

  def parse_incremental(session)
    session.parse
  rescue Parslet::ParseFailed => error
    error
  end

  # Collects all slices contained in a parse result tree.
  def slices_in(tree, acc=[])
    case tree
    when Parslet::Slice then acc << tree
    when Array then tree.each { |e| slices_in(e, acc) }
    when Hash then tree.each_value { |v| slices_in(v, acc) }
    end
    acc
  end

  # Asserts that the incremental result is identical to a full parse of
  # the current text -- including failure positions -- and that no slice
  # points at a previous generation of the text.
  #
  def expect_consistent!(session, parser)
    incremental = parse_incremental(session)
    full = parse_full(parser, session.text)

    if full.is_a?(Parslet::ParseFailed)
      expect(incremental).to be_a(Parslet::ParseFailed)
      expect(incremental.message).to eq(full.message)
      expect(incremental.parse_failure_cause.pos.charpos).to(
        eq(full.parse_failure_cause.pos.charpos))
      expect(incremental.parse_failure_cause.ascii_tree).to(
        eq(full.parse_failure_cause.ascii_tree))
      return incremental
    end

    expect(incremental).to_not be_a(Parslet::ParseFailed)
    # Slice#inspect includes the offset, so this compares both tree
    # shape and slice positions.
    expect(incremental.inspect).to eq(full.inspect)

    slices = slices_in(incremental)
    expect(slices).to_not be_empty
    slices.each do |slice|
      expect(
        slice.position.instance_variable_get(:@string).equal?(session.text)
      ).to be(true), "slice #{slice.inspect} points at an old text"
    end

    incremental
  end

  # Replaces the first occurrence of +anchor+ in the session's text with
  # +by+.
  #
  def replace_first(session, anchor, by)
    index = session.text.index(anchor) or
      fail "Anchor #{anchor.inspect} not found in #{session.text.inspect}"
    session.edit(index, index + anchor.size, by)
  end

  # A fixed script of insertions, deletions and replacements, exercised
  # against full reparses step by step. Each entry applies its edit to
  # the text produced by the previous entries.
  #
  def edit_script
    [
      ['replace a number (substitution)',
        ->(s) { replace_first(s, 'alpha = 1;', 'alpha = 42;') }],
      ['insert a line in the middle (insertion)',
        ->(s) { replace_first(s, 'beta', "mid = 3;\nbeta") }],
      ['delete that line again (deletion)',
        ->(s) { replace_first(s, "mid = 3;\n", '') }],
      ['append a line at end of input',
        ->(s) { s.edit(s.text.size, s.text.size, "zeta = 6;\n") }],
      ['insert a line at start of input',
        ->(s) { s.edit(0, 0, "zero = 0;\n") }],
      ['replace a value by a longer one',
        ->(s) { replace_first(s, 'delta = 4;', 'delta = "four";') }],
      ['introduce multibyte characters',
        ->(s) { replace_first(s, '"five"', '"fünf"') }],
      ['break the syntax after the multibyte edit',
        ->(s) { replace_first(s, 'gamma =', 'gamma ') }],
      ['repair the syntax again',
        ->(s) { replace_first(s, 'gamma  ', 'gamma = ') }],
      ['delete the final newline',
        ->(s) { s.edit(s.text.size - 1, s.text.size, '') }],
      ['restore the final newline',
        ->(s) { s.edit(s.text.size, s.text.size, "\n") }],
    ]
  end

  # Exact cache statistics for the fixed edit script above, in the same
  # order: [hits, misses, full parse misses, invalidated, shifted]. These
  # numbers are deterministic; they make the reuse benefit checkable
  # without relying on wall clock timing.
  #
  EXPECTED_STATS = [
    [6,  44, 260, 43, 216],
    [13, 57, 299, 18, 200],
    [9,  8,  260, 47, 210],
    [7,  55, 300, 15, 0],
    [9,  48, 340, 0,  300],
    [9,  60, 357, 46, 113],
    [14, 38, 357, 38, 54],
    [7,  26, 163, 27, 195],
    [12, 32, 357, 30, 191],
    [10, 8,  356, 9,  7],
    [8,  16, 357, 15, 0],
  ]

  it 'produces results identical to full reparses at every step' do
    expect_consistent!(session, parser)

    edit_script.each do |description, edit|
      edit.call(session)
      expect_consistent!(session, parser)
    end
  end

  it 'reuses memoized results, with exact checkable statistics' do
    expect_consistent!(session, parser)

    edit_script.zip(EXPECTED_STATS).each do |(description, edit), expected|
      session.reset_stats!
      edit.call(session)
      incremental = expect_consistent!(session, parser)

      hits, misses, full_misses, invalidated, shifted = expected
      stats = session.stats

      # Baseline: a fresh session parses the same text from scratch.
      fresh = described_class.new(parser, session.text)
      begin
        fresh.parse
      rescue Parslet::ParseFailed
        # The step left the text unparseable; the baseline misses were
        # still recorded.
      end

      expect(stats[:hits]).to eq(hits),
        "hits mismatch after #{description.inspect}"
      expect(stats[:misses]).to eq(misses),
        "misses mismatch after #{description.inspect}"
      expect(fresh.stats[:misses]).to eq(full_misses),
        "full parse baseline mismatch after #{description.inspect}"
      expect(stats[:invalidated]).to eq(invalidated),
        "invalidated mismatch after #{description.inspect}"
      expect(stats[:shifted]).to eq(shifted),
        "shifted mismatch after #{description.inspect}"

      # The point of the whole exercise: the incremental parse recomputes
      # only a fraction of what a full parse computes.
      unless incremental.is_a?(Parslet::ParseFailed)
        expect(stats[:misses]).to be < full_misses / 2
      end
    end
  end

  it 'rejects invalid edit ranges' do
    expect { session.edit(5, 2, 'x') }.to raise_error(ArgumentError)
    expect { session.edit(-1, 2, 'x') }.to raise_error(ArgumentError)
    expect { session.edit(0, session.text.size + 1, 'x') }.
      to raise_error(ArgumentError)
  end
end
