# Encoding: UTF-8

require 'spec_helper'

# Targeted tests for the observation tracking of incremental sessions:
# reuse must not be decided by the span of successful matches alone.
# Lookahead, failed alternative branches and end-of-input checks all
# observe input beyond the matched region, and edits there must
# invalidate the corresponding entries.
#
describe 'incremental observation tracking' do
  include Parslet

  def session_for(parser, text)
    Parslet::Incremental::Session.new(parser, text)
  end

  def parse_or_error(parslet, text)
    parslet.parse(text)
  rescue Parslet::ParseFailed => error
    error
  end

  def expect_consistent(session, parslet)
    incremental =
      begin
        session.parse
      rescue Parslet::ParseFailed => error
        error
      end
    full = parse_or_error(parslet, session.text)

    if full.is_a?(Parslet::ParseFailed)
      expect(incremental).to be_a(Parslet::ParseFailed)
      expect(incremental.message).to eq(full.message)
      expect(incremental.parse_failure_cause.pos.charpos).to(
        eq(full.parse_failure_cause.pos.charpos))
    else
      expect(incremental).to_not be_a(Parslet::ParseFailed)
      expect(incremental.inspect).to eq(full.inspect)
    end
  end

  describe 'lookahead' do
    # Matches any character that is not followed by an 'a'.
    let(:parslet) { (str('a').absent? >> any).repeat }

    it 'observes the character after the match' do
      session = session_for(parslet, 'xbx')
      expect_consistent(session, parslet)

      # The lookahead at position 0 observed position 1. Replacing it
      # with 'a' must change the parse, so the cached entry must not be
      # reused.
      session.edit(1, 2, 'a')
      expect_consistent(session, parslet)
      expect(session.stats[:invalidated]).to be > 0
      expect(session.text).to eq('xax')
    end
  end

  describe 'failed alternative branches' do
    let(:parslet) { (str('ab') | str('a')) >> str('c') }

    it 'observes input read by the failing branch' do
      session = session_for(parslet, 'ac')
      expect_consistent(session, parslet)

      # str('ab') failed at position 0 after observing 'c' at position 1.
      # Turning 'ac' into 'ab' must make the first branch succeed.
      session.edit(1, 2, 'b')
      expect_consistent(session, parslet)
      expect(session.stats[:invalidated]).to be > 0
    end
  end

  describe 'end of input checks' do
    it 'observes end of input in repetitions' do
      parslet = str('a').repeat
      session = session_for(parslet, 'aa')
      expect_consistent(session, parslet)

      # Appending makes the consume-all parse fail; the repetition had
      # observed that the input ended at position 2.
      session.edit(2, 2, 'b')
      expect_consistent(session, parslet)
      expect(session.stats[:invalidated]).to be > 0
    end

    it 'observes end of input in negative lookahead' do
      parslet = str('a') >> any.absent?
      session = session_for(parslet, 'a')
      expect_consistent(session, parslet)

      session.edit(1, 1, 'b')
      expect_consistent(session, parslet)
      expect(session.stats[:invalidated]).to be > 0
    end
  end

  describe 'captures and dynamic parses' do
    # Matches repeated pairs of the same letter, like "aa,bb,".
    class CaptureParser < Parslet::Parser
      rule(:pair) do
        match['ab'].capture(:first) >>
          dynamic { |_src, ctx| str(ctx.captures[:first]) } >>
          str(',')
      end
      rule(:file) { pair.repeat }
      root(:file)
    end

    let(:parser) { CaptureParser.new }

    it 'replays capture side effects on cache hits' do
      session = session_for(parser, 'aa,bb,')
      expect_consistent(session, parser)

      # Touch the comma of the first pair only. The capture at position 0
      # survives the edit and is reused; its side effect must be replayed
      # for the (never cached) dynamic parse to see.
      session.edit(2, 3, ',')
      expect_consistent(session, parser)
      expect(session.stats[:hits]).to be > 0

      # Now change the first pair's letter: the capture is invalidated
      # and the dynamic parse must follow suit.
      session.edit(0, 1, 'b')
      expect_consistent(session, parser)
    end
  end

  describe 'multibyte characters' do
    let(:parslet) { (str('é') | str('a') | any).repeat }

    it 'handles edits around multibyte characters' do
      session = session_for(parslet, 'aéaé')
      expect_consistent(session, parslet)

      session.edit(0, 0, 'é')
      expect_consistent(session, parslet)

      session.edit(2, 3, 'ü')
      expect_consistent(session, parslet)

      session.edit(0, 1, '')
      expect_consistent(session, parslet)
    end
  end
end
