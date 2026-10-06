require 'parslet/source'
require 'parslet/atoms/context'
require 'parslet/atoms/cache'

class Parslet::IncrementalSession
  def initialize(parser, input)
    @parser = parser
    @source = Parslet::Source.new(input)
    @cache = Parslet::Atoms::Cache.new
    @error_reporter = Parslet::ErrorReporter::Tree.new
  end

  def parse(options={})
    prefix = options[:prefix]
    reporter = options[:reporter]
    @source.bytepos = 0
    context = Parslet::Atoms::Context.new(nil)
    context.use_persistent_cache(@cache)
    consume_all = !prefix

    success, value = @parser.apply(@source, context, consume_all)

    unless success
      @source.bytepos = 0
      error_reporter = reporter || @error_reporter
      context = Parslet::Atoms::Context.new(error_reporter)
      context.use_persistent_cache(@cache)
      success, value = @parser.apply(@source, context, consume_all)

      fail "Assertion failed: success was true when parsing with reporter" if success
      value.raise
    end

    @parser.flatten(value)
  end

  def replace(char_pos, char_length, replacement)
    start_byte = byte_offset_for_char_offset(input, char_pos)
    old_length = input[char_pos, char_length].bytesize
    @source.replace(char_pos, char_length, replacement)
    @cache.replace(start_byte, old_length, replacement.to_str)
    self
  end

  def insert(char_pos, replacement)
    replace(char_pos, 0, replacement)
  end

  def delete(char_pos, char_length)
    replace(char_pos, char_length, '')
  end

  def input
    @source.string
  end

  def cache_stats
    @cache.stats
  end

  def reset_cache_stats
    @cache.reset_stats
  end

private

  def byte_offset_for_char_offset(string, char_offset)
    string[0, char_offset].bytesize
  end
end
