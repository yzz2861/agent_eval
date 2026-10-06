class Parslet::Atoms::Permutation < Parslet::Atoms::Base
  Member = Struct.new(:name, :parslet, :required)

  class Builder
    attr_reader :members

    def initialize
      @members = []
    end

    def required(name, parslet)
      add(name, parslet, true)
    end

    def optional(name, parslet)
      add(name, parslet, false)
    end

  private
    def add(name, parslet, required)
      unless parslet.is_a?(Parslet::Atoms::Base)
        raise ArgumentError, "permutation member #{name.inspect} must be a parslet"
      end
      unless required == true || required == false
        raise ArgumentError, "permutation member #{name.inspect} must be required or optional"
      end

      members << Member.new(name.to_sym, parslet, required)
      parslet
    end
  end

  class Failure
    attr_reader :causes, :duplicates, :missing

    def initialize
      @causes = []
      @duplicates = {}
      @missing = {}
    end

    def merge(failure)
      causes.concat(failure.causes)
      merge_positions(duplicates, failure.duplicates)
      merge_positions(missing, failure.missing)
      dedupe
      self
    end

    def add_cause(cause)
      causes << cause unless cause.nil?
      dedupe
      self
    end

    def add_duplicate(name, cause)
      duplicates[name] = position_of(cause)
      causes << cause unless cause.nil?
      dedupe
      self
    end

    def add_missing(name, cause)
      missing[name] = position_of(cause)
      causes << cause unless cause.nil?
      dedupe
      self
    end

  private
    def position_of(cause)
      cause ? cause.pos : nil
    end

    def merge_positions(target, other)
      other.each do |name, position|
        target[name] = position if position && (target[name].nil? || position > target[name])
      end
    end

    def dedupe
      causes.compact!
      causes.uniq! { |cause| [cause.pos, cause.message] }
    end
  end

  attr_reader :members

  def self.build(&block)
    builder = Builder.new
    block.call(builder)
    new(builder.members)
  end

  def initialize(members)
    super()

    @members = members.map do |member|
      next member if member.is_a?(Member)

      name, parslet, required = member
      required = true if required.nil?
      unless required == true || required == false
        raise ArgumentError, "permutation member #{name.inspect} must be required or optional"
      end

      Member.new(name.to_sym, parslet, required)
    end

    names = @members.map(&:name)
    duplicates = names.select { |name| names.count(name) > 1 }.uniq
    unless duplicates.empty?
      raise ArgumentError, "duplicate permutation member name(s): #{duplicates.inspect}"
    end

    @members.each do |member|
      unless member.parslet.is_a?(Parslet::Atoms::Base)
        raise ArgumentError, "permutation member #{member.name.inspect} must be a parslet"
      end
      unless member.required == true || member.required == false
        raise ArgumentError, "permutation member #{member.name.inspect} must be required or optional"
      end
    end

    @named_parslets = @members.map do |member|
      Parslet::Atoms::Named.new(member.parslet, member.name)
    end
  end

  def try(source, context, consume_all)
    start = source.bytepos
    failure = explore(0, {}, source, context, consume_all)
    if failure.is_a?(Failure)
      source.bytepos = start
      return context.err(
        self, source, root_message(failure), failure.causes)
    end

    succ(failure)
  end

  def cached?
    false
  end

  def to_s_inner(prec)
    descriptions = members.map do |member|
      marker = member.required ? '' : '?'
      "#{member.name}:#{member.parslet.to_s(prec)}#{marker}"
    end
    "PERMUTATION(#{descriptions.join(', ')})"
  end

  def accept(visitor)
    visitor.visit_permutation(members)
  end

private

  def root_message(failure)
    if failure.duplicates.any?
      "Duplicate permutation member(s): #{deepest_names(failure.duplicates).inspect}"
    elsif failure.missing.any?
      "Missing required permutation member(s): #{deepest_names(failure.missing).inspect}"
    else
      "Failed to match permutation (#{inspect})"
    end
  end

  def deepest_names(entries)
    deepest = entries.values.compact.max
    entries.select { |_, position| position == deepest }.keys
  end

  def explore(mask, result, source, context, consume_all)
    position = source.bytepos
    failure = Failure.new
    required_seen = @members.all? do |member|
      !member.required || result.key?(member.name)
    end

    members.each_with_index do |member, index|
      next if member?(mask, index)

      success, value = named_parslets[index].apply(source, context, false)
      next_position = source.bytepos

      if success
        next_result = result.merge(value)

        if next_position == position
          source.bytepos = position
          outcome = explore(mask | (1 << index), next_result, source, context, consume_all)
        else
          source.bytepos = next_position
          outcome = explore(mask | (1 << index), next_result, source, context, consume_all)
          source.bytepos = position if outcome.is_a?(Failure)
        end

        return outcome unless outcome.is_a?(Failure)
        failure.merge(outcome)
      else
        source.bytepos = position
        failure.add_cause(value)
      end
    end

    members.each_with_index do |member, index|
      next if member?(mask, index) || member.required

      source.bytepos = position
      outcome = explore(mask | (1 << index), result, source, context, consume_all)
      source.bytepos = position

      return outcome unless outcome.is_a?(Failure)
      failure.merge(outcome)
    end

    terminal_failure = Failure.new

    unless required_seen
      members.each do |member|
        next unless member.required && !result.key?(member.name)

        cause = context.err_at(
          self, source,
          "Missing required permutation member #{member.name.inspect}",
          source.pos
        ).last
        terminal_failure.add_missing(member.name, cause)
      end
    end

    duplicate_failure = duplicate_failure(result, source, context)
    if duplicate_failure
      terminal_failure.merge(duplicate_failure)
    elsif required_seen && duplicate_failure.nil?
      if consume_all && source.chars_left > 0
        cause = context.err_at(
          self, source,
          'Extra input after last permutation',
          source.pos
        ).last
        terminal_failure.add_cause(cause)
        return failure.merge(terminal_failure)
      end

      source.bytepos = position
      return result
    end

    failure.merge(terminal_failure)
  end

  def duplicate_failure(result, source, context)
    position = source.bytepos
    failure = nil

    members.each_with_index do |member, index|
      next unless result.key?(member.name)

      success, _ = named_parslets[index].apply(source, context, false)
      next_position = source.bytepos
      source.bytepos = position

      if success && next_position != position
        failure ||= Failure.new
        cause = context.err_at(
          self, source,
          "Duplicate permutation member #{member.name.inspect}",
          source.pos
        ).last
        failure.add_duplicate(member.name, cause)
      end
    end

    failure
  end

  def member?(mask, index)
    mask & (1 << index) != 0
  end

  attr_reader :named_parslets
end

Parslet::Atoms::Group = Parslet::Atoms::Permutation
