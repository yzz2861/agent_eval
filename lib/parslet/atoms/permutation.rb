
# Matches a set of named members in any order, with every member appearing at
# most once. Required members must all appear, while optional members may be
# omitted. The successful result is a hash keyed by member name.
#
class Parslet::Atoms::Permutation < Parslet::Atoms::Base
  Member = Struct.new(:name, :parslet, :required)

  class Builder
    attr_reader :members, :owner

    def initialize(owner=nil)
      @members = []
      @owner = owner
    end

    def required(name, parslet)
      add(name, parslet, true)
    end

    def optional(name, parslet)
      add(name, parslet, false)
    end

    def member(name, parslet, required=false)
      add(name, parslet, required)
    end

  private
    def add(name, parslet, required)
      members << Member.new(name, parslet, required)
      parslet
    end

    def method_missing(name, *args, &block)
      if owner && owner.respond_to?(name, true)
        owner.send(name, *args, &block)
      else
        super
      end
    end

    def respond_to_missing?(name, include_private=false)
      (owner && owner.respond_to?(name, include_private)) || super
    end
  end

  attr_reader :members

  def initialize(*members, &block)
    super()

    if block
      owner = eval('self', block.binding)
      builder = Builder.new(owner)
      if block.arity == 1
        block.call(builder)
      else
        builder.instance_eval(&block)
      end
      members.concat(builder.members)
    end

    @members = members
    validate_members
  end

  def error_msgs
    @error_msgs ||= {
      duplicate: "Duplicate member in permutation",
      missing: "Missing required member in permutation (#{inspect})",
      failed: "Failed to match permutation (#{inspect})"
    }
  end

  def cached?
    false
  end

  def try(source, context, consume_all)
    result = empty_result
    status, value = match_members(source, context, consume_all, 0, result)

    return succ(value) if status == :success

    message =
      case status
      when :duplicate
        "#{error_msgs[:duplicate]} (#{value.inspect})"
      when :missing
        error_msgs[:missing]
      else
        error_msgs[:failed]
      end

    children = status == :duplicate ? nil : (value ? [value] : nil)
    context.err(self, source, message, children)
  end

  precedence BASE
  def to_s_inner(prec)
    parts = members.map do |member|
      marker = member.required ? '' : '?'
      "#{member.name}:#{member.parslet.to_s(prec)}#{marker}"
    end
    "permute(#{parts.join(', ')})"
  end

private
  def validate_members
    names = members.map(&:name)
    duplicates = names.select { |name| names.count(name) > 1 }.uniq
    unless duplicates.empty?
      raise ArgumentError, "Duplicate member names: #{duplicates.inspect}"
    end
  end

  def empty_result
    members.each_with_object({}) do |member, result|
      result[member.name] = nil
    end
  end

  def required_mask
    @required_mask ||= members.each_with_index.inject(0) do |mask, (member, index)|
      member.required ? mask | (1 << index) : mask
    end
  end

  def match_members(source, context, consume_all, used, result)
    failure = nil

    members.each_with_index do |member, index|
      next if used & (1 << index) != 0

      position = source.bytepos
      success, value = member.parslet.apply(source, context, false)

      if success
        advanced = source.bytepos != position

        if !advanced && !member.required
          source.bytepos = position
          next
        end

        previous_value = result[member.name]
        result[member.name] = member_value(member, value)

        status, child_value = match_members(
          source, context, consume_all,
          used | (1 << index), result
        )

        if status == :success
          return [status, child_value]
        elsif status == :duplicate
          source.bytepos = position
          result[member.name] = previous_value
          return [status, child_value]
        else
          failure = deeper_failure(failure, child_value || failure)
        end

        source.bytepos = position
        result[member.name] = previous_value
      else
        failure = deeper_failure(failure, value)
      end
    end

    duplicate = duplicate_member(source, used)
    return [:duplicate, duplicate] if duplicate

    if (used & required_mask) == required_mask
      return [:failure, failure] if consume_all && source.chars_left > 0

      [:success, result]
    else
      [:missing, failure]
    end
  end

  def duplicate_member(source, used)
    position = source.bytepos

    members.each_with_index do |member, index|
      next if used & (1 << index) == 0

      success, _ = member.parslet.apply(
        source, Parslet::Atoms::Context.new, false)
      end_position = source.bytepos
      detected = success && end_position != position
      source.bytepos = detected ? end_position : position
      return member.name if detected
    end

    source.bytepos = position
    nil
  end

  def member_value(member, value)
    value = flatten(value, true)
    return value[member.name] if value.is_a?(Hash) && value.key?(member.name)
    value
  end

  def deeper_failure(current, candidate)
    return candidate if current.nil?
    return candidate if candidate.nil?
    candidate.pos >= current.pos ? candidate : current
  end
end
