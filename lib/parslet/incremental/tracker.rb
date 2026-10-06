class Parslet::Incremental::Tracker
  # One frame per atom application currently being computed. A frame
  # accumulates everything the parse observes while the corresponding atom
  # (including all nested atoms) is tried:
  #
  # max_examined::  highest byte offset (exclusive) whose content was read
  # len_from::      lowest byte offset from which the remaining input
  #                 length was observed (end-of-input checks), or nil
  # writes::        captures written while the frame was open
  #
  class Frame
    attr_accessor :max_examined, :len_from, :writes

    def initialize
      @max_examined = 0
      @len_from = nil
      @writes = {}
    end

    def observe_content(upto)
      @max_examined = upto if upto > @max_examined
    end

    def observe_length(from)
      @len_from = from if from && (@len_from.nil? || from < @len_from)
    end
  end

  def initialize
    @frames = []
  end

  def push_frame
    @frames.push(Frame.new)
  end

  # Pops the innermost frame and merges its observations into its parent:
  # whatever a nested atom observed, the enclosing atom observed as well.
  #
  def pop_frame
    frame = @frames.pop
    return unless frame

    if (parent = @frames.last)
      parent.observe_content(frame.max_examined)
      parent.observe_length(frame.len_from)
      frame.writes.each { |name, value| parent.writes[name] = value }
    end

    frame
  end

  # Records that input content up to byte offset +upto+ (exclusive) has
  # been read.
  #
  def observe_content(upto)
    @frames.last.observe_content(upto) if @frames.last
  end

  # Records that the remaining input length was observed from byte offset
  # +from+ on (an end-of-input check). This makes the observation depend on
  # the total input length, not just on content.
  #
  def observe_length(from)
    @frames.last.observe_length(from) if @frames.last && from
  end

  # Records a capture write so it can be replayed when a cached entry is
  # reused.
  #
  def observe_write(name, value)
    @frames.last.writes[name] = value if @frames.last
  end
end
