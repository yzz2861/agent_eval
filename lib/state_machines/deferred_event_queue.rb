# frozen_string_literal: true

module StateMachines
  # A single event that could not be processed immediately and was stored on
  # an object for later processing.  The original positional arguments are
  # preserved so that the event is replayed exactly as it was originally
  # fired.
  DeferredEvent = Struct.new(:name, :args, :bang, keyword_init: true) do
  end

  # A bounded, per-object FIFO queue of events that were deferred while the
  # object was in a state configured to defer them.  Each state machine stores
  # its own queue on every object, so two machines (or two distinct objects)
  # never share a queue.
  #
  # Two kinds of nesting are tracked:
  # * A *transition* is being performed (from before-callback through
  #   after-callback).  Any event fired while the outermost transition is
  #   running is recorded and never re-entered synchronously.
  # * A *drain pass* is consuming a captured batch of deferred events.  A
  #   captured entry is attempted at most once per pass: entries that are
  #   still not executable are set aside and only revisited after a later
  #   state change, so they cannot spin in place.
  class DeferredEventQueue
    # Raised when an event is deferred but the object's queue is already full
    class QueueFull < StateMachines::Error
      def initialize(object, event_name, size) # :nodoc:
        super(object, "Deferred event queue for #{event_name.inspect} is full (limit #{size})")
        @event_name = event_name
        @size = size
      end

      # The event that could not be queued
      attr_reader :event_name

      # The configured capacity of the queue
      attr_reader :size
    end

    # State of a single drain pass.  +entries+ is the batch captured when the
    # pass began and +requeued+ collects entries that could not be processed
    # and must stay deferred until the next state change.
    Pass = Struct.new(:entries, :requeued, keyword_init: true)

    def initialize(size) # :nodoc:
      @size = size
      @entries = []
      @transition_depth = 0
      @passes = []
    end

    # The maximum number of events that may be stored at once
    attr_reader :size

    # The events currently waiting to be processed (oldest first)
    attr_reader :entries

    # Number of events currently stored
    def length
      @entries.length
    end

    alias count length

    # Whether any events are currently stored
    def empty?
      @entries.empty?
    end

    # Stores an event for later processing.  Raises QueueFull if the queue is
    # already at its configured capacity.
    def add(entry)
      if @entries.length >= @size
        raise QueueFull.new(nil, entry.name, @size)
      end

      @entries << entry
      entry
    end

    # Marks the start of a transition (and its callbacks) on the object.
    def begin_transition!
      @transition_depth += 1
    end

    # Marks the end of a transition.  Returns true when this was the
    # outermost transition, meaning its callbacks have now all finished.
    def end_transition!
      @transition_depth -= 1 if @transition_depth.positive?
      @transition_depth.zero?
    end

    # Whether a transition or a drain pass is currently active on the object.
    # Events fired while this is true are recorded instead of running inline.
    def busy?
      @transition_depth.positive? || !@passes.empty?
    end

    # Whether a transition (with its callbacks) is currently running
    def transitioning?
      @transition_depth.positive?
    end

    # Begins a new drain pass, atomically moving every currently stored event
    # out of the queue.  Events enqueued while the pass is running (for
    # example from within a callback) accumulate in a fresh queue and are not
    # revisited by this pass.
    def begin_pass!
      @passes << Pass.new(entries: @entries, requeued: [])
      @entries = []
      last_pass.entries
    end

    # Whether a drain pass is currently in progress on this object
    def draining?
      !@passes.empty?
    end

    # Marks an entry from the current pass as still not executable.  It is
    # kept in insertion order and moved to the front of the queue (before any
    # events enqueued during the pass) when the pass finishes.
    def keep(entry)
      last_pass.requeued << entry
    end

    # Ends the current drain pass, restoring events that could not be
    # processed to the front of the queue.  Returns true if this was the
    # outermost pass.
    def end_pass!
      pass = @passes.pop
      @entries = pass.requeued + @entries
      @passes.empty?
    end

    # Aborts the current pass because an exception escaped an attempted
    # event: every entry that had not been attempted yet is restored to the
    # front of the queue (before entries enqueued during the pass).
    def abort_pass!(attempted_count)
      pass = @passes.pop
      remaining = pass.entries[attempted_count..] || []
      @entries = pass.requeued + remaining + @entries
      @passes.empty?
    end

    private

    def last_pass
      @passes.last
    end
  end
end
