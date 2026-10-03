# frozen_string_literal: true

module StateMachines
  class Machine
    # Provides per-object storage and draining of events that were fired
    # while the object was in a state configured to defer them (or while
    # another transition was still running its callbacks).
    module DeferredEvents
      # The default maximum number of deferred events stored per object and
      # per machine.
      DEFAULT_DEFERRED_QUEUE_SIZE = 10

      # The maximum number of deferred events kept for a single object.
      attr_reader :deferred_queue_size

      # Returns (and lazily creates) the bounded queue of deferred events
      # belonging to this machine on the given object.  Queues are stored in
      # per-object, per-machine instance variables so that objects and machines
      # never share a queue.
      def deferred_event_queue(object)
        object.instance_variable_get(deferred_queue_ivar) ||
          object.instance_variable_set(deferred_queue_ivar, DeferredEventQueue.new(@deferred_queue_size))
      end

      # The events currently deferred for the given object, oldest first.
      def deferred_events(object)
        queue = object.instance_variable_get(deferred_queue_ivar)
        queue ? queue.entries.dup : []
      end

      # Records an event for later processing.  Raises
      # StateMachines::DeferredEventQueue::QueueFull when the object's bounded
      # queue is already full; the event is then dropped and never processed.
      def enqueue_deferred_event(object, entry)
        deferred_event_queue(object).add(entry)
      end

      # Builds an independent copy of +source+'s queue on +target+ (used when
      # an object is copied).  The queue structure and its pending entries are
      # duplicated; the argument objects themselves are copied per Ruby's
      # normal copy semantics (shallow copy).
      def dup_deferred_event_queue(source, target)
        source_queue = source.instance_variable_get(deferred_queue_ivar)
        return unless source_queue

        target_queue = DeferredEventQueue.new(@deferred_queue_size)
        source_queue.entries.each do |entry|
          target_queue.add(DeferredEvent.new(name: entry.name, args: entry.args.dup, bang: entry.bang))
        end
        target.instance_variable_set(deferred_queue_ivar, target_queue)
      end

      # Attempts to consume every event deferred for the object exactly once.
      # Executable events are fired in FIFO order; events that still cannot
      # fire remain at the front of the queue and are retried only after a
      # later state change.
      #
      # Failures of non-bang events (invalid transition returning false) do
      # not stop the drain.  Exceptions raised by callbacks or by queued bang
      # events propagate to the caller; entries not yet attempted are restored
      # to the queue before the exception bubbles up.
      def drain_deferred_events(object)
        queue = deferred_event_queue(object)
        return true if queue.empty? || queue.transitioning?

        batch = queue.begin_pass!
        attempted = 0
        begin
          batch.each do |entry|
            event = events[entry.name, :name]
            # Bang entries are always attempted: if the transition is still
            # unavailable they must raise InvalidTransition rather than being
            # silently retained.  Non-bang entries that are not executable are
            # kept and retried after a later state change.
            if event && (entry.bang || event.can_fire?(object))
              attempted += 1
              event.fire_queued_event(object, entry)
            else
              queue.keep(entry)
              attempted += 1
            end
          end
        rescue StandardError
          # Entries never reached remain queued for a later state change.
          queue.abort_pass!(attempted)
          raise
        else
          queue.end_pass!
        end
        true
      end

      # Tracks events invoked through their bang helper.  The marker is kept
      # in thread-local storage so that bang semantics survive delegation
      # through user-overridden non-bang event methods and through deferred
      # queue draining, while never leaking across threads.
      def with_bang_event(object, event_name)
        marker = [object.object_id, event_name.to_sym]
        Thread.current[:state_machines_bang_events] ||= []
        Thread.current[:state_machines_bang_events] << marker
        begin
          yield
        ensure
          Thread.current[:state_machines_bang_events].pop
        end
      end

      # Whether the given event on the given object was invoked via the bang
      # helper in the current call stack.
      def bang_event_call?(object, event_name)
        stack = Thread.current[:state_machines_bang_events]
        !!(stack && stack.include?([object.object_id, event_name.to_sym]))
      end

      private

      # Per-machine storage slot used on each object.
      def deferred_queue_ivar
        @deferred_queue_ivar ||= :"@_state_machine_deferred_events_#{object_id}"
      end
    end
  end
end
