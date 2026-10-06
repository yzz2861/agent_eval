# frozen_string_literal: true
require_relative "task"
require_relative "early_time"

module Rake

  # A FileTask is a task that includes time based dependencies.  If any of a
  # FileTask's prerequisites have a timestamp that is later than the file
  # represented by this task, then the file must be rebuilt (using the
  # supplied actions).
  #
  class FileTask < Task

    # Is this file task needed?  Yes if it doesn't exist, or if its time stamp
    # is out of date.
    def needed?
      begin
        out_of_date?(File.mtime(name)) || @application.options.build_all
      rescue Errno::ENOENT
        true
      end
    end

    # Time stamp for file task.
    def timestamp
      begin
        File.mtime(name)
      rescue Errno::ENOENT
        Rake::LATE
      end
    end

    private

    # Are there any prerequisites with a later time than the given time stamp?
    def out_of_date?(stamp)
      prerequisite_tasks_for_timestamp.any? { |prereq|
        prereq_task = application[prereq, @scope]
        if prereq_task.instance_of?(Rake::FileTask)
          prereq_task.timestamp > stamp || @application.options.build_all
        else
          prereq_task.timestamp > stamp
        end
      }
    end

    def prerequisite_tasks_for_timestamp # :nodoc:
      collect_prerequisite_tasks_for_timestamp(prerequisites, {})
    end
    private :prerequisite_tasks_for_timestamp

    def collect_prerequisite_tasks_for_timestamp(names, seen) # :nodoc:
      names.flat_map do |name|
        next [] if seen[name]

        seen[name] = true
        prerequisite = lookup_prerequisite(name)
        [prerequisite].concat(
          collect_prerequisite_tasks_for_timestamp(
            prerequisite.prerequisites, seen))
      end
    end
    private :collect_prerequisite_tasks_for_timestamp

    # ----------------------------------------------------------------
    # Task class methods.
    #
    class << self
      # Apply the scope to the task name according to the rules for this kind
      # of task.  File based tasks ignore the scope when creating the name.
      def scope_name(scope, task_name)
        Rake.from_pathname(task_name)
      end
    end
  end
end
