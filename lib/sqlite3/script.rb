# frozen_string_literal: true

module SQLite3
  # Iterates over the results of a SQL script containing one or more
  # statements. A Script is normally created with Database#script.
  class Script
    include Enumerable

    # Creates a script iterator attached to +database+. Statement boundaries in
    # +sql+ are identified by SQLite's SQL parser.
    def initialize(database, sql)
      raise ArgumentError, "script called on a closed database" if database.closed?

      @database = database
      @sql = sql
      @statement = nil
      @result_set = nil
      @closed = false
    end

    # Executes the next statement. A statement that returns rows yields a
    # ResultSet; any other statement returns the number of rows changed.
    # Returns +nil+ when the script has no more statements.
    #
    # Bind parameters supplied to this call are bound only to this statement.
    def next_result(*bind_vars)
      return nil if closed?

      begin
        close_current_statement!
        until @sql.nil? || @sql.strip.empty?
          @statement = @database.prepare(@sql)
          if @statement.closed?
            @sql = @statement.remainder
            @statement = nil
            next
          end

          remainder = @statement.remainder
          @sql = remainder
          validate_bind_parameters!(@statement, bind_vars)
          result_set = @statement.execute(*bind_vars)

          if @statement.column_count.zero?
            changes = @database.changes
            @statement.close
            @statement = nil
            return changes
          else
            @result_set = result_set
            return result_set
          end
        end

        @closed = true
        nil
      rescue ::Exception
        close
        raise
      end
    end

    # Iterates over each statement result. See #next_result for the values
    # that are yielded. Unfinished statements and the script are closed when
    # iteration stops early or raises.
    def each
      return to_enum(:each) unless block_given?

      begin
        while (result = next_result)
          yield result
        end
        self
      ensure
        close
      end
    end

    # Closes the statement backing the current result and marks the script as
    # finished. Already-executed statements are not rolled back.
    def close
      close_current_statement!
      @sql = nil
      @closed = true
      self
    end

    # Returns +true+ after all script statements have been consumed or #close
    # has been called.
    def closed?
      @closed || @sql.nil?
    end

    private

    def close_current_statement!
      @result_set = nil
      @statement&.close unless @statement&.closed?
      @statement = nil
    end

    def validate_bind_parameters!(statement, bind_vars)
      positional_count = 0
      named_keys = []

      bind_vars.flatten.each do |bind_var|
        if Hash === bind_var
          named_keys.concat(bind_var.keys.map { |key| normalize_named_key(key) })
        else
          positional_count += 1
        end
      end

      required_named_keys = statement.named_params
      required_positional_count = statement.bind_parameter_count - required_named_keys.length
      missing = []
      if positional_count != required_positional_count
        missing << "#{positional_count} of #{required_positional_count} positional"
      end
      missing_names = required_named_keys - named_keys
      missing << "named #{missing_names.join(", ")}" unless missing_names.empty?

      return if missing.empty?

      raise ArgumentError, "wrong number of bind parameters for statement (#{missing.join("; ")} missing or incorrect)"
    end

    def normalize_named_key(key)
      name = key.to_s
      name.start_with?(":") ? name[1..] : name
    end
  end
end
