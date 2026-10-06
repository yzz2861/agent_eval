require "English"

module Dotenv
  module Substitutions
    # Substitute variables in a value.
    #
    #   HOST=example.com
    #   URL="https://$HOST"
    #
    module Variable
      class << self
        VARIABLE = /
          (\\)?         # is it escaped with a backslash?
          (\$)          # literal $
          (?!\()        # shouldn't be followed by parenthesis
          \{?           # allow brace wrapping
          ([A-Z0-9_]+)? # optional alpha nums
          \}?           # closing brace
        /xi

        # Substitute variables in a value, looking them up in +env+.
        #
        # @param value [String] the value to substitute variables in
        # @param env [Hash] the environment view to read variables from
        # @param fallback [Hash, nil] where to look up variables missing from
        #   +env+. Defaults to the process +ENV+. Pass +nil+ to resolve
        #   variables only within +env+.
        def call(value, env, fallback: ENV)
          value.gsub(VARIABLE) do |variable|
            match = $LAST_MATCH_INFO

            if match[1] == "\\"
              variable[1..]
            elsif match[3]
              env[match[3]] || fallback&.[](match[3]) || ""
            else
              variable
            end
          end
        end
      end
    end
  end
end
