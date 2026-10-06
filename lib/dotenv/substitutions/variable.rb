require "English"

module Dotenv
  module Substitutions
    # Substitute variables in a value.
    #
    #   HOST=example.com
    #   URL="https://$HOST"
    #
    module Variable
      VARIABLE = /
        (\\)?         # is it escaped with a backslash?
        (\$)          # literal $
        (?!\()        # shouldn't be followed by parenthesis
        \{?           # allow brace wrapping
        ([A-Z0-9_]+)? # optional alpha nums
        \}?           # closing brace
      /xi

      class << self
        def call(value, env)
          value.gsub(VARIABLE) do |variable|
            match = $LAST_MATCH_INFO

            if match[1] == "\\"
              variable[1..]
            elsif env.respond_to?(:variable_value)
              env.variable_value(match[3])
            elsif match[3]
              if env.key?(match[3])
                env[match[3]] || ""
              else
                ENV.key?(match[3]) ? ENV[match[3]] : ""
              end
            else
              variable
            end
          end
        end
      end
    end
  end
end
