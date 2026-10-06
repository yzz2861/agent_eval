module Dotenv
  # A source .env file before variable values are resolved.
  class Source
    attr_reader :filename, :content

    def initialize(filename, content)
      @filename = filename
      @content = content
    end
  end
end
