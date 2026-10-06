module Dotenv
  # A variable definition as written in a .env file, before substitutions are applied.
  Definition = Struct.new(:key, :value, :quote, :filename, :source_id, :line, keyword_init: true) do
    def single_quoted?
      quote == "'"
    end
  end

  # The contents of one .env file before parsing and resolution.
  Source = Struct.new(:filename, :content, keyword_init: true)
end
