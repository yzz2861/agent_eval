# frozen_string_literal: true

require "forwardable"

class CSV
  # = \CSV::Table
  # A \CSV::Table instance represents \CSV data.
  # (see {class CSV}[../CSV.html]).
  #
  # The instance may have:
  # - Rows: each is a Table::Row object.
  # - Headers: names for the columns.
  #
  # === Instance Methods
  #
  # \CSV::Table has three groups of instance methods:
  # - Its own internally defined instance methods.
  # - Methods included by module Enumerable.
  # - Methods delegated to class Array.:
  #   * Array#empty?
  #   * Array#length
  #   * Array#size
  #
  # == Creating a \CSV::Table Instance
  #
  # Commonly, a new \CSV::Table instance is created by parsing \CSV source
  # using headers:
  #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
  #   table = CSV.parse(source, headers: true)
  #   table.class # => CSV::Table
  #
  # You can also create an instance directly. See ::new.
  #
  # == Headers
  #
  # If a table has headers, the headers serve as labels for the columns of data.
  # Each header serves as the label for its column.
  #
  # The headers for a \CSV::Table object are stored as an \Array of Strings.
  #
  # Commonly, headers are defined in the first row of \CSV source:
  #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
  #   table = CSV.parse(source, headers: true)
  #   table.headers # => ["Name", "Value"]
  #
  # If no headers are defined, the \Array is empty:
  #   table = CSV::Table.new([])
  #   table.headers # => []
  #
  # == Access Modes
  #
  # \CSV::Table provides three modes for accessing table data:
  # - \Row mode.
  # - Column mode.
  # - Mixed mode (the default for a new table).
  #
  # The access mode for a\CSV::Table instance affects the behavior
  # of some of its instance methods:
  # - #[]
  # - #[]=
  # - #delete
  # - #delete_if
  # - #each
  # - #values_at
  #
  # === \Row Mode
  #
  # Set a table to row mode with method #by_row!:
  #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
  #   table = CSV.parse(source, headers: true)
  #   table.by_row! # => #<CSV::Table mode:row row_count:4>
  #
  # Specify a single row by an \Integer index:
  #   # Get a row.
  #   table[1] # => #<CSV::Row "Name":"bar" "Value":"1">
  #   # Set a row, then get it.
  #   table[1] = CSV::Row.new(['Name', 'Value'], ['bam', 3])
  #   table[1] # => #<CSV::Row "Name":"bam" "Value":3>
  #
  # Specify a sequence of rows by a \Range:
  #   # Get rows.
  #   table[1..2] # => [#<CSV::Row "Name":"bam" "Value":3>, #<CSV::Row "Name":"baz" "Value":"2">]
  #   # Set rows, then get them.
  #   table[1..2] = [
  #     CSV::Row.new(['Name', 'Value'], ['bat', 4]),
  #     CSV::Row.new(['Name', 'Value'], ['bad', 5]),
  #   ]
  #   table[1..2] # => [["Name", #<CSV::Row "Name":"bat" "Value":4>], ["Value", #<CSV::Row "Name":"bad" "Value":5>]]
  #
  # === Column Mode
  #
  # Set a table to column mode with method #by_col!:
  #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
  #   table = CSV.parse(source, headers: true)
  #   table.by_col! # => #<CSV::Table mode:col row_count:4>
  #
  # Specify a column by an \Integer index:
  #   # Get a column.
  #   table[0]
  #   # Set a column, then get it.
  #   table[0] = ['FOO', 'BAR', 'BAZ']
  #   table[0] # => ["FOO", "BAR", "BAZ"]
  #
  # Specify a column by its \String header:
  #   # Get a column.
  #   table['Name'] # => ["FOO", "BAR", "BAZ"]
  #   # Set a column, then get it.
  #   table['Name'] = ['Foo', 'Bar', 'Baz']
  #   table['Name'] # => ["Foo", "Bar", "Baz"]
  #
  # === Mixed Mode
  #
  # In mixed mode, you can refer to either rows or columns:
  # - An \Integer index refers to a row.
  # - A \Range index refers to multiple rows.
  # - A \String index refers to a column.
  #
  # Set a table to mixed mode with method #by_col_or_row!:
  #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
  #   table = CSV.parse(source, headers: true)
  #   table.by_col_or_row! # => #<CSV::Table mode:col_or_row row_count:4>
  #
  # Specify a single row by an \Integer index:
  #   # Get a row.
  #   table[1] # => #<CSV::Row "Name":"bar" "Value":"1">
  #   # Set a row, then get it.
  #   table[1] = CSV::Row.new(['Name', 'Value'], ['bam', 3])
  #   table[1] # => #<CSV::Row "Name":"bam" "Value":3>
  #
  # Specify a sequence of rows by a \Range:
  #   # Get rows.
  #   table[1..2] # => [#<CSV::Row "Name":"bam" "Value":3>, #<CSV::Row "Name":"baz" "Value":"2">]
  #   # Set rows, then get them.
  #   table[1] = CSV::Row.new(['Name', 'Value'], ['bat', 4])
  #   table[2] = CSV::Row.new(['Name', 'Value'], ['bad', 5])
  #   table[1..2] # => [["Name", #<CSV::Row "Name":"bat" "Value":4>], ["Value", #<CSV::Row "Name":"bad" "Value":5>]]
  #
  # Specify a column by its \String header:
  #   # Get a column.
  #   table['Name'] # => ["foo", "bat", "bad"]
  #   # Set a column, then get it.
  #   table['Name'] = ['Foo', 'Bar', 'Baz']
  #   table['Name'] # => ["Foo", "Bar", "Baz"]
  class Table
    # Used internally to distinguish an absent pivoted coordinate from a
    # coordinate whose value is truly +nil+.
    MISSING_HEADER = Object.new.freeze
    private_constant(:MISSING_HEADER)

    class PivotRow < Row
      def initialize(headers, pairs)
        super([], [])
        @pivot_headers = headers
        @row = pairs
      end

      def headers
        @pivot_headers.dup
      end

      def has_key?(header)
        return false if header.equal?(MISSING_HEADER)

        super
      end
      alias_method :include?, :has_key?
      alias_method :key?, :has_key?
      alias_method :member?, :has_key?
      alias_method :header?, :has_key?

      def each(&block)
        return enum_for(__method__) do
          @row.count { |pair| !pair.first.equal?(MISSING_HEADER) }
        end unless block_given?

        @row.each do |pair|
          next if pair.first.equal?(MISSING_HEADER)

          yield(pair)
        end

        self
      end
      alias_method :each_pair, :each
    end
    private_constant(:PivotRow)

    # :call-seq:
    #   CSV::Table.new(array_of_rows, headers = nil) -> csv_table
    #
    # Returns a new \CSV::Table object.
    #
    # - Argument +array_of_rows+ must be an \Array of CSV::Row objects.
    # - Argument +headers+, if given, may be an \Array of Strings.
    #
    # ---
    #
    # Create an empty \CSV::Table object:
    #   table = CSV::Table.new([])
    #   table # => #<CSV::Table mode:col_or_row row_count:1>
    #
    # Create a non-empty \CSV::Table object:
    #   rows = [
    #     CSV::Row.new([], []),
    #     CSV::Row.new([], []),
    #     CSV::Row.new([], []),
    #   ]
    #   table  = CSV::Table.new(rows)
    #   table # => #<CSV::Table mode:col_or_row row_count:4>
    #
    # ---
    #
    # If argument +headers+ is an \Array of Strings,
    # those Strings become the table's headers:
    #   table = CSV::Table.new([], headers: ['Name', 'Age'])
    #   table.headers # => ["Name", "Age"]
    #
    # If argument +headers+ is not given and the table has rows,
    # the headers are taken from the first row:
    #   rows = [
    #     CSV::Row.new(['Foo', 'Bar'], []),
    #     CSV::Row.new(['foo', 'bar'], []),
    #     CSV::Row.new(['FOO', 'BAR'], []),
    #   ]
    #   table  = CSV::Table.new(rows)
    #   table.headers # => ["Foo", "Bar"]
    #
    # If argument +headers+ is not given and the table is empty (has no rows),
    # the headers are also empty:
    #   table  = CSV::Table.new([])
    #   table.headers # => []
    #
    # ---
    #
    # Raises an exception if argument +array_of_rows+ is not an \Array object:
    #   # Raises NoMethodError (undefined method `first' for :foo:Symbol):
    #   CSV::Table.new(:foo)
    #
    # Raises an exception if an element of +array_of_rows+ is not a \CSV::Table object:
    #   # Raises NoMethodError (undefined method `headers' for :foo:Symbol):
    #   CSV::Table.new([:foo])
    def initialize(array_of_rows, headers: nil)
      @table = array_of_rows
      @headers = headers
      unless @headers
        if @table.empty?
          @headers = []
        else
          @headers = @table.first.headers
        end
      end

      @mode  = :col_or_row
    end

    # The current access mode for indexing and iteration.
    attr_reader :mode

    # Internal data format used to compare equality.
    attr_reader :table
    protected   :table

    ### Array Delegation ###

    extend Forwardable
    def_delegators :@table, :empty?, :length, :size

    # :call-seq:
    #   table.by_col -> table_dup
    #
    # Returns a duplicate of +self+, in column mode
    # (see {Column Mode}[#class-CSV::Table-label-Column+Mode]):
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.mode # => :col_or_row
    #   dup_table = table.by_col
    #   dup_table.mode # => :col
    #   dup_table.equal?(table) # => false # It's a dup
    #
    # This may be used to chain method calls without changing the mode
    # (but also will affect performance and memory usage):
    #   dup_table.by_col['Name']
    #
    # Also note that changes to the duplicate table will not affect the original.
    def by_col
      self.class.new(@table.dup).by_col!
    end

    # :call-seq:
    #   table.by_col! -> self
    #
    # Sets the mode for +self+ to column mode
    # (see {Column Mode}[#class-CSV::Table-label-Column+Mode]); returns +self+:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.mode # => :col_or_row
    #   table1 = table.by_col!
    #   table.mode # => :col
    #   table1.equal?(table) # => true # Returned self
    def by_col!
      @mode = :col

      self
    end

    # :call-seq:
    #   table.by_col_or_row -> table_dup
    #
    # Returns a duplicate of +self+, in mixed mode
    # (see {Mixed Mode}[#class-CSV::Table-label-Mixed+Mode]):
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true).by_col!
    #   table.mode # => :col
    #   dup_table = table.by_col_or_row
    #   dup_table.mode # => :col_or_row
    #   dup_table.equal?(table) # => false # It's a dup
    #
    # This may be used to chain method calls without changing the mode
    # (but also will affect performance and memory usage):
    #   dup_table.by_col_or_row['Name']
    #
    # Also note that changes to the duplicate table will not affect the original.
    def by_col_or_row
      self.class.new(@table.dup).by_col_or_row!
    end

    # :call-seq:
    #   table.by_col_or_row! -> self
    #
    # Sets the mode for +self+ to mixed mode
    # (see {Mixed Mode}[#class-CSV::Table-label-Mixed+Mode]); returns +self+:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true).by_col!
    #   table.mode # => :col
    #   table1 = table.by_col_or_row!
    #   table.mode # => :col_or_row
    #   table1.equal?(table) # => true # Returned self
    def by_col_or_row!
      @mode = :col_or_row

      self
    end

    # :call-seq:
    #   table.by_row -> table_dup
    #
    # Returns a duplicate of +self+, in row mode
    # (see {Row Mode}[#class-CSV::Table-label-Row+Mode]):
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.mode # => :col_or_row
    #   dup_table = table.by_row
    #   dup_table.mode # => :row
    #   dup_table.equal?(table) # => false # It's a dup
    #
    # This may be used to chain method calls without changing the mode
    # (but also will affect performance and memory usage):
    #   dup_table.by_row[1]
    #
    # Also note that changes to the duplicate table will not affect the original.
    def by_row
      self.class.new(@table.dup).by_row!
    end

    # :call-seq:
    #   table.by_row! -> self
    #
    # Sets the mode for +self+ to row mode
    # (see {Row Mode}[#class-CSV::Table-label-Row+Mode]); returns +self+:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.mode # => :col_or_row
    #   table1 = table.by_row!
    #   table.mode # => :row
    #   table1.equal?(table) # => true # Returned self
    def by_row!
      @mode = :row

      self
    end

    # :call-seq:
    #   table.headers -> array_of_headers
    #
    # Returns a new \Array containing the \String headers for the table.
    #
    # If the table is not empty, returns the headers from the first row:
    #   rows = [
    #     CSV::Row.new(['Foo', 'Bar'], []),
    #     CSV::Row.new(['FOO', 'BAR'], []),
    #     CSV::Row.new(['foo', 'bar'], []),
    #   ]
    #   table  = CSV::Table.new(rows)
    #   table.headers # => ["Foo", "Bar"]
    #   table.delete(0)
    #   table.headers # => ["FOO", "BAR"]
    #   table.delete(0)
    #   table.headers # => ["foo", "bar"]
    #
    # If the table is empty, returns a copy of the headers in the table itself:
    #   table.delete(0)
    #   table.headers # => ["Foo", "Bar"]
    def headers
      if @table.empty?
        @headers.dup
      else
        @table.first.headers
      end
    end

    # :call-seq:
    #   table[n] -> row or column_data
    #   table[range] -> array_of_rows or array_of_column_data
    #   table[header] -> array_of_column_data
    #
    # Returns data from the table;  does not modify the table.
    #
    # ---
    #
    # Fetch a \Row by Its \Integer Index::
    # - Form: <tt>table[n]</tt>, +n+ an integer.
    # - Access mode: <tt>:row</tt> or <tt>:col_or_row</tt>.
    # - Return value: _nth_ row of the table, if that row exists;
    #   otherwise +nil+.
    #
    # Returns the _nth_ row of the table if that row exists:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.by_row! # => #<CSV::Table mode:row row_count:4>
    #   table[1] # => #<CSV::Row "Name":"bar" "Value":"1">
    #   table.by_col_or_row! # => #<CSV::Table mode:col_or_row row_count:4>
    #   table[1] # => #<CSV::Row "Name":"bar" "Value":"1">
    #
    # Counts backward from the last row if +n+ is negative:
    #   table[-1] # => #<CSV::Row "Name":"baz" "Value":"2">
    #
    # Returns +nil+ if +n+ is too large or too small:
    #   table[4] # => nil
    #   table[-4] # => nil
    #
    # Raises an exception if the access mode is <tt>:row</tt>
    # and +n+ is not an \Integer:
    #   table.by_row! # => #<CSV::Table mode:row row_count:4>
    #   # Raises TypeError (no implicit conversion of String into Integer):
    #   table['Name']
    #
    # ---
    #
    # Fetch a Column by Its \Integer Index::
    # - Form: <tt>table[n]</tt>, +n+ an \Integer.
    # - Access mode: <tt>:col</tt>.
    # - Return value: _nth_ column of the table, if that column exists;
    #   otherwise an \Array of +nil+ fields of length <tt>self.size</tt>.
    #
    # Returns the _nth_ column of the table if that column exists:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.by_col! # => #<CSV::Table mode:col row_count:4>
    #   table[1] # => ["0", "1", "2"]
    #
    # Counts backward from the last column if +n+ is negative:
    #   table[-2] # => ["foo", "bar", "baz"]
    #
    # Returns an \Array of +nil+ fields if +n+ is too large or too small:
    #   table[4] # => [nil, nil, nil]
    #   table[-4] # => [nil, nil, nil]
    #
    # ---
    #
    # Fetch Rows by \Range::
    # - Form: <tt>table[range]</tt>, +range+ a \Range object.
    # - Access mode: <tt>:row</tt> or <tt>:col_or_row</tt>.
    # - Return value: rows from the table, beginning at row <tt>range.start</tt>,
    #   if those rows exists.
    #
    # Returns rows from the table, beginning at row <tt>range.first</tt>,
    # if those rows exist:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.by_row! # => #<CSV::Table mode:row row_count:4>
    #   rows = table[1..2] # => #<CSV::Row "Name":"bar" "Value":"1">
    #   rows # => [#<CSV::Row "Name":"bar" "Value":"1">, #<CSV::Row "Name":"baz" "Value":"2">]
    #   table.by_col_or_row! # => #<CSV::Table mode:col_or_row row_count:4>
    #   rows = table[1..2] # => #<CSV::Row "Name":"bar" "Value":"1">
    #   rows # => [#<CSV::Row "Name":"bar" "Value":"1">, #<CSV::Row "Name":"baz" "Value":"2">]
    #
    # If there are too few rows, returns all from <tt>range.start</tt> to the end:
    #   rows = table[1..50] # => #<CSV::Row "Name":"bar" "Value":"1">
    #   rows # => [#<CSV::Row "Name":"bar" "Value":"1">, #<CSV::Row "Name":"baz" "Value":"2">]
    #
    # Special case: if <tt>range.start == table.size</tt>, returns an empty \Array:
    #   table[table.size..50] # => []
    #
    # If <tt>range.end</tt> is negative, calculates the ending index from the end:
    #   rows = table[0..-1]
    #   rows # => [#<CSV::Row "Name":"foo" "Value":"0">, #<CSV::Row "Name":"bar" "Value":"1">, #<CSV::Row "Name":"baz" "Value":"2">]
    #
    # If <tt>range.start</tt> is negative, calculates the starting index from the end:
    #   rows = table[-1..2]
    #   rows # => [#<CSV::Row "Name":"baz" "Value":"2">]
    #
    # If <tt>range.start</tt> is larger than <tt>table.size</tt>, returns +nil+:
    #   table[4..4] # => nil
    #
    # ---
    #
    # Fetch Columns by \Range::
    # - Form: <tt>table[range]</tt>, +range+ a \Range object.
    # - Access mode: <tt>:col</tt>.
    # - Return value: column data from the table, beginning at column <tt>range.start</tt>,
    #   if those columns exist.
    #
    # Returns column values from the table, if the column exists;
    # the values are arranged by row:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.by_col!
    #   table[0..1] # => [["foo", "0"], ["bar", "1"], ["baz", "2"]]
    #
    # Special case: if <tt>range.start == headers.size</tt>,
    # returns an \Array (size: <tt>table.size</tt>) of empty \Arrays:
    #   table[table.headers.size..50] # => [[], [], []]
    #
    # If <tt>range.end</tt> is negative, calculates the ending index from the end:
    #   table[0..-1] # => [["foo", "0"], ["bar", "1"], ["baz", "2"]]
    #
    # If <tt>range.start</tt> is negative, calculates the starting index from the end:
    #   table[-2..2] # => [["foo", "0"], ["bar", "1"], ["baz", "2"]]
    #
    # If <tt>range.start</tt> is larger than <tt>table.size</tt>,
    # returns an \Array of +nil+ values:
    #   table[4..4] # => [nil, nil, nil]
    #
    # ---
    #
    # Fetch a Column by Its \String Header::
    # - Form: <tt>table[header]</tt>, +header+ a \String header.
    # - Access mode: <tt>:col</tt> or <tt>:col_or_row</tt>
    # - Return value: column data from the table, if that +header+ exists.
    #
    # Returns column values from the table, if the column exists:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.by_col! # => #<CSV::Table mode:col row_count:4>
    #   table['Name'] # => ["foo", "bar", "baz"]
    #   table.by_col_or_row! # => #<CSV::Table mode:col_or_row row_count:4>
    #   col = table['Name']
    #   col # => ["foo", "bar", "baz"]
    #
    # Modifying the returned column values does not modify the table:
    #   col[0] = 'bat'
    #   col # => ["bat", "bar", "baz"]
    #   table['Name'] # => ["foo", "bar", "baz"]
    #
    # Returns an \Array of +nil+ values if there is no such column:
    #   table['Nosuch'] # => [nil, nil, nil]
    def [](index_or_header)
      if @mode == :row or  # by index
         (@mode == :col_or_row and (index_or_header.is_a?(Integer) or index_or_header.is_a?(Range)))
        @table[index_or_header]
      else                 # by header
        @table.map { |row| row[index_or_header] }
      end
    end

    # :call-seq:
    #   table[n] = row -> row
    #   table[n] = field_or_array_of_fields -> field_or_array_of_fields
    #   table[header] = field_or_array_of_fields -> field_or_array_of_fields
    #
    # Puts data onto the table.
    #
    # ---
    #
    # Set a \Row by Its \Integer Index::
    # - Form: <tt>table[n] = row</tt>, +n+ an \Integer,
    #   +row+ a \CSV::Row instance or an \Array of fields.
    # - Access mode: <tt>:row</tt> or <tt>:col_or_row</tt>.
    # - Return value: +row+.
    #
    # If the row exists, it is replaced:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   new_row = CSV::Row.new(['Name', 'Value'], ['bat', 3])
    #   table.by_row! # => #<CSV::Table mode:row row_count:4>
    #   return_value = table[0] = new_row
    #   return_value.equal?(new_row) # => true # Returned the row
    #   table[0].to_h # => {"Name"=>"bat", "Value"=>3}
    #
    # With access mode <tt>:col_or_row</tt>:
    #   table.by_col_or_row! # => #<CSV::Table mode:col_or_row row_count:4>
    #   table[0] = CSV::Row.new(['Name', 'Value'], ['bam', 4])
    #   table[0].to_h # => {"Name"=>"bam", "Value"=>4}
    #
    # With an \Array instead of a \CSV::Row, inherits headers from the table:
    #   array = ['bad', 5]
    #   return_value = table[0] = array
    #   return_value.equal?(array) # => true # Returned the array
    #   table[0].to_h # => {"Name"=>"bad", "Value"=>5}
    #
    # If the row does not exist, extends the table by adding rows:
    # assigns rows with +nil+ as needed:
    #   table.size # => 3
    #   table[5] = ['bag', 6]
    #   table.size # => 6
    #   table[3] # => nil
    #   table[4]# => nil
    #   table[5].to_h # => {"Name"=>"bag", "Value"=>6}
    #
    # Note that the +nil+ rows are actually +nil+, not a row of +nil+ fields.
    #
    # ---
    #
    # Set a Column by Its \Integer Index::
    # - Form: <tt>table[n] = array_of_fields</tt>, +n+ an \Integer,
    #   +array_of_fields+ an \Array of \String fields.
    # - Access mode: <tt>:col</tt>.
    # - Return value: +array_of_fields+.
    #
    # If the column exists, it is replaced:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   new_col = [3, 4, 5]
    #   table.by_col! # => #<CSV::Table mode:col row_count:4>
    #   return_value = table[1] = new_col
    #   return_value.equal?(new_col) # => true # Returned the column
    #   table[1] # => [3, 4, 5]
    #   # The rows, as revised:
    #   table.by_row! # => #<CSV::Table mode:row row_count:4>
    #   table[0].to_h # => {"Name"=>"foo", "Value"=>3}
    #   table[1].to_h # => {"Name"=>"bar", "Value"=>4}
    #   table[2].to_h # => {"Name"=>"baz", "Value"=>5}
    #   table.by_col! # => #<CSV::Table mode:col row_count:4>
    #
    # If there are too few values, fills with +nil+ values:
    #   table[1] = [0]
    #   table[1] # => [0, nil, nil]
    #
    # If there are too many values, ignores the extra values:
    #   table[1] = [0, 1, 2, 3, 4]
    #   table[1] # => [0, 1, 2]
    #
    # If a single value is given, replaces all fields in the column with that value:
    #   table[1] = 'bat'
    #   table[1] # => ["bat", "bat", "bat"]
    #
    # ---
    #
    # Set a Column by Its \String Header::
    # - Form: <tt>table[header] = field_or_array_of_fields</tt>,
    #   +header+ a \String header, +field_or_array_of_fields+ a field value
    #   or an \Array of \String fields.
    # - Access mode: <tt>:col</tt> or <tt>:col_or_row</tt>.
    # - Return value: +field_or_array_of_fields+.
    #
    # If the column exists, it is replaced:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   new_col = [3, 4, 5]
    #   table.by_col! # => #<CSV::Table mode:col row_count:4>
    #   return_value = table['Value'] = new_col
    #   return_value.equal?(new_col) # => true # Returned the column
    #   table['Value'] # => [3, 4, 5]
    #   # The rows, as revised:
    #   table.by_row! # => #<CSV::Table mode:row row_count:4>
    #   table[0].to_h # => {"Name"=>"foo", "Value"=>3}
    #   table[1].to_h # => {"Name"=>"bar", "Value"=>4}
    #   table[2].to_h # => {"Name"=>"baz", "Value"=>5}
    #   table.by_col! # => #<CSV::Table mode:col row_count:4>
    #
    # If there are too few values, fills with +nil+ values:
    #   table['Value'] = [0]
    #   table['Value'] # => [0, nil, nil]
    #
    # If there are too many values, ignores the extra values:
    #   table['Value'] = [0, 1, 2, 3, 4]
    #   table['Value'] # => [0, 1, 2]
    #
    # If the column does not exist, extends the table by adding columns:
    #   table['Note'] = ['x', 'y', 'z']
    #   table['Note'] # => ["x", "y", "z"]
    #   # The rows, as revised:
    #   table.by_row!
    #   table[0].to_h # => {"Name"=>"foo", "Value"=>0, "Note"=>"x"}
    #   table[1].to_h # => {"Name"=>"bar", "Value"=>1, "Note"=>"y"}
    #   table[2].to_h # => {"Name"=>"baz", "Value"=>2, "Note"=>"z"}
    #   table.by_col!
    #
    # If a single value is given, replaces all fields in the column with that value:
    #   table['Value'] = 'bat'
    #   table['Value'] # => ["bat", "bat", "bat"]
    def []=(index_or_header, value)
      if @mode == :row or  # by index
         (@mode == :col_or_row and index_or_header.is_a? Integer)
        if value.is_a? Array
          @table[index_or_header] = Row.new(headers, value)
        else
          @table[index_or_header] = value
        end
      else                 # set column
        unless index_or_header.is_a? Integer
          index = @headers.index(index_or_header) || @headers.size
          @headers[index] = index_or_header
        end
        if value.is_a? Array  # multiple values
          @table.each_with_index do |row, i|
            if row.header_row?
              row[index_or_header] = index_or_header
            else
              row[index_or_header] = value[i]
            end
          end
        else                  # repeated value
          @table.each do |row|
            if row.header_row?
              row[index_or_header] = index_or_header
            else
              row[index_or_header] = value
            end
          end
        end
      end
    end

    # :call-seq:
    #   table.values_at(*indexes) -> array_of_rows
    #   table.values_at(*headers) -> array_of_columns_data
    #
    # If the access mode is <tt>:row</tt> or <tt>:col_or_row</tt>,
    # and each argument is either an \Integer or a \Range,
    # returns rows.
    # Otherwise, returns columns data.
    #
    # In either case, the returned values are in the order
    # specified by the arguments.  Arguments may be repeated.
    #
    # ---
    #
    # Returns rows as an \Array of \CSV::Row objects.
    #
    # No argument:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.values_at # => []
    #
    # One index:
    #   values = table.values_at(0)
    #   values # => [#<CSV::Row "Name":"foo" "Value":"0">]
    #
    # Two indexes:
    #   values = table.values_at(2, 0)
    #   values # => [#<CSV::Row "Name":"baz" "Value":"2">, #<CSV::Row "Name":"foo" "Value":"0">]
    #
    # One \Range:
    #   values = table.values_at(1..2)
    #   values # => [#<CSV::Row "Name":"bar" "Value":"1">, #<CSV::Row "Name":"baz" "Value":"2">]
    #
    # \Ranges and indexes:
    #   values = table.values_at(0..1, 1..2, 0, 2)
    #   pp values
    # Output:
    #   [#<CSV::Row "Name":"foo" "Value":"0">,
    #    #<CSV::Row "Name":"bar" "Value":"1">,
    #    #<CSV::Row "Name":"bar" "Value":"1">,
    #    #<CSV::Row "Name":"baz" "Value":"2">,
    #    #<CSV::Row "Name":"foo" "Value":"0">,
    #    #<CSV::Row "Name":"baz" "Value":"2">]
    #
    # ---
    #
    # Returns columns data as row Arrays,
    # each consisting of the specified columns data for that row:
    #   values = table.values_at('Name')
    #   values # => [["foo"], ["bar"], ["baz"]]
    #   values = table.values_at('Value', 'Name')
    #   values # => [["0", "foo"], ["1", "bar"], ["2", "baz"]]
    def values_at(*indices_or_headers)
      if @mode == :row or  # by indices
         ( @mode == :col_or_row and indices_or_headers.all? do |index|
                                      index.is_a?(Integer)         or
                                      ( index.is_a?(Range)         and
                                        index.first.is_a?(Integer) and
                                        index.last.is_a?(Integer) )
                                    end )
        @table.values_at(*indices_or_headers)
      else                 # by headers
        @table.map { |row| row.values_at(*indices_or_headers) }
      end
    end

    # :call-seq:
    #   table.pivot(row_columns, column_column, value_column,
    #               columns: nil, column_order: nil, merge: nil)
    #     {|old_value, new_value| ... } -> csv_table
    #
    # Returns a new table in wide format. +row_columns+ identifies the
    # columns retained as row keys, +column_column+ supplies the new column
    # labels, and +value_column+ supplies cell values.
    #
    # Each dimension may be an Integer column index or a header. A row key
    # may consist of several columns; pass an Array for +row_columns+.
    #
    # New columns are ordered by first appearance by default. Pass +columns+
    # (or its alias +column_order+) to specify an explicit order, including
    # columns that do not occur in the source table.
    #
    # Raises ArgumentError if the same row and column coordinate has more
    # than one value and no merge block or +merge+ callable is given. The
    # block or callable receives the old and new values and returns the
    # merged value.
    def pivot(row_columns, column_column, value_column,
              columns: nil, column_order: nil, merge: nil, &merge_block)
      if !column_order.nil? && !columns.nil?
        raise ArgumentError, "cannot pass both columns and column_order"
      end
      columns ||= column_order
      if merge && merge_block
        raise ArgumentError, "cannot pass both merge and a block"
      end
      unless merge.nil? || merge.respond_to?(:call)
        raise TypeError, "merge must respond to #call"
      end

      row_specs = Array(row_columns)
      explicit_columns = pivot_column_order(columns)
      column_labels = []
      grouped_values = {}
      row_order = []
      merge ||= merge_block

      each_pivot_record(row_specs, column_column, value_column) do
        |row_key, column_label, value|
        column_index = if explicit_columns
                         explicit_columns.index(column_label)
                       else
                         column_labels.index(column_label) || column_labels.size
                       end
        next if column_index.nil?

        unless grouped_values.key?(row_key)
          grouped_values[row_key] = {}
          row_order << row_key
        end

        if column_index >= column_labels.size
          column_labels.concat(Array.new(column_index + 1 - column_labels.size))
        end
        column_labels[column_index] = column_label

        if grouped_values[row_key].key?(column_index)
          unless merge
            raise ArgumentError,
                    "conflicting values found for pivot coordinate " \
                    "#{row_key.inspect}, #{column_label.inspect}"
          end
          value = merge.call(grouped_values[row_key][column_index], value)
        end
        grouped_values[row_key][column_index] = value
      end

      columns = explicit_columns || column_labels
      headers = pivot_headers(row_specs, columns)
      rows = row_order.map do |row_key|
        pairs = row_specs.each_with_index.map do |spec, index|
          [pivot_header(spec), row_key[index]]
        end
        columns.each_with_index do |column_label, column_index|
          value = grouped_values[row_key][column_index]
          if value.nil? && !grouped_values[row_key].key?(column_index)
            pairs << [MISSING_HEADER, nil]
          else
            pairs << [column_label, value]
          end
        end
        PivotRow.new(headers, pairs)
      end

      self.class.new(rows, headers: headers)
    end

    # :call-seq:
    #   table.unpivot(row_columns, value_columns = nil,
    #                 column_name: "column", value_name: "value") -> csv_table
    #   table.unpivot(row_columns, value_columns: nil,
    #                 column_name: "column", value_name: "value") -> csv_table
    #
    # Returns a new table in long format. +row_columns+ identifies the
    # columns retained as row keys. +value_columns+ identifies the columns to
    # unpivot; if omitted, all non-row columns are used.
    #
    # Both arguments accept headers or Integer indexes; multiple columns may
    # be passed as Arrays. The unpivoted column label and value are placed in
    # columns named by +column_name+ and +value_name+.
    #
    # A present +nil+ value is emitted, while a coordinate absent from a
    # sparse row is omitted.
    def unpivot(row_columns, *positional_value_columns,
                value_columns: nil,
                column_name: :pivot_default_column_name,
                value_name: :pivot_default_value_name)
      unless positional_value_columns.empty? ||
             positional_value_columns.size == 1
        raise ArgumentError,
              "wrong number of arguments " \
              "(given #{1 + positional_value_columns.size}, expected 1..2)"
      end
      unless positional_value_columns.empty? || value_columns.nil?
        raise ArgumentError, "cannot pass both positional and keyword value columns"
      end

      value_columns = positional_value_columns.first unless positional_value_columns.empty?
      column_name = "column" if column_name == :pivot_default_column_name
      value_name = "value" if value_name == :pivot_default_value_name

      row_specs = Array(row_columns)
      value_specs = value_columns.nil? ? nil : Array(value_columns)
      headers = [
        *pivot_headers(row_specs),
        column_name,
        value_name,
      ]
      rows = []

      @table.each do |row|
        next if row.header_row?

        row_pairs = row_specs.map do |spec|
          pair_for(row, spec)
        end
        next if row_pairs.any? { |pair| pair.nil? }

        value_pairs = if value_specs
                        value_specs.map do |spec|
                          pair = pair_for(row, spec)
                          next if pair.nil?
                          next if pair.first.equal?(MISSING_HEADER)

                          pair
                        end.compact
                      else
                        selected_indices = row_specs.map do |spec|
                          pair_index(row, spec)
                        end.compact
                        row.send(:row).each.with_index.reject do |pair, index|
                          selected_indices.include?(index) ||
                            pair.first.equal?(MISSING_HEADER)
                        end.map(&:first)
                      end

        value_pairs.each do |column_label, value|
          rows << Row.new(headers,
                          row_pairs.map(&:last) + [column_label, value])
        end
      end

      self.class.new(rows, headers: headers)
    end

    # :call-seq:
    #   table << row_or_array -> self
    #
    # If +row_or_array+ is a \CSV::Row object,
    # it is appended to the table:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table << CSV::Row.new(table.headers, ['bat', 3])
    #   table[3] # => #<CSV::Row "Name":"bat" "Value":3>
    #
    # If +row_or_array+ is an \Array, it is used to create a new
    # \CSV::Row object which is then appended to the table:
    #   table << ['bam', 4]
    #   table[4] # => #<CSV::Row "Name":"bam" "Value":4>
    def <<(row_or_array)
      if row_or_array.is_a? Array  # append Array
        @table << Row.new(headers, row_or_array)
      else                         # append Row
        @table << row_or_array
      end

      self # for chaining
    end

    #
    # :call-seq:
    #   table.push(*rows_or_arrays) -> self
    #
    # A shortcut for appending multiple rows. Equivalent to:
    #   rows.each {|row| self << row }
    #
    # Each argument may be either a \CSV::Row object or an \Array:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   rows = [
    #     CSV::Row.new(table.headers, ['bat', 3]),
    #     ['bam', 4]
    #   ]
    #   table.push(*rows)
    #   table[3..4] # => [#<CSV::Row "Name":"bat" "Value":3>, #<CSV::Row "Name":"bam" "Value":4>]
    def push(*rows)
      rows.each { |row| self << row }

      self # for chaining
    end

    # :call-seq:
    #   table.delete(*indexes) -> deleted_values
    #   table.delete(*headers) -> deleted_values
    #
    # If the access mode is <tt>:row</tt> or <tt>:col_or_row</tt>,
    # and each argument is either an \Integer or a \Range,
    # returns deleted rows.
    # Otherwise, returns deleted columns data.
    #
    # In either case, the returned values are in the order
    # specified by the arguments.  Arguments may be repeated.
    #
    # ---
    #
    # Returns rows as an \Array of \CSV::Row objects.
    #
    # One index:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   deleted_values = table.delete(0)
    #   deleted_values # => [#<CSV::Row "Name":"foo" "Value":"0">]
    #
    # Two indexes:
    #   table = CSV.parse(source, headers: true)
    #   deleted_values = table.delete(2, 0)
    #   deleted_values # => [#<CSV::Row "Name":"baz" "Value":"2">, #<CSV::Row "Name":"foo" "Value":"0">]
    #
    # ---
    #
    # Returns columns data as column Arrays.
    #
    # One header:
    #   table = CSV.parse(source, headers: true)
    #   deleted_values = table.delete('Name')
    #   deleted_values # => ["foo", "bar", "baz"]
    #
    # Two headers:
    #   table = CSV.parse(source, headers: true)
    #   deleted_values = table.delete('Value', 'Name')
    #   deleted_values # => [["0", "1", "2"], ["foo", "bar", "baz"]]
    def delete(*indexes_or_headers)
      if indexes_or_headers.empty?
        raise ArgumentError, "wrong number of arguments (given 0, expected 1+)"
      end
      deleted_values = indexes_or_headers.map do |index_or_header|
        if @mode == :row or  # by index
            (@mode == :col_or_row and index_or_header.is_a? Integer)
          @table.delete_at(index_or_header)
        else                 # by header
          if index_or_header.is_a? Integer
            @headers.delete_at(index_or_header)
          else
            @headers.delete(index_or_header)
          end
          @table.map { |row| row.delete(index_or_header).last }
        end
      end
      if indexes_or_headers.size == 1
        deleted_values[0]
      else
        deleted_values
      end
    end

    # :call-seq:
    #   table.delete_if {|row_or_column| ... } -> self
    #
    # Removes rows or columns for which the block returns a truthy value;
    # returns +self+.
    #
    # Removes rows when the access mode is <tt>:row</tt> or <tt>:col_or_row</tt>;
    # calls the block with each \CSV::Row object:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.by_row! # => #<CSV::Table mode:row row_count:4>
    #   table.size # => 3
    #   table.delete_if {|row| row['Name'].start_with?('b') }
    #   table.size # => 1
    #
    # Removes columns when the access mode is <tt>:col</tt>;
    # calls the block with each column as a 2-element array
    # containing the header and an \Array of column fields:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.by_col! # => #<CSV::Table mode:col row_count:4>
    #   table.headers.size # => 2
    #   table.delete_if {|column_data| column_data[1].include?('2') }
    #   table.headers.size # => 1
    #
    # Returns a new \Enumerator if no block is given:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.delete_if # => #<Enumerator: #<CSV::Table mode:col_or_row row_count:4>:delete_if>
    def delete_if(&block)
      return enum_for(__method__) { @mode == :row or @mode == :col_or_row ? size : headers.size } unless block_given?

      if @mode == :row or @mode == :col_or_row  # by index
        @table.delete_if(&block)
      else                                      # by header
        headers.each do |header|
          delete(header) if yield([header, self[header]])
        end
      end

      self # for chaining
    end

    include Enumerable

    # :call-seq:
    #  table.each {|row_or_column| ... ) -> self
    #
    # Calls the block with each row or column; returns +self+.
    #
    # When the access mode is <tt>:row</tt> or <tt>:col_or_row</tt>,
    # calls the block with each \CSV::Row object:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.by_row! # => #<CSV::Table mode:row row_count:4>
    #   table.each {|row| p row }
    # Output:
    #   #<CSV::Row "Name":"foo" "Value":"0">
    #   #<CSV::Row "Name":"bar" "Value":"1">
    #   #<CSV::Row "Name":"baz" "Value":"2">
    #
    # When the access mode is <tt>:col</tt>,
    # calls the block with each column as a 2-element array
    # containing the header and an \Array of column fields:
    #   table.by_col! # => #<CSV::Table mode:col row_count:4>
    #   table.each {|column_data| p column_data }
    # Output:
    #   ["Name", ["foo", "bar", "baz"]]
    #   ["Value", ["0", "1", "2"]]
    #
    # Returns a new \Enumerator if no block is given:
    #   table.each # => #<Enumerator: #<CSV::Table mode:col row_count:4>:each>
    def each(&block)
      return enum_for(__method__) { @mode == :col ? headers.size : size } unless block_given?

      if @mode == :col
        headers.each.with_index do |header, i|
          yield([header, @table.map {|row| row[header, i]}])
        end
      else
        @table.each(&block)
      end

      self # for chaining
    end

    # :call-seq:
    #   table == other_table -> true or false
    #
    # Returns +true+ if all each row of +self+ <tt>==</tt>
    # the corresponding row of +other_table+, otherwise, +false+.
    #
    # The access mode does no affect the result.
    #
    # Equal tables:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   other_table = CSV.parse(source, headers: true)
    #   table == other_table # => true
    #
    # Different row count:
    #   other_table.delete(2)
    #   table == other_table # => false
    #
    # Different last row:
    #   other_table << ['bat', 3]
    #   table == other_table # => false
    def ==(other)
      return @table == other.table if other.is_a? CSV::Table
      @table == other
    end

    # :call-seq:
    #   table.to_a -> array_of_arrays
    #
    # Returns the table as an \Array of \Arrays;
    # the headers are in the first row:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.to_a # => [["Name", "Value"], ["foo", "0"], ["bar", "1"], ["baz", "2"]]
    def to_a
      array = [headers]
      @table.each do |row|
        array.push(row.fields) unless row.header_row?
      end

      array
    end

    # :call-seq:
    #   table.to_csv(**options) -> csv_string
    #
    # Returns the table as \CSV string.
    # See {Options for Generating}[../CSV.html#class-CSV-label-Options+for+Generating].
    #
    # Defaults option +write_headers+ to +true+:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.to_csv # => "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #
    # Omits the headers if option +write_headers+ is given as +false+
    # (see {Option +write_headers+}[../CSV.html#class-CSV-label-Option+write_headers]):
    #   table.to_csv(write_headers: false) # => "foo,0\nbar,1\nbaz,2\n"
    #
    # Limit rows if option +limit+ is given like +2+:
    #   table.to_csv(limit: 2) # => "Name,Value\nfoo,0\nbar,1\n"
    def to_csv(write_headers: true, limit: nil, **options)
      array = write_headers ? [headers.to_csv(**options)] : []
      limit ||= @table.size
      limit = @table.size + 1 + limit if limit < 0
      limit = 0 if limit < 0
      @table.first(limit).each do |row|
        array.push(row.fields.to_csv(**options)) unless row.header_row?
      end

      array.join("")
    end
    alias_method :to_s, :to_csv

    #
    # Extracts the nested value specified by the sequence of +index+ or +header+ objects by calling dig at each step,
    # returning nil if any intermediate step is nil.
    #
    def dig(index_or_header, *index_or_headers)
      value = self[index_or_header]
      if value.nil?
        nil
      elsif index_or_headers.empty?
        value
      else
        unless value.respond_to?(:dig)
          raise TypeError, "#{value.class} does not have \#dig method"
        end
        value.dig(*index_or_headers)
      end
    end

    # :call-seq:
    #   table.inspect => string
    #
    # Returns a <tt>US-ASCII</tt>-encoded \String showing table:
    # - Class: <tt>CSV::Table</tt>.
    # - Access mode: <tt>:row</tt>, <tt>:col</tt>, or <tt>:col_or_row</tt>.
    # - Size:  Row count, including the header row.
    #
    # Example:
    #   source = "Name,Value\nfoo,0\nbar,1\nbaz,2\n"
    #   table = CSV.parse(source, headers: true)
    #   table.inspect # => "#<CSV::Table mode:col_or_row row_count:4>\nName,Value\nfoo,0\nbar,1\nbaz,2\n"
    #
    def inspect
      inspected = +"#<#{self.class} mode:#{@mode} row_count:#{to_a.size}>"
      summary = to_csv(limit: 5)
      inspected << "\n" << summary if summary.encoding.ascii_compatible?
      inspected
    end

    private

    def each_pivot_record(row_specs, column_spec, value_spec)
      @table.each do |row|
        next if row.header_row?

        row_pairs = row_specs.map { |spec| pair_for(row, spec) }
        next if row_pairs.any?(&:nil?)

        column_pair = pair_for(row, column_spec)
        next if column_pair.nil?

        value_pair = pair_for(row, value_spec)
        next if value_pair.nil?

        yield(row_pairs.map(&:last), column_pair.last, value_pair.last)
      end
    end

    def pivot_column_order(column_order)
      return nil if column_order.nil?
      unless column_order.is_a?(Array)
        raise TypeError, "column_order must be an Array"
      end

      column_order.each_with_index do |column, index|
        if column_order[(index + 1)..-1].include?(column)
          raise ArgumentError, "duplicate pivot column: #{column.inspect}"
        end
      end
      column_order.dup
    end

    def pivot_header(spec)
      return spec unless spec.is_a?(Integer)

      headers[spec]
    end

    def pivot_headers(row_specs, columns = nil)
      headers = row_specs.map { |spec| pivot_header(spec) }
      headers.concat(columns) if columns
      headers
    end

    def pair_for(row, spec)
      pairs = row.send(:row)
      if spec.is_a?(Integer)
        index = spec
        index += row.size if index.negative?
        return nil if index.negative?

        pair = pairs[index]
      else
        pair = pairs.find do |header, _value|
          !header.equal?(MISSING_HEADER) && header == spec
        end
      end

      return nil if pair.nil?
      return nil if pair.first.equal?(MISSING_HEADER)

      pair
    end

    def pair_index(row, spec)
      pairs = row.send(:row)
      if spec.is_a?(Integer)
        index = spec
        index += row.size if index.negative?
        return nil if index.negative? || index >= row.size

        found = pairs.each.with_index.find do |(header, _value), pair_index|
          pair_index == index && !header.equal?(MISSING_HEADER)
        end
        found&.last
      else
        found = pairs.each.with_index.find do |(header, _value), _index|
          !header.equal?(MISSING_HEADER) && header == spec
        end
        found&.last
      end
    end
  end
end
