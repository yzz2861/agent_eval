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
    PIVOT_UNDEFINED = Object.new.freeze

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
    #   table.pivot(row_key, column_key, value_key, columns: nil,
    #               merge: nil) {|old_value, new_value| ... } -> csv_table
    #
    # Returns a new table reshaped from long form to wide form.
    #
    # +row_key+ identifies one or more columns whose values identify a row.
    # +column_key+ identifies the column containing the names for new columns.
    # +value_key+ identifies the column containing the values for those columns.
    # Each key may be given as a header or an integer column index, which makes
    # it possible to select columns with duplicate headers.
    #
    #   source = "account,month,value\nCash,Jan,10\nCash,Feb,20\n"
    #   table = CSV.parse(source, headers: true)
    #   table.pivot("account", "month", "value").to_a
    #   # => [["account", "Jan", "Feb"], ["Cash", "10", "20"]]
    #
    # New columns are ordered by first occurrence by default. Pass +columns+
    # to specify the order explicitly and to include columns with no values:
    #   table.pivot("account", "month", "value", columns: ["Feb", "Jan"])
    #
    # An exception is raised when a row-column coordinate has more than one
    # value. Pass +merge+ or a block to combine duplicates:
    #   table.pivot("account", "month", "value") do |old_value, new_value|
    #     old_value + new_value
    #   end
    #
    # A coordinate with an actual +nil+ value is retained. A coordinate with no
    # source record is absent from the returned sparse row, so the two cases
    # remain distinguishable through CSV::Row#header? while table output remains
    # aligned with the full headers.
    def pivot(row_key, column_key, value_key,
              columns: PIVOT_UNDEFINED, column_order: PIVOT_UNDEFINED,
              merge: PIVOT_UNDEFINED, &merge_block)
      columns = PIVOT_UNDEFINED if columns.nil?
      column_order = PIVOT_UNDEFINED if column_order.nil?
      merge = PIVOT_UNDEFINED if merge.nil?
      row_indices = resolve_pivot_selectors(row_key)
      column_index = resolve_single_pivot_selector(column_key, "column_key")
      value_index = resolve_single_pivot_selector(value_key, "value_key")

      merge_callable = pivot_merge_callable(merge, merge_block)
      selected_indices = row_indices + [column_index, value_index]
      unless selected_indices.uniq.size == selected_indices.size
        raise ArgumentError, "row_key, column_key, and value_key must not select the same column"
      end

      explicit_columns = !column_order.equal?(PIVOT_UNDEFINED) ||
                         !columns.equal?(PIVOT_UNDEFINED)
      explicit_labels = if !column_order.equal?(PIVOT_UNDEFINED)
                           pivot_array(column_order)
                         elsif !columns.equal?(PIVOT_UNDEFINED)
                           pivot_array(columns)
                         else
                           nil
                         end
      if explicit_labels && explicit_labels.uniq.size != explicit_labels.size
        raise ArgumentError, "columns must not contain duplicates"
      end

      row_headers = row_indices.map { |index| pivot_header_copy(headers[index]) }

      labels = []
      output_labels = []
      label_set = {}
      label_positions = Hash.new { |positions, label| positions[label] = [] }
      if explicit_labels
        pivot_array(explicit_labels).each do |label|
          label_set[label] = true
          labels << label
          label_positions[label] << labels.size - 1
          output_labels << pivot_header_copy(label)
        end
      end

      ordered_row_keys = []
      known_row_keys = {}
      values_by_row = Hash.new { |values, key| values[key] = {} }
      label_occurrences = Hash.new { |occurrences, key| occurrences[key] = Hash.new(0) }

      @table.each do |row|
        next if row.header_row?
        next unless pivot_field_present?(row, column_index)
        next unless pivot_field_present?(row, value_index)
        next unless row_indices.all? { |index| pivot_field_present?(row, index) }

        row_values = row_indices.map { |index| row[index] }
        label = row[column_index]

        if explicit_columns
          unless label_set.key?(label)
            raise ArgumentError, "unexpected pivot column: #{label.inspect}"
          end
        elsif !label_set.key?(label)
          label_set[label] = true
          labels << label
          label_positions[label] << labels.size - 1
          output_labels << pivot_header_copy(label)
        end

        unless known_row_keys.key?(row_values)
          known_row_keys[row_values] = true
          ordered_row_keys << row_values
        end

        cells = values_by_row[row_values]
        label_occurrence = label_occurrences[row_values][label]
        label_position = label_positions[label][label_occurrence] ||
                         label_positions[label].last
        label_index = row_headers.size + label_position
        value = row[value_index]
        if cells.key?(label_index)
          if merge_callable
            value = merge_callable.call(cells[label_index], value)
          else
            raise ArgumentError, "multiple values for pivot coordinate #{row_values.inspect}, #{label.inspect}"
          end
        end
        cells[label_index] = value
        label_occurrences[row_values][label] += 1
      end

      pivot_headers = row_headers + output_labels
      rows = ordered_row_keys.map do |row_values|
        values_by_index = {}
        row_indices.each_with_index do |_, index|
          values_by_index[index] = row_values[index]
        end
        cells = values_by_row[row_values]
        cells.each { |index, value| values_by_index[index] = value }
        PivotRow.new(pivot_headers, values_by_index)
      end

      self.class.new(rows, headers: pivot_headers)
    end

    # :call-seq:
    #   table.unpivot(row_key, value_columns = nil, column_key: "column", value_key: "value") -> csv_table
    #
    # Returns a new table reshaped from wide form to long form.
    #
    # +row_key+ identifies one or more columns retained on each returned row.
    # +value_columns+ identifies the columns to unpivot; headers or integer
    # column indexes may be used. When omitted, all columns not selected by
    # +row_key+ are unpivoted.
    #
    #   source = "account,Jan,Feb\nCash,10,20\n"
    #   table = CSV.parse(source, headers: true)
    #   table.unpivot("account", ["Jan", "Feb"],
    #                column_key: "month", value_key: "value").to_a
    #   # => [["account", "month", "value"],
    #   #     ["Cash", "Jan", "10"],
    #   #     ["Cash", "Feb", "20"]]
    #
    # Actual +nil+ values produce rows. Coordinates absent from a sparse pivot
    # table do not.
    def unpivot(row_key, value_columns = PIVOT_UNDEFINED,
                column_name = PIVOT_UNDEFINED, value_name = PIVOT_UNDEFINED,
                column_key: PIVOT_UNDEFINED, value_key: PIVOT_UNDEFINED)
      value_columns = PIVOT_UNDEFINED if value_columns.nil?
      row_indices = resolve_pivot_selectors(row_key)
      value_indices = if value_columns.equal?(PIVOT_UNDEFINED)
                        headers.each_index.reject { |index| row_indices.include?(index) }
                      else
                        resolve_pivot_selectors(value_columns)
                      end

      all_indices = row_indices + value_indices
      unless all_indices.uniq.size == all_indices.size
        raise ArgumentError, "row_key and value_columns must not select the same column"
      end

      column_label = if column_key.equal?(PIVOT_UNDEFINED)
                       column_name.equal?(PIVOT_UNDEFINED) ? "column" : column_name
                     else
                       column_key
                     end
      value_label = if value_key.equal?(PIVOT_UNDEFINED)
                      value_name.equal?(PIVOT_UNDEFINED) ? "value" : value_name
                    else
                      value_key
                    end

      row_headers = row_indices.map { |index| pivot_header_copy(headers[index]) }
      value_headers = value_indices.map { |index| pivot_header_copy(headers[index]) }
      long_headers = row_headers + [pivot_header_copy(column_label),
                                    pivot_header_copy(value_label)]

      rows = []
      @table.each do |row|
        next if row.header_row?
        next unless row_indices.all? { |index| pivot_field_present?(row, index) }

        row_values = row_indices.map { |index| row[index] }
        value_indices.each_with_index do |index, value_header_index|
          next unless pivot_field_present?(row, index)
          rows << Row.new(long_headers,
                         row_values + [value_headers[value_header_index], row[index]])
        end
      end

      self.class.new(rows, headers: long_headers)
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

    def pivot_array(value)
      value.is_a?(Array) ? value : [value]
    end

    def pivot_header_copy(header)
      header.is_a?(String) ? header.dup : header
    end

    def resolve_pivot_selectors(selectors)
      pivot_array(selectors).map do |selector|
        if selector.is_a?(Range)
          raise ArgumentError, "column ranges are not supported"
        end
        resolve_single_pivot_selector(selector, "column")
      end.tap do |indices|
        if indices.uniq.size != indices.size
          raise ArgumentError, "column selectors must not contain duplicates"
        end
      end
    end

    def resolve_single_pivot_selector(selector, argument_name)
      if selector.is_a?(Array) || selector.is_a?(Range)
        raise ArgumentError, "#{argument_name} must select one column"
      end

      index = if selector.is_a?(Integer)
                selector
              else
                headers.index(selector)
              end
      index += headers.size if index.is_a?(Integer) && index < 0
      unless index.is_a?(Integer) && index >= 0 && index < headers.size
        raise IndexError, "column not found: #{selector.inspect}"
      end
      index
    end

    def pivot_merge_callable(merge, merge_block)
      if !merge.equal?(PIVOT_UNDEFINED) && merge_block
        raise ArgumentError, "provide either merge or a block, not both"
      end

      callable = merge_block || (merge.equal?(PIVOT_UNDEFINED) ? nil : merge)
      if callable && !callable.respond_to?(:call)
        raise TypeError, "merge must respond to #call"
      end
      callable
    end

    def pivot_field_present?(row, index)
      if row.is_a?(PivotRow)
        row.pivot_field_present?(index)
      else
        row.headers.size > index
      end
    end

    # A row aligned with the table's full headers while storing only
    # coordinates that actually have a source value.
    class PivotRow < Row
      def initialize(full_headers, values_by_index)
        @present_indices = values_by_index.keys.select do |index|
          index >= 0 && index < full_headers.size
        end
        super([], [])
        @row.replace(full_headers.each_index.map do |index|
          [full_headers[index], values_by_index.fetch(index, nil)]
        end)
        full_headers.each { |header| header.freeze if header.is_a?(String) }
        @full_headers = full_headers
        @present_indices = @present_indices.sort
      end

      def initialize_copy(other)
        super
        @full_headers = @full_headers.dup
        @present_indices = @present_indices.dup
      end

      def headers
        @full_headers.dup
      end

      def field(header_or_index, minimum_index = 0)
        case header_or_index
        when Integer
          index = header_or_index
          index += @full_headers.size if index < 0
          return nil unless index >= 0 && index < @full_headers.size
          @row[index].last
        when Range
          start_index = range_index(header_or_index.begin)
          end_index = range_index(header_or_index.end)
          range = Range.new(start_index, end_index, header_or_index.exclude_end?)
          @row[range].map(&:last)
        else
          minimum_index = minimum_index.is_a?(Integer) ? minimum_index : 0
          @row.each_with_index do |(candidate_header, value), index|
            return value if index >= minimum_index && candidate_header == header_or_index
          end
          nil
        end
      end

      def fields(*specifiers)
        return @row.map(&:last) if specifiers.empty?

        if specifiers.all? { |specifier| specifier.is_a?(Integer) || specifier.is_a?(Range) }
          specifiers.flat_map do |specifier|
            specifier.is_a?(Range) ? field(specifier) : [field(specifier)]
          end
        else
          super
        end
      end

      def has_key?(header, minimum_index = 0)
        if header.is_a?(Integer)
          pivot_field_present?(header)
        else
          minimum_index = 0 unless minimum_index.is_a?(Integer)
          @present_indices.any? do |index|
            index >= minimum_index && @row[index].first == header
          end
        end
      end
      alias_method :include?, :has_key?
      alias_method :key?, :has_key?
      alias_method :member?, :has_key?
      alias_method :header?, :has_key?

      def each(&block)
        return enum_for(__method__) { size } unless block_given?

        @present_indices.each do |index|
          yield(@row[index])
        end

        self
      end
      alias_method :each_pair, :each

      def to_h
        hash = {}
        if block_given?
          each do |header, value|
            key, converted_value = yield(header, value)
            hash[key] = converted_value unless hash.key?(key)
          end
        else
          each do |header, value|
            hash[header] = value unless hash.key?(header)
          end
        end
        hash
      end
      alias_method :to_hash, :to_h

      def ==(other)
        return to_a == other.each.to_a if other.is_a?(Row)
        super
      end

      def to_a
        @present_indices.map { |index| @row[index].dup }
      end
      alias_method :to_ary, :to_a

      def pivot_field_present?(index)
        index += @full_headers.size if index < 0
        @present_indices.include?(index)
      end

      private

      def range_index(index_or_header)
        if index_or_header.is_a?(Integer)
          index_or_header
        else
          @full_headers.index(index_or_header)
        end
      end
    end
  end
end
