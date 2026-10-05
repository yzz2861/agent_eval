# frozen_string_literal: true
# = PStore -- Transactional File Storage for Ruby Objects
#
# pstore.rb -
#   originally by matz
#   documentation by Kev Jackson and James Edward Gray II
#   improved by Hongli Lai
#
# See PStore for documentation.

require "digest"
require "json"

# \PStore implements a file based persistence mechanism based on a Hash.
# User code can store hierarchies of Ruby objects (values)
# into the data store by name (keys).
# An object hierarchy may be just a single object.
# User code may later read values back from the data store
# or even update data, as needed.
#
# The transactional behavior ensures that any changes succeed or fail together.
# This can be used to ensure that the data store is not left in a transitory state,
# where some values were updated but others were not.
#
# Behind the scenes, Ruby objects are stored to the data store file with Marshal.
# That carries the usual limitations. Proc objects cannot be marshalled,
# for example.
#
# There are three important concepts here (details at the links):
#
# - {Store}[rdoc-ref:PStore@The+Store]: a store is an instance of \PStore.
# - {Entries}[rdoc-ref:PStore@Entries]: the store is hash-like;
#   each entry is the key for a stored object.
# - {Transactions}[rdoc-ref:PStore@Transactions]: each transaction is a collection
#   of prospective changes to the store;
#   a transaction is defined in the block given with a call
#   to PStore#transaction.
#
# == About the Examples
#
# Examples on this page need a store that has known properties.
# They can get a new (and populated) store by calling thus:
#
#   example_store do |store|
#     # Example code using store goes here.
#   end
#
# All we really need to know about +example_store+
# is that it yields a fresh store with a known population of entries;
# its implementation:
#
#   require 'pstore'
#   require 'tempfile'
#   # Yield a pristine store for use in examples.
#   def example_store
#     # Create the store in a temporary file.
#     Tempfile.create do |file|
#       store = PStore.new(file)
#       # Populate the store.
#       store.transaction do
#         store[:foo] = 0
#         store[:bar] = 1
#         store[:baz] = 2
#       end
#       yield store
#     end
#   end
#
# == The Store
#
# The contents of the store are maintained in a file whose path is specified
# when the store is created (see PStore.new).
# The objects are stored and retrieved using
# module Marshal, which means that certain objects cannot be added to the store;
# see {Marshal::dump}[https://docs.ruby-lang.org/en/master/Marshal.html#method-c-dump].
#
# == Entries
#
# A store may have any number of entries.
# Each entry has a key and a value, just as in a hash:
#
# - Key: as in a hash, the key can be (almost) any object;
#   see {Hash Keys}[https://docs.ruby-lang.org/en/master/Hash.html#class-Hash-label-Hash+Keys].
#   You may find it convenient to keep it simple by using only
#   symbols or strings as keys.
# - Value: the value may be any object that can be marshalled by \Marshal
#   (see {Marshal::dump}[https://docs.ruby-lang.org/en/master/Marshal.html#method-c-dump])
#   and in fact may be a collection
#   (e.g., an array, a hash, a set, a range, etc).
#   That collection may in turn contain nested objects,
#   including collections, to any depth;
#   those objects must also be \Marshal-able.
#   See {Hierarchical Values}[rdoc-ref:PStore@Hierarchical+Values].
#
# == Transactions
#
# === The Transaction Block
#
# The block given with a call to method #transaction#
# contains a _transaction_,
# which consists of calls to \PStore methods that
# read from or write to the store
# (that is, all \PStore methods except #transaction itself,
# #path, and Pstore.new):
#
#   example_store do |store|
#     store.transaction do
#       store.keys # => [:foo, :bar, :baz]
#       store[:bat] = 3
#       store.keys # => [:foo, :bar, :baz, :bat]
#     end
#   end
#
# Execution of the transaction is deferred until the block exits,
# and is executed _atomically_ (all-or-nothing):
# either all transaction calls are executed, or none are.
# This maintains the integrity of the store.
#
# Other code in the block (including even calls to #path and PStore.new)
# is executed immediately, not deferred.
#
# The transaction block:
#
# - May not contain a nested call to #transaction.
# - Is the only context where methods that read from or write to
#   the store are allowed.
#
# As seen above, changes in a transaction are made automatically
# when the block exits.
# The block may be exited early by calling method #commit or #abort.
#
# - Method #commit triggers the update to the store and exits the block:
#
#     example_store do |store|
#       store.transaction do
#         store.keys # => [:foo, :bar, :baz]
#         store[:bat] = 3
#         store.commit
#         fail 'Cannot get here'
#       end
#       store.transaction do
#         # Update was completed.
#         store.keys # => [:foo, :bar, :baz, :bat]
#       end
#     end
#
# - Method #abort discards the update to the store and exits the block:
#
#     example_store do |store|
#       store.transaction do
#         store.keys # => [:foo, :bar, :baz]
#         store[:bat] = 3
#         store.abort
#         fail 'Cannot get here'
#       end
#       store.transaction do
#         # Update was not completed.
#         store.keys # => [:foo, :bar, :baz]
#       end
#     end
#
# === Read-Only Transactions
#
# By default, a transaction allows both reading from and writing to
# the store:
#
#   store.transaction do
#     # Read-write transaction.
#     # Any code except a call to #transaction is allowed here.
#   end
#
# If argument +read_only+ is passed as +true+,
# only reading is allowed:
#
#   store.transaction(true) do
#     # Read-only transaction:
#     # Calls to #transaction, #[]=, and #delete are not allowed here.
#   end
#
# == Hierarchical Values
#
# The value for an entry may be a simple object (as seen above).
# It may also be a hierarchy of objects nested to any depth:
#
#   deep_store = PStore.new('deep.store')
#   deep_store.transaction do
#     array_of_hashes = [{}, {}, {}]
#     deep_store[:array_of_hashes] = array_of_hashes
#     deep_store[:array_of_hashes] # => [{}, {}, {}]
#     hash_of_arrays = {foo: [], bar: [], baz: []}
#     deep_store[:hash_of_arrays] = hash_of_arrays
#     deep_store[:hash_of_arrays]  # => {:foo=>[], :bar=>[], :baz=>[]}
#     deep_store[:hash_of_arrays][:foo].push(:bat)
#     deep_store[:hash_of_arrays]  # => {:foo=>[:bat], :bar=>[], :baz=>[]}
#   end
#
# And recall that you can use
# {dig methods}[https://docs.ruby-lang.org/en/master/dig_methods_rdoc.html]
# in a returned hierarchy of objects.
#
# == Working with the Store
#
# === Creating a Store
#
# Use method PStore.new to create a store.
# The new store creates or opens its containing file:
#
#   store = PStore.new('t.store')
#
# === Modifying the Store
#
# Use method #[]= to update or create an entry:
#
#   example_store do |store|
#     store.transaction do
#       store[:foo] = 1 # Update.
#       store[:bam] = 1 # Create.
#     end
#   end
#
# Use method #delete to remove an entry:
#
#   example_store do |store|
#     store.transaction do
#       store.delete(:foo)
#       store[:foo] # => nil
#     end
#   end
#
# === Retrieving Values
#
# Use method #fetch (allows default) or #[] (defaults to +nil+)
# to retrieve an entry:
#
#   example_store do |store|
#     store.transaction do
#       store[:foo]             # => 0
#       store[:nope]            # => nil
#       store.fetch(:baz)       # => 2
#       store.fetch(:nope, nil) # => nil
#       store.fetch(:nope)      # Raises exception.
#     end
#   end
#
# === Querying the Store
#
# Use method #key? to determine whether a given key exists:
#
#   example_store do |store|
#     store.transaction do
#       store.key?(:foo) # => true
#     end
#   end
#
# Use method #keys to retrieve keys:
#
#   example_store do |store|
#     store.transaction do
#       store.keys # => [:foo, :bar, :baz]
#     end
#   end
#
# Use method #path to retrieve the path to the store's underlying file;
# this method may be called from outside a transaction block:
#
#   store = PStore.new('t.store')
#   store.path # => "t.store"
#
# == Transaction Safety
#
# For transaction safety, see:
#
# - Optional argument +thread_safe+ at method PStore.new.
# - Attribute #ultra_safe.
#
# Needless to say, if you're storing valuable data with \PStore, then you should
# backup the \PStore file from time to time.
#
# == An Example Store
#
#  require "pstore"
#
#  # A mock wiki object.
#  class WikiPage
#
#    attr_reader :page_name
#
#    def initialize(page_name, author, contents)
#      @page_name = page_name
#      @revisions = Array.new
#      add_revision(author, contents)
#    end
#
#    def add_revision(author, contents)
#      @revisions << {created: Time.now,
#                     author: author,
#                     contents: contents}
#    end
#
#    def wiki_page_references
#      [@page_name] + @revisions.last[:contents].scan(/\b(?:[A-Z]+[a-z]+){2,}/)
#    end
#
#  end
#
#  # Create a new wiki page.
#  home_page = WikiPage.new("HomePage", "James Edward Gray II",
#                           "A page about the JoysOfDocumentation..." )
#
#  wiki = PStore.new("wiki_pages.pstore")
#  # Update page data and the index together, or not at all.
#  wiki.transaction do
#    # Store page.
#    wiki[home_page.page_name] = home_page
#    # Create page index.
#    wiki[:wiki_index] ||= Array.new
#    # Update wiki index.
#    wiki[:wiki_index].push(*home_page.wiki_page_references)
#  end
#
#  # Read wiki data, setting argument read_only to true.
#  wiki.transaction(true) do
#    wiki.keys.each do |key|
#      puts key
#      puts wiki[key]
#    end
#  end
#
class PStore
  # :stopdoc:
  VERSION = "0.2.1"

  RDWR_ACCESS = {mode: IO::RDWR | IO::CREAT | IO::BINARY, encoding: Encoding::ASCII_8BIT}.freeze
  RD_ACCESS = {mode: IO::RDONLY | IO::BINARY, encoding: Encoding::ASCII_8BIT}.freeze
  WR_ACCESS = {mode: IO::WRONLY | IO::CREAT | IO::TRUNC | IO::BINARY, encoding: Encoding::ASCII_8BIT}.freeze
  private_constant :RDWR_ACCESS, :RD_ACCESS, :WR_ACCESS
  # :startdoc:

  # The error type thrown by all PStore methods.
  class Error < StandardError
  end

  # Supported on-disk formats for PStore.new (keyword argument +format+):
  #
  # - FORMAT_MARSHAL (the default): the historical Marshal-based format.
  # - FORMAT_JSON: a versioned, type-tagged JSON format that is
  #   human-inspectable and never instantiates arbitrary Ruby classes
  #   when loading.  See JSONCodec for the supported value types.
  FORMAT_MARSHAL = :marshal
  FORMAT_JSON = :json
  FORMATS = [FORMAT_MARSHAL, FORMAT_JSON].freeze
  private_constant :FORMATS

  # :stopdoc:
  #
  # Encoder/decoder for the type-tagged JSON format (FORMAT_JSON).
  #
  # The file contains a single JSON document:
  #
  #   {"format":"pstore-json","version":1,"data":<encoded table>}
  #
  # Values are encoded as follows:
  #
  # - String, Integer, finite Float, +true+, +false+ and +nil+
  #   map to their native JSON counterparts.
  # - Symbol maps to a tagged object: <tt>{"$sym":"name"}</tt>.
  # - Array maps to a JSON array of encoded elements.
  # - Hash maps to a tagged object holding an array of encoded
  #   key/value pairs, so that string keys and symbol keys
  #   (and any other supported key type) stay distinct:
  #   <tt>{"$hash":[[key1, value1], [key2, value2]]}</tt>.
  #
  # Any other object is rejected, cyclic structures are rejected,
  # and decoding enforces limits on nesting depth and total node count.
  module JSONCodec
    FORMAT_NAME = "pstore-json"
    FORMAT_VERSION = 1
    MAGIC = %({"format":"#{FORMAT_NAME}").freeze
    MARSHAL_MAGIC = "\x04\x08".b.freeze
    SYMBOL_TAG = "$sym"
    HASH_TAG = "$hash"

    # Default upper bound on container nesting when encoding or decoding.
    DEFAULT_MAX_DEPTH = 100
    # Default upper bound on the total number of values when encoding or decoding.
    DEFAULT_MAX_NODES = 1_000_000

    module_function

    # Whether +data+ looks like a file written in the JSON format.
    def json_data?(data)
      data.start_with?(MAGIC)
    end

    # Whether +data+ looks like a Marshal-format PStore file.
    def marshal_data?(data)
      data.start_with?(MARSHAL_MAGIC)
    end

    # Encodes +table+ (a Hash) into the versioned JSON document.
    # The whole structure is validated before anything is returned:
    # unsupported objects, non-finite floats, cyclic structures and
    # structures exceeding +max_depth+ or +max_nodes+ raise PStore::Error.
    def dump(table, max_depth: DEFAULT_MAX_DEPTH, max_nodes: DEFAULT_MAX_NODES)
      state = {nodes: 0, seen: {}.compare_by_identity}
      data = encode_value(table, 0, max_depth, max_nodes, state)
      envelope = {"format" => FORMAT_NAME, "version" => FORMAT_VERSION, "data" => data}
      JSON.generate(envelope)
    rescue JSON::GeneratorError => error
      raise PStore::Error, "cannot encode data in JSON format: #{error.message}"
    end

    # Decodes a JSON document previously written by JSONCodec.dump.
    # Raises PStore::Error if the document is not in the expected format
    # or version, or exceeds +max_depth+ or +max_nodes+.
    # Raises EOFError for empty input (mirroring Marshal.load).
    def load(content, max_depth: DEFAULT_MAX_DEPTH, max_nodes: DEFAULT_MAX_NODES)
      content = content.read unless content.is_a?(String)
      raise EOFError, "empty PStore JSON data" if content.empty?
      content = content.dup.force_encoding(Encoding::UTF_8)
      unless content.valid_encoding?
        raise PStore::Error, "PStore JSON data is not valid UTF-8"
      end
      envelope =
        begin
          # Tagged hashes add JSON nesting levels beyond the logical
          # depth, so allow some slack over the logical limit.
          JSON.parse(content, max_nesting: max_depth * 4 + 16)
        rescue JSON::ParserError => error
          raise PStore::Error, "PStore file is not valid JSON: #{error.message}"
        end
      unless envelope.is_a?(Hash) && envelope["format"] == FORMAT_NAME
        raise PStore::Error, "PStore file is not in #{FORMAT_NAME} format"
      end
      version = envelope["version"]
      unless version == FORMAT_VERSION
        raise PStore::Error, "unsupported PStore JSON format version: #{version.inspect}"
      end
      state = {nodes: 0}
      decode_value(envelope["data"], 0, max_depth, max_nodes, state)
    end

    def encode_value(value, depth, max_depth, max_nodes, state)
      state[:nodes] += 1
      if state[:nodes] > max_nodes
        raise PStore::Error, "data exceeds the maximum of #{max_nodes} nodes"
      end
      case value
      when String, Integer, true, false, nil
        value
      when Float
        unless value.finite?
          raise PStore::Error, "cannot store non-finite Float: #{value}"
        end
        value
      when Symbol
        {SYMBOL_TAG => value.to_s}
      when Array
        enter_container(value, depth, max_depth, state)
        begin
          value.map {|element| encode_value(element, depth + 1, max_depth, max_nodes, state) }
        ensure
          state[:seen].delete(value)
        end
      when Hash
        enter_container(value, depth, max_depth, state)
        begin
          pairs = value.map do |key, element|
            [encode_value(key, depth + 1, max_depth, max_nodes, state),
             encode_value(element, depth + 1, max_depth, max_nodes, state)]
          end
          {HASH_TAG => pairs}
        ensure
          state[:seen].delete(value)
        end
      else
        raise PStore::Error, "unsupported object type for JSON format: #{value.class}"
      end
    end
    private_class_method :encode_value

    def enter_container(value, depth, max_depth, state)
      if depth >= max_depth
        raise PStore::Error, "data exceeds the maximum nesting depth of #{max_depth}"
      end
      if state[:seen].key?(value)
        raise PStore::Error, "cannot store cyclic data structure"
      end
      state[:seen][value] = true
    end
    private_class_method :enter_container

    def decode_value(node, depth, max_depth, max_nodes, state)
      state[:nodes] += 1
      if state[:nodes] > max_nodes
        raise PStore::Error, "data exceeds the maximum of #{max_nodes} nodes"
      end
      case node
      when String, Integer, true, false, nil
        node
      when Float
        unless node.finite?
          raise PStore::Error, "non-finite Float in PStore JSON data"
        end
        node
      when Array
        check_depth(depth, max_depth)
        node.map {|element| decode_value(element, depth + 1, max_depth, max_nodes, state) }
      when Hash
        check_depth(depth, max_depth)
        if node.size == 1 && node.key?(SYMBOL_TAG)
          name = node[SYMBOL_TAG]
          unless name.is_a?(String)
            raise PStore::Error, "invalid Symbol encoding in PStore JSON data"
          end
          name.to_sym
        elsif node.size == 1 && node.key?(HASH_TAG)
          pairs = node[HASH_TAG]
          unless pairs.is_a?(Array)
            raise PStore::Error, "invalid Hash encoding in PStore JSON data"
          end
          result = {}
          pairs.each do |pair|
            unless pair.is_a?(Array) && pair.size == 2
              raise PStore::Error, "invalid Hash encoding in PStore JSON data"
            end
            key = decode_value(pair[0], depth + 1, max_depth, max_nodes, state)
            result[key] = decode_value(pair[1], depth + 1, max_depth, max_nodes, state)
          end
          result
        else
          raise PStore::Error, "invalid tagged object in PStore JSON data"
        end
      else
        raise PStore::Error, "unsupported value in PStore JSON data"
      end
    end
    private_class_method :decode_value

    def check_depth(depth, max_depth)
      if depth >= max_depth
        raise PStore::Error, "data exceeds the maximum nesting depth of #{max_depth}"
      end
    end
    private_class_method :check_depth
  end
  private_constant :JSONCodec
  # :startdoc:

  # Whether \PStore should do its best to prevent file corruptions,
  # even when an unlikely error (such as memory-error or filesystem error) occurs:
  #
  # - +true+: changes are posted by creating a temporary file,
  #   writing the updated data to it, then renaming the file to the given #path.
  #   File integrity is maintained.
  #   Note: has effect only if the filesystem has atomic file rename
  #   (as do POSIX platforms Linux, MacOS, FreeBSD and others).
  #
  # - +false+ (the default): changes are posted by rewinding the open file
  #   and writing the updated data.
  #   File integrity is maintained if the filesystem raises
  #   no unexpected I/O error;
  #   if such an error occurs during a write to the store,
  #   the file may become corrupted.
  #
  attr_accessor :ultra_safe

  # Returns a new \PStore object.
  #
  # Argument +file+ is the path to the file in which objects are to be stored;
  # if the file exists, it should be one that was written by \PStore.
  #
  #   path = 't.store'
  #   store = PStore.new(path)
  #
  # A \PStore object is
  # {reentrant}[https://en.wikipedia.org/wiki/Reentrancy_(computing)].
  # If argument +thread_safe+ is given as +true+,
  # the object is also thread-safe (at the cost of a small performance penalty):
  #
  #   store = PStore.new(path, true)
  #
  # ==== Storage Format
  #
  # Optional keyword argument +format+ selects the on-disk format:
  #
  # - +:marshal+ (the default): the historical format based on module
  #   \Marshal.  Loading a Marshal file can instantiate arbitrary Ruby
  #   classes, so only open files you trust.
  # - +:json+: a versioned, type-tagged JSON format that is
  #   human-inspectable and never instantiates arbitrary Ruby classes
  #   when loading.  Only simple data can be stored: String, Symbol,
  #   Integer, finite Float, +true+, +false+, +nil+, Array and Hash.
  #   String keys and Symbol keys are kept distinct.  Unsupported
  #   objects and cyclic structures are rejected with PStore::Error.
  #
  #   store = PStore.new(path, format: :json)
  #
  # A Marshal-format file is _not_ converted implicitly; use the
  # explicit migration entry point PStore.migrate_to_json to convert
  # an existing file.
  #
  # Optional keyword arguments +max_depth+ and +max_nodes+ bound the
  # nesting depth and the total number of values accepted when
  # encoding or decoding JSON-format data (defaults: 100 and
  # 1_000_000).  They have no effect on the Marshal format.
  #
  def initialize(file, thread_safe = false,
                 format: FORMAT_MARSHAL,
                 max_depth: JSONCodec::DEFAULT_MAX_DEPTH,
                 max_nodes: JSONCodec::DEFAULT_MAX_NODES)
    dir = File::dirname(file)
    unless File::directory? dir
      raise PStore::Error, format("directory %s does not exist", dir)
    end
    if File::exist? file and not File::readable? file
      raise PStore::Error, format("file %s not readable", file)
    end
    unless FORMATS.include?(format)
      raise ArgumentError, format("unknown PStore format: %s", format.inspect)
    end
    @filename = File.path(file)
    @abort = false
    @ultra_safe = false
    @thread_safe = thread_safe
    @format = format
    @max_depth = max_depth
    @max_nodes = max_nodes
    @lock = Thread::Mutex.new
  end

  # Explicit migration entry point: converts the Marshal-format PStore
  # file at +file+ to the JSON format (see PStore.new, keyword +format+).
  #
  # The whole content of the file is validated and encoded _before_ the
  # file is touched; the file is then replaced atomically (via a
  # temporary file and rename).  If validation or writing fails, the
  # original file is left unchanged.
  #
  # Optional keyword arguments +max_depth+ and +max_nodes+ bound the
  # nesting depth and total number of values accepted in the data,
  # exactly as for PStore.new.
  #
  # Raises PStore::Error if the file does not exist, is not a
  # Marshal-format PStore file, is already in JSON format, or contains
  # data that cannot be represented in the JSON format.
  #
  # Returns +true+ on success.
  def self.migrate_to_json(file,
                           max_depth: JSONCodec::DEFAULT_MAX_DEPTH,
                           max_nodes: JSONCodec::DEFAULT_MAX_NODES)
    path = File.path(file)
    unless File.exist?(path)
      raise Error, format("file %s does not exist", path)
    end
    data = File.binread(path)
    if data.empty?
      # A zero-length file is a valid, empty PStore file.
      table = {}
    else
      if JSONCodec.json_data?(data)
        raise Error, format("file %s is already in JSON format", path)
      end
      table =
        begin
          Marshal.load(data)
        rescue StandardError => error
          raise Error, format("file %s is not a valid Marshal PStore file: %s",
                              path, error.message)
        end
      raise Error, "PStore file seems to be corrupted." unless table.is_a?(Hash)
    end
    # Fully validate and encode before touching the existing file.
    json_data = JSONCodec.dump(table, max_depth: max_depth, max_nodes: max_nodes)
    # Atomically replace the file only after successful validation.
    temp_filename = "#{path}.tmp.#{Process.pid}.#{rand 1000000}"
    begin
      File.open(temp_filename, File::WRONLY | File::CREAT | File::TRUNC | File::BINARY, 0o600) do |temp_file|
        temp_file.write(json_data)
        temp_file.flush
        begin
          temp_file.fsync
        rescue SystemCallError
        end
      end
      begin
        File.chmod(File.stat(path).mode, temp_filename)
      rescue SystemCallError
      end
      File.rename(temp_filename, path)
    rescue Exception
      File.unlink(temp_filename) rescue nil
      raise
    end
    true
  end

  # Raises PStore::Error if the calling code is not in a PStore#transaction.
  def in_transaction
    raise PStore::Error, "not in transaction" unless @lock.owned?
  end
  #
  # Raises PStore::Error if the calling code is not in a PStore#transaction or
  # if the code is in a read-only PStore#transaction.
  #
  def in_transaction_wr
    in_transaction
    raise PStore::Error, "in read-only transaction" if @rdonly
  end
  private :in_transaction, :in_transaction_wr

  # Returns the value for the given +key+ if the key exists.
  # +nil+ otherwise;
  # if not +nil+, the returned value is an object or a hierarchy of objects:
  #
  #   example_store do |store|
  #     store.transaction do
  #       store[:foo]  # => 0
  #       store[:nope] # => nil
  #     end
  #   end
  #
  # Returns +nil+ if there is no such key.
  #
  # See also {Hierarchical Values}[rdoc-ref:PStore@Hierarchical+Values].
  #
  # Raises an exception if called outside a transaction block.
  def [](key)
    in_transaction
    @table[key]
  end

  # Like #[], except that it accepts a default value for the store.
  # If the +key+ does not exist:
  #
  # - Raises an exception if +default+ is +PStore::Error+.
  # - Returns the value of +default+ otherwise:
  #
  #     example_store do |store|
  #       store.transaction do
  #         store.fetch(:nope, nil) # => nil
  #         store.fetch(:nope)      # Raises an exception.
  #       end
  #     end
  #
  # Raises an exception if called outside a transaction block.
  def fetch(key, default=PStore::Error)
    in_transaction
    unless @table.key? key
      if PStore::Error.equal?(default)
        raise PStore::Error, format("undefined key '%s'", key)
      else
        return default
      end
    end
    @table[key]
  end

  # Creates or replaces the value for the given +key+:
  #
  #   example_store do |store|
  #     temp.transaction do
  #       temp[:bat] = 3
  #     end
  #   end
  #
  # See also {Hierarchical Values}[rdoc-ref:PStore@Hierarchical+Values].
  #
  # Raises an exception if called outside a transaction block.
  def []=(key, value)
    in_transaction_wr
    @table[key] = value
  end

  # Removes and returns the value at +key+ if it exists:
  #
  #   example_store do |store|
  #     store.transaction do
  #       store[:bat] = 3
  #       store.delete(:bat)
  #     end
  #   end
  #
  # Returns +nil+ if there is no such key.
  #
  # Raises an exception if called outside a transaction block.
  def delete(key)
    in_transaction_wr
    @table.delete key
  end

  # Returns an array of the existing keys:
  #
  #   example_store do |store|
  #     store.transaction do
  #       store.keys # => [:foo, :bar, :baz]
  #     end
  #   end
  #
  # Raises an exception if called outside a transaction block.
  def keys
    in_transaction
    @table.keys
  end
  alias roots keys

  # Returns +true+ if +key+ exists, +false+ otherwise:
  #
  #   example_store do |store|
  #     store.transaction do
  #       store.key?(:foo) # => true
  #     end
  #   end
  #
  # Raises an exception if called outside a transaction block.
  def key?(key)
    in_transaction
    @table.key? key
  end
  alias root? key?

  # Returns the string file path used to create the store:
  #
  #   store.path # => "flat.store"
  #
  def path
    @filename
  end

  # Exits the current transaction block, committing any changes
  # specified in the
  # {transaction block}[rdoc-ref:PStore@The+Transaction+Block].
  #
  # Raises an exception if called outside a transaction block.
  def commit
    in_transaction
    @abort = false
    throw self
  end

  # Exits the current transaction block, discarding any changes
  # specified in the
  # {transaction block}[rdoc-ref:PStore@The+Transaction+Block].
  #
  # Raises an exception if called outside a transaction block.
  def abort
    in_transaction
    @abort = true
    throw self
  end

  # Opens a transaction block for the store.
  # See {Transactions}[rdoc-ref:PStore@Transactions].
  #
  # With argument +read_only+ as +false+, the block may both read from
  # and write to the store.
  #
  # With argument +read_only+ as +true+, the block may not include calls
  # to #transaction, #[]=, or #delete.
  #
  # Raises an exception if called within a transaction block.
  def transaction(read_only = false)  # :yields:  pstore
    value = nil
    if !@thread_safe
      raise PStore::Error, "nested transaction" unless @lock.try_lock
    else
      begin
        @lock.lock
      rescue ThreadError
        raise PStore::Error, "nested transaction"
      end
    end
    begin
      @rdonly = read_only
      @abort = false
      file = open_and_lock_file(@filename, read_only)
      if file
        begin
          @table, checksum, original_data_size = load_data(file, read_only)

          catch(self) do
            value = yield(self)
          end

          if !@abort && !read_only
            save_data(checksum, original_data_size, file)
          end
        ensure
          file.close
        end
      else
        # This can only occur if read_only == true.
        @table = {}
        catch(self) do
          value = yield(self)
        end
      end
    ensure
      @lock.unlock
    end
    value
  end

  private
  # :stopdoc:

  def json_format?
    @format == FORMAT_JSON
  end

  # Constant for relieving Ruby's garbage collector.
  CHECKSUM_ALGO = %w[SHA512 SHA384 SHA256 SHA1 RMD160 MD5].each do |algo|
    begin
      break Digest(algo)
    rescue LoadError
    end
  end
  EMPTY_STRING = ""
  EMPTY_MARSHAL_DATA = Marshal.dump({})
  EMPTY_MARSHAL_CHECKSUM = CHECKSUM_ALGO.digest(EMPTY_MARSHAL_DATA)

  EMPTY_MARSHAL_DATA.freeze
  EMPTY_MARSHAL_CHECKSUM.freeze
  private_constant :CHECKSUM_ALGO, :EMPTY_STRING, :EMPTY_MARSHAL_DATA, :EMPTY_MARSHAL_CHECKSUM

  #
  # Open the specified filename (either in read-only mode or in
  # read-write mode) and lock it for reading or writing.
  #
  # The opened File object will be returned. If _read_only_ is true,
  # and the file does not exist, then nil will be returned.
  #
  # All exceptions are propagated.
  #
  def open_and_lock_file(filename, read_only)
    filename = File.path(filename)
    loop do
      if read_only
        begin
          file = File.new(filename, **RD_ACCESS)
        rescue Errno::ENOENT
          return nil
        end
      else
        file = File.new(filename, **RDWR_ACCESS)
      end
      current = false
      begin
        file.flock(read_only ? File::LOCK_SH : File::LOCK_EX)
        # An atomic save may have replaced the file while this lock was pending.
        current = File.identical?(file, filename)
        return file if current
      ensure
        file.close unless current
      end
    end
  end

  # Load the given PStore file.
  # If +read_only+ is true, the unmarshalled Hash will be returned.
  # If +read_only+ is false, a 3-tuple will be returned: the unmarshalled
  # Hash, a checksum of the data, and the size of the data.
  def load_data(file, read_only)
    if read_only
      begin
        table = load(file)
        raise Error, "PStore file seems to be corrupted." unless table.is_a?(Hash)
      rescue EOFError
        raise unless file.size == 0
        # This seems to be a newly-created file.
        table = {}
      end
      table
    else
      data = file.read
      if data.empty?
        # This seems to be a newly-created file.
        table = {}
        checksum = empty_checksum
        size = empty_data.bytesize
      else
        table = load(data)
        checksum = CHECKSUM_ALGO.digest(data)
        size = data.bytesize
        raise Error, "PStore file seems to be corrupted." unless table.is_a?(Hash)
      end
      data.replace(EMPTY_STRING)
      [table, checksum, size]
    end
  end

  ON_WINDOWS = true & (/mswin|mingw|bccwin|wince/ =~ RUBY_PLATFORM) # :nodoc:
  private_constant :ON_WINDOWS

  def save_data(original_checksum, original_file_size, file)
    new_data = dump(@table)

    if new_data.bytesize != original_file_size || CHECKSUM_ALGO.digest(new_data) != original_checksum
      if @ultra_safe && !ON_WINDOWS
        # Once a file is locked, Windows does not guarantee that the
        # lock will be released until the file is closed.
        save_data_with_atomic_file_rename_strategy(new_data, file)
      else
        save_data_with_fast_strategy(new_data, file)
      end
    end

    new_data.replace(EMPTY_STRING)
  end

  def save_data_with_atomic_file_rename_strategy(data, file)
    temp_filename = "#{@filename}.tmp.#{Process.pid}.#{rand 1000000}"
    temp_file = File.new(temp_filename, **WR_ACCESS, perm: 0o000)
    begin
      temp_file.flock(File::LOCK_EX)
      temp_file.write(data)
      temp_file.flush
      temp_file.chmod(file.stat.mode)
      File.rename(temp_filename, @filename)
    rescue Exception
      File.unlink(temp_file) rescue nil
      raise
    ensure
      temp_file.close
    end
  end

  def save_data_with_fast_strategy(data, file)
    file.rewind
    file.write(data)
    file.truncate(data.bytesize)
  end


  # This method is just a wrapper around Marshal.dump (or the JSON
  # codec, for JSON-format stores) to allow subclass overriding used
  # in YAML::Store.
  def dump(table)  # :nodoc:
    if json_format?
      JSONCodec.dump(table, max_depth: @max_depth, max_nodes: @max_nodes)
    else
      Marshal::dump(table)
    end
  end

  # This method is just a wrapper around Marshal.load (or the JSON
  # codec, for JSON-format stores) to allow subclass overriding used
  # in YAML::Store.
  def load(content)  # :nodoc:
    if json_format?
      data = content.is_a?(String) ? content : content.read
      if JSONCodec.marshal_data?(data)
        raise Error, format("PStore file %s is in Marshal format; " \
                            "migrate it with PStore.migrate_to_json", @filename)
      end
      JSONCodec.load(data, max_depth: @max_depth, max_nodes: @max_nodes)
    else
      if content.is_a?(String)
        if JSONCodec.json_data?(content)
          raise Error, format("PStore file %s is in JSON format; " \
                              "open it with PStore.new(file, format: :json)", @filename)
        end
        Marshal::load(content)
      else
        # Peek at the IO without disturbing Marshal.load's behavior.
        pos = content.pos
        head = content.read(JSONCodec::MAGIC.bytesize) || ""
        content.pos = pos
        if JSONCodec.json_data?(head)
          raise Error, format("PStore file %s is in JSON format; " \
                              "open it with PStore.new(file, format: :json)", @filename)
        end
        Marshal::load(content)
      end
    end
  end

  def empty_data
    json_format? ? JSONCodec.dump({}) : empty_marshal_data
  end

  def empty_checksum
    json_format? ? CHECKSUM_ALGO.digest(empty_data) : empty_marshal_checksum
  end

  def empty_marshal_data
    EMPTY_MARSHAL_DATA
  end
  def empty_marshal_checksum
    EMPTY_MARSHAL_CHECKSUM
  end
end
