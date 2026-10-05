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
# == Storage Formats
#
# By default, a store file is written with Marshal (see above).
# Marshal can serialize almost any Ruby object, but its output is opaque
# and loading it may instantiate arbitrary Ruby classes,
# which is not suitable for untrusted data.
#
# As an alternative, a store may use an optional, typed JSON format
# that is human-readable, inspectable, and never instantiates
# arbitrary Ruby classes when loading:
#
#   store = PStore.new('t.store', format: :json)
#
# The JSON format supports exactly these kinds of objects:
#
# - +nil+, +true+, and +false+.
# - Strings.
# - Symbols.
# - Integers.
# - Finite floats (NaN and infinities are rejected).
# - Arrays of supported objects.
# - Hashes whose keys and values are supported objects;
#   string keys and symbol keys are kept distinct.
#
# Any other object is rejected with PStore::Error,
# as is any object graph containing circular references.
# Files in the JSON format carry a format version,
# and decoding enforces limits on nesting depth and total node count;
# see PStore::JSONFormat.
#
# A store opened with +format: :json+ does not read Marshal files.
# An existing Marshal file can only be converted through the explicit
# migration entry point PStore.migrate_to_json, which fully validates
# the data before atomically replacing the file;
# if validation fails, the original file is left untouched.
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

  # The default on-disk format, using module Marshal.
  FORMAT_MARSHAL = :marshal

  # The optional typed JSON on-disk format; see PStore::JSONFormat.
  FORMAT_JSON = :json

  # :stopdoc:
  #
  # Implementation of the optional typed JSON storage format.
  #
  # A file in this format is a JSON object envelope:
  #
  #   {"format": "pstore-json", "version": 1, "data": <node>}
  #
  # where +data+ is the stored Hash, encoded as a typed node.
  # Nodes map to JSON as follows:
  #
  # - +nil+, +true+, +false+, Integer, finite Float, and String
  #   map to their native JSON counterparts.
  # - Array maps to a JSON array of encoded elements.
  # - Symbol maps to a tagged object:
  #   <tt>{"__pstore_type__": "symbol", "value": <name>}</tt>.
  # - Hash maps to a tagged object holding an array of encoded
  #   key/value pairs, so that string keys and symbol keys
  #   (and any other supported key types) stay distinct:
  #   <tt>{"__pstore_type__": "hash", "entries": [[k, v], ...]}</tt>.
  #
  # Decoding never instantiates arbitrary Ruby classes,
  # and is bounded by MAX_DEPTH and MAX_NODES.
  module JSONFormat
    FORMAT_NAME = "pstore-json"
    FORMAT_VERSION = 1

    TYPE_TAG = "__pstore_type__"
    SYMBOL_TAG = "symbol"
    HASH_TAG = "hash"
    TAG_VALUE = "value"
    TAG_ENTRIES = "entries"

    # Maximum nesting depth accepted when decoding.
    MAX_DEPTH = 100
    # Maximum total number of nodes accepted when decoding.
    MAX_NODES = 1_000_000

    NOT_JSON_MESSAGE =
      "PStore file is not in JSON format " \
      "(migrate a Marshal file with PStore.migrate_to_json)"

    module_function

    # Returns the JSON text for the given table Hash.
    # Raises PStore::Error if the table contains unsupported objects
    # or circular references.
    def encode_table(table)
      envelope = {
        "format" => FORMAT_NAME,
        "version" => FORMAT_VERSION,
        "data" => encode_value(table, {}, 1),
      }
      JSON.generate(envelope)
    rescue JSON::GeneratorError => error
      raise PStore::Error, "cannot encode value in JSON format: #{error.message}"
    end

    # Returns the table Hash stored in the given JSON text (or IO).
    # Raises PStore::Error if the content is not a valid JSON format
    # file, has an unsupported version, is malformed,
    # or exceeds the decoding limits.
    def decode_table(content)
      content = content.read if content.respond_to?(:read)
      content = content.dup.force_encoding(Encoding::UTF_8)
      begin
        root = JSON.parse(content, max_nesting: MAX_DEPTH + 1)
      rescue JSON::NestingError
        raise PStore::Error,
              "PStore JSON file exceeds the depth limit of #{MAX_DEPTH}"
      rescue JSON::ParserError
        raise PStore::Error, NOT_JSON_MESSAGE
      end
      unless root.is_a?(Hash) && root["format"] == FORMAT_NAME
        raise PStore::Error, NOT_JSON_MESSAGE
      end
      unless root["version"] == FORMAT_VERSION
        raise PStore::Error,
              "unsupported PStore JSON format version: #{root["version"].inspect}"
      end
      table = decode_value(root["data"], 1, [0])
      raise PStore::Error, "PStore file seems to be corrupted." unless table.is_a?(Hash)
      table
    end

    # Returns true if the given string looks like a JSON format file.
    def envelope?(data)
      root = JSON.parse(data.dup.force_encoding(Encoding::UTF_8))
      root.is_a?(Hash) && root["format"] == FORMAT_NAME
    rescue JSON::ParserError, TypeError
      false
    end

    def encode_value(value, seen, depth)
      if depth > MAX_DEPTH
        raise PStore::Error,
              "cannot store object graph deeper than #{MAX_DEPTH} levels in JSON format"
      end
      case value
      when nil, true, false, Integer, String
        value
      when Float
        unless value.finite?
          raise PStore::Error,
                "cannot store non-finite Float #{value.inspect} in JSON format"
        end
        value
      when Symbol
        {TYPE_TAG => SYMBOL_TAG, TAG_VALUE => value.name}
      when Array
        encode_container(value, seen) do
          value.map {|element| encode_value(element, seen, depth + 1) }
        end
      when Hash
        entries = encode_container(value, seen) do
          value.map do |key, element|
            [encode_value(key, seen, depth + 1), encode_value(element, seen, depth + 1)]
          end
        end
        {TYPE_TAG => HASH_TAG, TAG_ENTRIES => entries}
      else
        raise PStore::Error, "cannot store #{value.class} in JSON format"
      end
    end

    def encode_container(value, seen)
      id = value.__id__
      if seen[id]
        raise PStore::Error, "cannot store circular references in JSON format"
      end
      seen[id] = true
      begin
        yield
      ensure
        seen.delete(id)
      end
    end

    def decode_value(node, depth, budget)
      budget[0] += 1
      if budget[0] > MAX_NODES
        raise PStore::Error,
              "PStore JSON file exceeds the limit of #{MAX_NODES} nodes"
      end
      if depth > MAX_DEPTH
        raise PStore::Error,
              "PStore JSON file exceeds the depth limit of #{MAX_DEPTH}"
      end
      case node
      when nil, true, false, Integer, Float, String
        node
      when Array
        node.map {|element| decode_value(element, depth + 1, budget) }
      when Hash
        decode_tagged_node(node, depth, budget)
      else
        raise PStore::Error, "unexpected JSON value in PStore file"
      end
    end

    def decode_tagged_node(node, depth, budget)
      case node[TYPE_TAG]
      when SYMBOL_TAG
        name = node[TAG_VALUE]
        unless node.size == 2 && name.is_a?(String)
          raise PStore::Error, "malformed symbol node in PStore JSON file"
        end
        name.to_sym
      when HASH_TAG
        entries = node[TAG_ENTRIES]
        unless node.size == 2 && entries.is_a?(Array)
          raise PStore::Error, "malformed hash node in PStore JSON file"
        end
        result = {}
        entries.each do |entry|
          unless entry.is_a?(Array) && entry.size == 2
            raise PStore::Error, "malformed hash entry in PStore JSON file"
          end
          key = decode_value(entry[0], depth + 1, budget)
          result[key] = decode_value(entry[1], depth + 1, budget)
        end
        result
      else
        raise PStore::Error,
              "unknown type tag #{node[TYPE_TAG].inspect} in PStore JSON file"
      end
    end
  end
  private_constant :JSONFormat
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
  # Keyword argument +format+ selects the on-disk format:
  #
  # - <tt>format: :marshal</tt> (the default): read and write Marshal files.
  # - <tt>format: :json</tt>: read and write the typed JSON format;
  #   see {Storage Formats}[rdoc-ref:PStore@Storage+Formats].
  #   A Marshal file is not read implicitly in this mode;
  #   convert it first with PStore.migrate_to_json.
  #
  #   store = PStore.new(path, format: :json)
  #
  def initialize(file, thread_safe = false, format: FORMAT_MARSHAL)
    dir = File::dirname(file)
    unless File::directory? dir
      raise PStore::Error, format("directory %s does not exist", dir)
    end
    if File::exist? file and not File::readable? file
      raise PStore::Error, format("file %s not readable", file)
    end
    unless FORMAT_MARSHAL == format || FORMAT_JSON == format
      raise ArgumentError, "unknown PStore format: #{format.inspect}"
    end
    @filename = File.path(file)
    @abort = false
    @ultra_safe = false
    @thread_safe = thread_safe
    @format = format
    @lock = Thread::Mutex.new
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

  # Converts the \Marshal format \PStore file at +file+
  # to the typed JSON format (see
  # {Storage Formats}[rdoc-ref:PStore@Storage+Formats]).
  #
  # This is the only way to convert a \Marshal file:
  # a store opened with <tt>format: :json</tt> never reads
  # \Marshal data implicitly.
  #
  # The stored data is fully validated and re-encoded before anything
  # is written; the file is then replaced atomically
  # (via a temporary file and rename).
  # If the data contains objects that the JSON format cannot represent
  # or circular references, or if any other error occurs,
  # PStore::Error (or the original exception) is raised
  # and the original file is left untouched:
  #
  #   PStore.migrate_to_json('t.store')
  #   store = PStore.new('t.store', format: :json)
  #
  # Raises PStore::Error if the file does not exist,
  # is not a valid \Marshal \PStore file,
  # or is already in the JSON format.
  def self.migrate_to_json(file)
    path = File.path(file)
    unless File::exist? path
      raise PStore::Error, format("file %s does not exist", path)
    end
    data = File.binread(path)
    if data.empty?
      table = {}
    else
      if JSONFormat.envelope?(data)
        raise PStore::Error, format("file %s is already in JSON format", path)
      end
      begin
        table = Marshal.load(data)
      rescue StandardError => error
        raise PStore::Error,
              format("file %s is not a valid Marshal PStore file: %s", path, error.message)
      end
      unless table.is_a?(Hash)
        raise PStore::Error, format("file %s is not a valid Marshal PStore file", path)
      end
    end

    # Fully validate by encoding everything before touching the file,
    # and verify that the payload decodes back to the same data.
    payload = JSONFormat.encode_table(table)
    unless JSONFormat.decode_table(payload) == table
      raise PStore::Error, format("file %s could not be converted faithfully", path)
    end

    temp_filename = "#{path}.tmp.#{Process.pid}.#{rand 1000000}"
    begin
      File.open(temp_filename, File::WRONLY | File::CREAT | File::TRUNC | File::BINARY) do |temp_file|
        temp_file.flock(File::LOCK_EX)
        temp_file.write(payload)
        temp_file.flush
        temp_file.chmod(File.stat(path).mode) rescue nil
      end
      File.rename(temp_filename, path)
    rescue Exception
      File.unlink(temp_filename) rescue nil
      raise
    end
    true
  end

  private
  # :stopdoc:

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
        if file.size == 0
          # This seems to be a newly-created file.
          table = {}
        else
          table = load(file)
          raise Error, "PStore file seems to be corrupted." unless table.is_a?(Hash)
        end
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
        if @format == FORMAT_JSON
          empty_data = dump({})
          checksum = CHECKSUM_ALGO.digest(empty_data)
          size = empty_data.bytesize
        else
          checksum = empty_marshal_checksum
          size = empty_marshal_data.bytesize
        end
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


  # This method is just a wrapper around the format's dump routine
  # to allow subclass overriding used in YAML::Store.
  def dump(table)  # :nodoc:
    if @format == FORMAT_JSON
      JSONFormat.encode_table(table)
    else
      Marshal::dump(table)
    end
  end

  # This method is just a wrapper around the format's load routine
  # to allow subclass overriding used in YAML::Store.
  def load(content)  # :nodoc:
    if @format == FORMAT_JSON
      JSONFormat.decode_table(content)
    else
      Marshal::load(content)
    end
  end

  def empty_marshal_data
    EMPTY_MARSHAL_DATA
  end
  def empty_marshal_checksum
    EMPTY_MARSHAL_CHECKSUM
  end
end
