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
# == Multi-Store Transactions
#
# PStore.coordinate starts a recoverable transaction across multiple stores:
#
#   PStore.coordinate(account_store, ledger_store) do |account, ledger|
#     account[:balance] -= amount
#     ledger[:transfers] << amount
#   end
#
# Stores are locked in a stable path order. Prepared values are written to
# separate files first. The coordinator then records the final commit decision
# and publishes participants one at a time with the usual per-file rename.
# Those individual renames are not collectively atomic. Recovery makes the
# already-recorded outcome consistent: a committed decision finishes the
# remaining publications, while a transaction interrupted before that decision
# rolls back the prepared files. Reopening a participant performs recovery.
# A missing or corrupt coordinator record is an error rather than a guess.
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

  # Opens a recoverable transaction across multiple stores.
  # The stores are locked in a stable path order, prepared values are written
  # to side files, the commit decision is journaled, and each store is then
  # published. Reopening any participant after an interrupted transaction
  # completes or rolls back the recorded transaction.
  def self.coordinate(*stores)
    TransactionCoordinator.new(*stores).transaction do |*coordinated_stores|
      yield(*coordinated_stores)
    end
  end

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
  def initialize(file, thread_safe = false)
    dir = File::dirname(file)
    unless File::directory? dir
      raise PStore::Error, format("directory %s does not exist", dir)
    end
    if File::exist? file and not File::readable? file
      raise PStore::Error, format("file %s not readable", file)
    end
    @filename = File.path(file)
    @abort = false
    @ultra_safe = false
    @thread_safe = thread_safe
    @lock = Thread::Mutex.new
    @coordinator = nil
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
    throw(@coordinator || self)
  end

  # Exits the current transaction block, discarding any changes
  # specified in the
  # {transaction block}[rdoc-ref:PStore@The+Transaction+Block].
  #
  # Raises an exception if called outside a transaction block.
  def abort
    in_transaction
    @abort = true
    if @coordinator
      @coordinator.abort!
    else
      throw self
    end
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
    lock_transaction
    begin
      @rdonly = read_only
      @abort = false
      @coordinator = nil
      file = nil
      loop do
        file = open_and_lock_file(@filename, read_only)
        if PStore::TransactionRecovery.pending_marker?(@filename)
          file&.close
          PStore::TransactionRecovery.recover_for_file(@filename)
          next
        end
        break
      end
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
      @coordinator = nil
      @lock.unlock
    end
    value
  end

  private
  # :stopdoc:

  def lock_transaction
    if !@thread_safe
      raise PStore::Error, "nested transaction" unless @lock.try_lock
    else
      begin
        @lock.lock
      rescue ThreadError
        raise PStore::Error, "nested transaction"
      end
    end
  end

  def lock_for_coordinator
    @lock.lock
  rescue ThreadError
    raise PStore::Error, "nested transaction"
  end

  def unlock_for_coordinator
    @lock.unlock if @lock.owned?
  end

  def begin_coordinated_transaction(coordinator, file)
    @rdonly = false
    @abort = false
    @coordinator = coordinator
    @table, @original_checksum, @original_size = load_data(file, false)
  end

  def reset_coordinated_transaction
    @rdonly = nil
    @abort = false
    @coordinator = nil
    @table = nil
    @original_checksum = nil
    @original_size = nil
  end

  def coordinated_state
    {
      path: File.expand_path(@filename),
      table: @table,
      original_checksum: @original_checksum,
      original_size: @original_size
    }
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
        checksum = empty_marshal_checksum
        size = empty_marshal_data.bytesize
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


  # This method is just a wrapped around Marshal.dump
  # to allow subclass overriding used in YAML::Store.
  def dump(table)  # :nodoc:
    Marshal::dump(table)
  end

  # This method is just a wrapped around Marshal.load.
  # to allow subclass overriding used in YAML::Store.
  def load(content)  # :nodoc:
    Marshal::load(content)
  end

  def empty_marshal_data
    EMPTY_MARSHAL_DATA
  end
  def empty_marshal_checksum
    EMPTY_MARSHAL_CHECKSUM
  end

  def self.checksum_algo
    CHECKSUM_ALGO
  end

  def self.empty_marshal_data
    EMPTY_MARSHAL_DATA
  end

  def self.empty_marshal_checksum
    EMPTY_MARSHAL_CHECKSUM
  end

  class TransactionCoordinator
    def initialize(*stores)
      @stores = stores
      if @stores.length < 2
        raise PStore::Error, "at least two stores are required"
      end
      unless @stores.all? { |store| store.is_a?(PStore) }
        raise PStore::Error, "only PStore instances can be coordinated"
      end
      paths = @stores.map { |store| File.expand_path(store.path) }
      if paths.uniq.length != paths.length
        raise PStore::Error, "duplicate PStore paths are not allowed"
      end
      @ordered_stores = @stores.sort_by { |store| File.expand_path(store.path) }
      @throw_tag = Object.new
    end

    def transaction
      files = {}
      prepared_record = nil
      committed = false
      value = nil
      @ordered_stores.each { |store| store.send(:lock_for_coordinator) }
      begin
        loop do
          files.each_value(&:close)
          files = {}
          @ordered_stores.each do |store|
            files[store] = store.send(:open_and_lock_file, store.path, false)
          end
          if @ordered_stores.any? { |store| PStore::TransactionRecovery.pending_marker?(store.path) }
            files.each_value { |file| file.close unless file.closed? }
            files = {}
            PStore::TransactionRecovery.recover_paths(@ordered_stores.map(&:path))
            next
          end
          break
        end

        @ordered_stores.each do |store|
          store.send(:begin_coordinated_transaction, self, files[store])
        end
        begin
          aborted = catch(@throw_tag) do
            value = yield(*@stores)
            false
          end
          return nil if aborted
          prepared_record = prepare
          before_commit_decision
          record_commit_decision(prepared_record)
          committed = true
          publish(prepared_record)
          cleanup(prepared_record)
        ensure
          @ordered_stores.each { |store| store.send(:reset_coordinated_transaction) }
        end
      rescue Exception
        if prepared_record && !committed
          PStore::TransactionRecovery.rollback_prepared(prepared_record, validate_markers: false)
        end
        raise
      ensure
        files.each_value { |file| file.close unless file.closed? }
        @ordered_stores.each { |store| store.send(:unlock_for_coordinator) }
      end
      value
    end

    def abort!
      throw @throw_tag, true
    end

    private

    def before_commit_decision
    end

    def prepare
      transaction_id = generate_transaction_id
      record = nil
      states = []
      journal_path = PStore::TransactionRecovery.journal_path(@ordered_stores.map(&:path), transaction_id)
      states = @ordered_stores.map do |store|
        state = store.send(:coordinated_state)
        data = store.send(:dump, state[:table])
        target_path = state[:path]
        temp_path = PStore::TransactionRecovery.temp_path(target_path, transaction_id)
        mode = File.exist?(target_path) ? File.stat(target_path).mode : 0o600
        write_file_atomically(temp_path, data, perm: mode)
        {
          path: target_path,
          temp_path: temp_path,
          mode: mode,
          data_checksum: PStore.checksum_algo.digest(data),
          data_size: data.bytesize,
          old_checksum: state[:original_checksum],
          old_size: state[:original_size]
        }
      end
      record = {
        transaction_id: transaction_id,
        state: "prepared",
        journal_path: journal_path,
        participants: states
      }
      write_file_atomically(journal_path, PStore::TransactionRecovery.dump_record(record), perm: 0o600)
      states.each do |state|
        marker = {
          transaction_id: transaction_id,
          journal_path: journal_path
        }
        write_file_atomically(
          PStore::TransactionRecovery.marker_path(state[:path], transaction_id),
          PStore::TransactionRecovery.dump_record(marker),
          perm: 0o600
        )
      end
      record
    rescue Exception
      if record
        PStore::TransactionRecovery.rollback_prepared(record, validate_markers: false)
      else
        states.each { |state| File.unlink(state[:temp_path]) if File.exist?(state[:temp_path]) }
        File.unlink(journal_path) if File.exist?(journal_path)
      end
      raise
    end

    def record_commit_decision(record)
      committed_record = record.merge(state: "committed")
      write_file_atomically(
        record[:journal_path],
        PStore::TransactionRecovery.dump_record(committed_record),
        perm: 0o600
      )
    end

    def publish(record)
      record[:participants].each do |participant|
        publish_participant(participant)
      end
    end

    def publish_participant(participant)
      PStore::TransactionRecovery.publish_committed_participant(participant)
    end

    def cleanup(record)
      record[:participants].each do |participant|
        marker_path = PStore::TransactionRecovery.marker_path(participant[:path], record[:transaction_id])
        File.unlink(marker_path) if File.exist?(marker_path)
        PStore::TransactionRecovery.sync_directory(File.dirname(marker_path))
      end
      File.unlink(record[:journal_path]) if File.exist?(record[:journal_path])
      PStore::TransactionRecovery.sync_directory(File.dirname(record[:journal_path]))
    end

    def generate_transaction_id
      "#{Process.pid}.#{(Time.now.to_r * 1_000_000).numerator}.#{rand(1 << 64)}.#{object_id}"
    end

    def write_file_atomically(path, data, perm:)
      PStore::TransactionRecovery.write_file_atomically(path, data, perm: perm)
    end
  end

  module TransactionRecovery
    module_function

    def pending_marker?(store_path)
      path = File.expand_path(store_path)
      Dir.glob(marker_pattern(path)).any? || related_journal_paths([path]).any?
    end

    def recover_for_file(store_path)
      recover_paths([store_path])
    end

    def recover_paths(paths)
      expanded_paths = paths.map { |path| File.expand_path(path) }.uniq
      marker_paths = expanded_paths.flat_map { |path| Dir.glob(marker_pattern(path)) }.uniq
      marker_records = marker_paths.map { |path| validate_marker!(load_record(path), path) }
      marker_journals = marker_records.map { |record| record[:journal_path] }
      journal_paths = (marker_journals + related_journal_paths(expanded_paths)).uniq.sort
      journal_paths.each { |journal_path| recover_journal(journal_path, expanded_paths) }
    end

    def recover_journal(journal_path, allowed_paths = nil)
      journal = load_record(journal_path)
      validate_record!(journal, journal_path)
      participants = journal.fetch(:participants).sort_by { |participant| participant.fetch(:path) }
      participant_paths = participants.map { |participant| participant.fetch(:path) }
      if allowed_paths && participant_paths.none? { |path| allowed_paths.include?(path) }
        raise PStore::Error, "unrelated transaction recovery record #{journal_path}"
      end
      files = {}
      begin
        participants.each do |participant|
          files[participant.fetch(:path)] = open_exclusive(participant.fetch(:path))
        end
        case journal.fetch(:state)
        when "prepared"
          rollback_prepared(journal, validate_markers: false)
        when "committed"
          participants.each { |participant| publish_committed_participant(participant) }
          cleanup_committed(journal)
        else
          raise PStore::Error, "unknown transaction state #{journal[:state].inspect}"
        end
      ensure
        files.each_value { |file| file.close unless file.closed? }
      end
    end

    def rollback_prepared(record, validate_markers: true)
      participants = record.fetch(:participants)
      participants.each do |participant|
        validate_participant!(participant)
        verify_current_file(participant, participant.fetch(:old_checksum), participant.fetch(:old_size))
        marker_path = marker_path(participant.fetch(:path), record.fetch(:transaction_id))
        if File.exist?(marker_path) && !File.exist?(participant.fetch(:temp_path))
          raise PStore::Error, "missing prepared transaction file #{participant.fetch(:temp_path)}"
        elsif validate_markers && !File.exist?(marker_path)
          raise PStore::Error, "missing participant marker #{marker_path}"
        end
      end
      participants.each do |participant|
        marker = marker_path(participant.fetch(:path), record.fetch(:transaction_id))
        File.unlink(marker) if File.exist?(marker)
        sync_directory(File.dirname(marker))
        if participant[:temp_path] && File.exist?(participant[:temp_path])
          File.unlink(participant[:temp_path])
          sync_directory(File.dirname(participant[:temp_path]))
        end
      end
      File.unlink(record[:journal_path]) if record[:journal_path] && File.exist?(record[:journal_path])
      sync_directory(File.dirname(record[:journal_path])) if record[:journal_path]
    end

    def publish_committed_participant(participant)
      validate_participant!(participant)
      path = participant.fetch(:path)
      temp_path = participant.fetch(:temp_path)
      expected_checksum = participant.fetch(:data_checksum)
      expected_size = participant.fetch(:data_size)
      current = current_checksum(path)
      expected_new = [expected_checksum, expected_size]
      return if current == expected_new
      unless File.exist?(temp_path)
        raise PStore::Error, "missing prepared transaction file #{temp_path}"
      end
      data = File.binread(temp_path)
      verify_data(data, expected_checksum, expected_size, temp_path)
      expected_old = [participant.fetch(:old_checksum), participant.fetch(:old_size)]
      unless current == expected_old || current == expected_new
        raise PStore::Error, "unexpected transaction target contents #{path}"
      end
      return if current == expected_new
      File.rename(temp_path, path)
      sync_directory(File.dirname(path))
    end

    def cleanup_committed(record)
      participants = record.fetch(:participants)
      participants.each do |participant|
        marker = marker_path(participant.fetch(:path), record.fetch(:transaction_id))
        File.unlink(marker) if File.exist?(marker)
        sync_directory(File.dirname(marker))
      end
      File.unlink(record.fetch(:journal_path)) if File.exist?(record.fetch(:journal_path))
      sync_directory(File.dirname(record.fetch(:journal_path)))
    end

    def verify_current_file(participant, expected_checksum, expected_size)
      current = current_checksum(participant.fetch(:path))
      unless current == [expected_checksum, expected_size]
        raise PStore::Error, "transaction participant changed outside recovery #{participant.fetch(:path)}"
      end
    end

    def current_checksum(path)
      if File.exist?(path) && File.size(path) > 0
        data = File.binread(path)
        [PStore.checksum_algo.digest(data), data.bytesize]
      else
        [PStore.empty_marshal_checksum, PStore.empty_marshal_data.bytesize]
      end
    end

    def verify_data(data, expected_checksum, expected_size, path)
      unless data.bytesize == expected_size && PStore.checksum_algo.digest(data) == expected_checksum
        raise PStore::Error, "corrupted prepared transaction file #{path}"
      end
    end

    def dump_record(record)
      payload = Marshal.dump(record)
      Marshal.dump(version: 1, checksum: PStore.checksum_algo.digest(payload), payload: payload)
    end

    def load_record(path)
      unless File.exist?(path)
        raise PStore::Error, "missing transaction recovery record #{path}"
      end
      envelope = Marshal.load(File.binread(path))
      payload = envelope[:payload]
      unless envelope.is_a?(Hash) && payload.is_a?(String) &&
             PStore.checksum_algo.digest(payload) == envelope[:checksum]
        raise PStore::Error, "corrupted transaction recovery record #{path}"
      end
      record = Marshal.load(payload)
      raise PStore::Error, "corrupted transaction recovery record #{path}" unless record.is_a?(Hash)
      record
    rescue StandardError => error
      raise PStore::Error, "corrupted transaction recovery record #{path}: #{error.message}"
    end

    def validate_record!(record, path)
      required = [:transaction_id, :state, :journal_path, :participants]
      unless required.all? { |key| record.key?(key) } &&
             record[:participants].is_a?(Array) && !record[:participants].empty? &&
             record[:transaction_id].is_a?(String) && !record[:transaction_id].empty? &&
             record[:journal_path].is_a?(String) &&
             %w[prepared committed].include?(record[:state]) &&
             record[:participants].map { |participant| participant[:path] }.uniq.length == record[:participants].length
        raise PStore::Error, "corrupted transaction recovery record #{path}"
      end
      unless File.expand_path(record[:journal_path]) == File.expand_path(path)
        raise PStore::Error, "corrupted transaction recovery record #{path}"
      end
      record[:participants].each { |participant| validate_participant!(participant) }
    end

    def validate_participant!(participant)
      required = [:path, :temp_path, :mode, :data_checksum, :data_size, :old_checksum, :old_size]
      valid = participant.is_a?(Hash) && required.all? { |key| participant.key?(key) } &&
              participant[:path].is_a?(String) && participant[:temp_path].is_a?(String) &&
              participant[:mode].is_a?(Integer) &&
              participant[:data_checksum].is_a?(String) && participant[:old_checksum].is_a?(String) &&
              participant[:data_size].is_a?(Integer) && participant[:data_size] >= 0 &&
              participant[:old_size].is_a?(Integer) && participant[:old_size] >= 0
      raise PStore::Error, "corrupted transaction participant record" unless valid
    end

    def validate_marker!(record, path)
      unless record.is_a?(Hash) && record[:transaction_id].is_a?(String) && !record[:transaction_id].empty? &&
             record[:journal_path].is_a?(String) && record[:journal_path].start_with?(File::SEPARATOR)
        raise PStore::Error, "corrupted transaction marker #{path}"
      end
      record
    end

    def related_journal_paths(paths)
      paths.flat_map do |path|
        Dir.glob(File.join(File.dirname(path), ".pstore-coordinator.*")).select do |journal_path|
          next false unless File.file?(journal_path)
          journal = load_record(journal_path)
          journal[:participants].is_a?(Array) &&
            journal[:participants].any? do |participant|
              participant.is_a?(Hash) && participant[:path] == path
            end
        end
      end.uniq
    end

    def write_file_atomically(path, data, perm:)
      temp_path = "#{path}.write.#{Process.pid}.#{rand(1 << 64)}"
      File.open(temp_path, File::RDWR | File::CREAT | File::EXCL | File::BINARY, 0o000) do |file|
        file.write(data)
        file.flush
        file.fsync
      end
      File.chmod(perm, temp_path)
      File.rename(temp_path, path)
      sync_directory(File.dirname(path))
    rescue Exception
      File.unlink(temp_path) if temp_path && File.exist?(temp_path)
      raise
    end

    def open_exclusive(path)
      loop do
        file = File.new(path, **PStore.const_get(:RDWR_ACCESS))
        current = false
        begin
          file.flock(File::LOCK_EX)
          current = File.identical?(file, path)
          return file if current
        ensure
          file.close unless current
        end
      end
    end

    def marker_pattern(path)
      File.join(File.dirname(path), ".#{File.basename(path)}.pstore-coordinator.*")
    end

    def marker_path(path, transaction_id)
      File.join(File.dirname(path), ".#{File.basename(path)}.pstore-coordinator.#{transaction_id}")
    end

    def temp_path(path, transaction_id)
      "#{path}.tmp.pstore-coordinator.#{transaction_id}"
    end

    def journal_path(store_paths, transaction_id)
      expanded_paths = store_paths.map { |path| File.expand_path(path) }.sort
      digest = Digest::SHA256.hexdigest(expanded_paths.join("\0"))
      File.join(File.dirname(expanded_paths.first), ".pstore-coordinator.#{digest}.#{transaction_id}")
    end

    def sync_directory(path)
      dir = File.open(path, File::RDONLY | File::BINARY)
      dir.fsync
    ensure
      dir&.close
    end
  end
end
