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
# === Updating Several Stores Together
#
# A single PStore#transaction protects one file. To update two or more store
# files as one recoverable unit, use PStore::TransactionCoordinator:
#
#   accounts = PStore.new('accounts.store')
#   ledger   = PStore.new('ledger.store')
#   PStore::TransactionCoordinator.transaction(accounts, ledger) do |a, l|
#     a[:balance] -= 100
#     l[:entries] << [:withdrawal, 100]
#   end
#
# The coordinator performs an explicit two-phase commit: it first records a
# durable prepare state and a final commit/abort decision in a coordination
# journal, and only then publishes the store files one at a time with atomic
# renames. A sequence of renames is not itself atomic, so if the process is
# killed between files, reopening any participating store replays the durable
# decision and brings every file to the same result. The given block is never
# re-run during recovery; if the coordination record is missing or corrupt,
# recovery raises PStore::Error instead of guessing.
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
  VERSION = "0.3.0"

  RDWR_ACCESS = {mode: IO::RDWR | IO::CREAT | IO::BINARY, encoding: Encoding::ASCII_8BIT}.freeze
  RD_ACCESS = {mode: IO::RDONLY | IO::BINARY, encoding: Encoding::ASCII_8BIT}.freeze
  WR_ACCESS = {mode: IO::WRONLY | IO::CREAT | IO::TRUNC | IO::BINARY, encoding: Encoding::ASCII_8BIT}.freeze
  private_constant :RDWR_ACCESS, :RD_ACCESS, :WR_ACCESS
  # :startdoc:

  # The error type thrown by all PStore methods.
  class Error < StandardError
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

  # Acquire or release the store's in-process lock on behalf of a
  # PStore::TransactionCoordinator.
  def coordinator_lock
    @lock.lock
  end
  def coordinator_unlock
    @lock.unlock if @lock.owned?
  end
  private :coordinator_lock, :coordinator_unlock

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
      # Finish any multi-store transaction whose participant files were left
      # behind by a crashed process before opening the current data file.
      PStore::TransactionCoordinator.recover_pending(@filename)
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
end

# PStore::TransactionCoordinator updates several PStore files as one
# recoverable, two-phase transaction.
#
# A single file rename is atomic on most filesystems, but a sequence of
# renames is not: a process can die after publishing some stores but before
# the rest.  This coordinator therefore keeps an explicit journal beside the
# participating files:
#
# 1. The user block runs exactly once and may read or modify every store.
# 2. (prepare) Each new file image is written and flushed to
#    +<path>.p2pc.<txid>.image+, then a durable +<path>.p2pc.<txid>.ready+
#    marker records that the image is complete.
# 3. (decision) The journal at +<first-store-dir>/.pstore-p2pc.<digest>.journal+
#    is atomically switched from its +prepared+ record to the final
#    +committed+ or +aborted+ decision.  The decision is durable before any
#    store file is replaced.
# 4. (publish) Committed images are renamed onto their store files one at a
#    time, in stable path order.  Each individual rename is atomic; the
#    sequence as a whole is not, but reopening any participating file replays
#    the durable decision until all files converge.
#
# If a process dies during any of these phases, the next
# PStore#transaction (or PStore::TransactionCoordinator.recover_pending)
# finishes the transaction: +committed+ rolls forward, every other recorded
# state rolls back without touching the original files.
#
# A ready marker whose journal is missing or corrupted cannot be resolved
# safely, so recovery raises PStore::Error instead of guessing.
class PStore::TransactionCoordinator
  PROTOCOL_VERSION = 1
  private_constant :PROTOCOL_VERSION

  READY_PATTERN = /\.p2pc\.([^.]+)\.ready\z/
  IMAGE_PATTERN = /\.p2pc\.([^.]+)\.image\z/
  private_constant :READY_PATTERN, :IMAGE_PATTERN

  # Runs +block+ as a single transaction over the given stores.
  # Stores are always locked and published in stable (sorted path) order.
  def self.transaction(*stores)
    new(*stores).transaction { yield(*stores) }
  end

  # Creates a coordinator for the given PStore objects.
  def initialize(*stores)
    @stores = stores
    unless @stores.length >= 2 && @stores.all? { |store| store.is_a?(PStore) }
      raise PStore::Error, "at least two PStore instances are required"
    end
    @ordered = @stores.uniq { |store| store.path }.sort_by(&:path)
    if @ordered.length != @stores.length
      raise PStore::Error, "the same PStore cannot participate twice"
    end
    @paths = @ordered.map(&:path)
    @digest = Digest::SHA256.digest(@paths.join("\0")).unpack1("H*")
    @journal_path = File.join(File.dirname(@paths.first),
                              ".pstore-p2pc.#{@digest}.journal")
    @journal_lock_path = "#{@journal_path}.lock"
  end

  # Finishes every unfinished multi-store transaction that touches the given
  # store file, then removes its coordination files. Raises PStore::Error if
  # a participant marker exists but its journal is missing or unreadable.
  def self.recover_pending(path)
    path = File.path(path)
    scan = scan_coordination([path])
    return if scan[:journal_paths].empty?
    run_recovery(scan, prelocked_data: {})
  end

  # Recovery entry for a live coordinator that already holds its own data file
  # locks (in sorted path order).
  def self.recover_locked(ordered_stores, locked_files)
    paths = ordered_stores.map(&:path)
    scan = scan_coordination(paths)
    return if scan[:journal_paths].empty?
    locks_by_path = {}
    ordered_stores.each { |store| locks_by_path[store.path] = locked_files[store] }
    run_recovery(scan, prelocked_data: locks_by_path)
  end
  private_class_method :recover_locked

  # Scans the given participant files' directories for coordination state,
  # then follows journal records to participant directories (participants may
  # live in different directories).
  def self.scan_coordination(seed_paths)
    scanned = {}
    discovered = Hash.new { |hash, key| hash[key] = [] }
    journal_paths = []

    scan = lambda do |participant_path|
      directory = File.dirname(participant_path)
      base = File.basename(participant_path)
      return if scanned.key?(directory)
      scanned[directory] = true

      referenced_txids = []
      orphan_images = []
      (Dir.children(directory) rescue []).each do |name|
        full_path = File.join(directory, name)
        if name.start_with?(".pstore-p2pc.") && name.end_with?(".journal")
          journal_paths << full_path unless journal_paths.include?(full_path)
        elsif (match = READY_PATTERN.match(name))
          record = read_record(full_path)
          journal_path = valid_marker(record, full_path)
          discovered[journal_path] << [full_path, record, match[1]]
          referenced_txids << match[1]
          unless journal_paths.include?(journal_path)
            journal_paths << journal_path
          end
        elsif (match = IMAGE_PATTERN.match(name)) && name.start_with?("#{base}.p2pc.")
          orphan_images << [full_path, match[1]]
        end
      end

      # An image left by a crash during prepare is garbage only while no ready
      # marker references the same transaction.
      orphan_images.each do |image_path, txid|
        File.unlink(image_path) unless referenced_txids.include?(txid)
      rescue SystemCallError
        nil
      end
    end

    seed_paths.each { |participant_path| scan.call(participant_path) }

    # Follow participant lists from every journal so cross-directory markers
    # are recovered too. A journal with zero markers is still recovered.
    participant_paths = seed_paths.dup
    visited_journals = {}
    until (journal_path = journal_paths.reject { |path| visited_journals[path] }.first).nil?
      visited_journals[journal_path] = true
      journal = read_record(journal_path)
      next unless journal.is_a?(Hash) && journal[:participants].is_a?(Array)
      journal[:participants].each do |participant_path|
        next unless participant_path.is_a?(String)
        next if participant_paths.include?(participant_path)
        participant_paths << participant_path
        scan.call(participant_path)
      end
    end

    {journal_paths: journal_paths.sort, discovered: discovered,
     participant_paths: participant_paths.uniq.sort}
  end
  private_class_method :scan_coordination

  # Locks and finishes crashed transactions. Every file lock is acquired in
  # one global order -- journal lock files and participant data files sorted
  # together by path -- so coordinators and recovery can never deadlock. The
  # coordinator passes its own already-open data files as +prelocked_data+.
  def self.run_recovery(initial_scan, prelocked_data:)
    journal_paths = initial_scan[:journal_paths]
    journal_lock_paths = journal_paths.map { |path| "#{path}.lock" }.sort
    data_paths = initial_scan[:participant_paths].sort

    ordered_keys = (journal_lock_paths.map { |path| [:journal, path] } +
                    data_paths.map { |path| [:data, path] }).sort_by { |_kind, path| path }

    opened = {}
    data_locks = prelocked_data.dup
    begin
      ordered_keys.each do |kind, path|
        if kind == :journal
          file = File.new(path, **PStore.const_get(:RDWR_ACCESS))
          file.flock(File::LOCK_EX)
          opened[path] = file
        elsif !data_locks.key?(path)
          file = File.new(path, **PStore.const_get(:RDWR_ACCESS))
          file.flock(File::LOCK_EX)
          data_locks[path] = file
          opened[path] = file
        end
      end

      # With all journal locks held, a journal that disappears means a live
      # coordinator finished; then its markers must be gone too. Re-read and
      # resolve every journal that still has either a file or a marker.
      stable = scan_coordination(data_paths)
      candidate = journal_paths | stable[:journal_paths]
      candidate.sort.each do |journal_path|
        markers = stable[:discovered].fetch(journal_path, [])
        next if markers.empty? && !File.file?(journal_path)
        recover_one(journal_path, markers, data_locks)
      end
    ensure
      opened.each_value { |file| file.close rescue nil }
      journal_lock_paths.each { |path| File.unlink(path) rescue nil }
    end
  end
  private_class_method :run_recovery

  def transaction
    raise PStore::Error, "no block given" unless block_given?

    begin
      @ordered.each { |store| store.send(:coordinator_lock) }
      @files = {}
      # Acquire every file lock in the same global path order used by
      # recovery: participant data files and the journal lock sorted together.
      acquire_keys = (@paths.map { |path| [:data, path] } +
                      [[:journal, @journal_lock_path]]).sort_by { |_kind, path| path }
      acquire_keys.each do |kind, path|
        if kind == :journal
          @journal_lock = open_lock_file(path)
        else
          store = @ordered.find { |candidate| candidate.path == path }
          file = store.send(:open_and_lock_file, path, false)
          @files[store] = file
        end
      end
      # No live coordinator holds this journal lock, so remnants on disk must
      # belong to a crashed process; resolve them before the user block runs.
      self.class.send(:recover_locked, @ordered, @files)

      @ordered.each do |store|
        file = @files[store]
        table, = store.send(:load_data, file, false)
        store.instance_variable_set(:@table, table)
        store.instance_variable_set(:@rdonly, false)
        store.instance_variable_set(:@abort, false)
      end

      result = run_block { yield(*@stores) }

      decision = @ordered.any? { |store| store.instance_variable_get(:@abort) } ? :aborted : :committed
      run_two_phase(decision)
      result
    ensure
      @files.each_value { |file| file.close rescue nil } if @files
      release_journal_lock
      @ordered.reverse_each { |store| store.send(:coordinator_unlock) } if @ordered
    end
  end

  private

  # Nested catch tags: store.commit/abort throw the store itself and must only
  # leave this coordinated transaction.
  def run_block
    @ordered.reverse.reduce(-> { yield }) do |inner, store|
      -> { catch(store) { inner.call } }
    end.call
  end

  def run_two_phase(decision)
    crash_hook("before_prepare")
    @txid = "#{Time.now.to_i}-#{Process.pid}-#{rand(0x100000000).to_s(36)}"

    # The prepare record exists before any participant marker does, so a marker
    # without its journal can never be an unresolved-but-valid transaction.
    journal = {version: PROTOCOL_VERSION, txid: @txid,
               participants: @paths, state: "prepared"}
    write_durable(@journal_path, Marshal.dump(journal))
    crash_hook("after_journal_prepared")

    images = {}
    @ordered.each do |store|
      image_path = "#{store.path}.p2pc.#{@txid}.image"
      data = store.send(:dump, store.instance_variable_get(:@table))
      write_durable(image_path, data)
      images[store] = image_path
    end

    @ordered.each do |store|
      marker_path = "#{store.path}.p2pc.#{@txid}.ready"
      marker = {version: PROTOCOL_VERSION, txid: @txid,
                journal: @journal_path, path: store.path, image: images[store]}
      write_durable(marker_path, Marshal.dump(marker))
    end
    crash_hook("after_prepare")

    journal[:state] = decision.to_s
    write_durable(@journal_path, Marshal.dump(journal))
    crash_hook("after_decision")

    if decision == :committed
      @ordered.each_with_index do |store, index|
        publish(store, images[store])
        crash_hook("after_publish_#{index}")
      end
    end
    cleanup(@txid)
    crash_hook("after_cleanup")
  end

  def publish(store, image_path)
    File.chmod(File.stat(store.path).mode, image_path) if File.file?(store.path)
    File.rename(image_path, store.path)
    fsync_dir(File.dirname(store.path))
  end

  def cleanup(txid)
    @ordered.each do |store|
      marker = "#{store.path}.p2pc.#{txid}.ready"
      File.unlink(marker) if File.file?(marker)
      image = "#{store.path}.p2pc.#{txid}.image"
      File.unlink(image) if File.file?(image)
    end
    File.unlink(@journal_path) if File.file?(@journal_path)
    fsync_dir(File.dirname(@journal_path))
  end

  def release_journal_lock
    return unless @journal_lock
    @journal_lock.close rescue nil
    @journal_lock = nil
    File.unlink(@journal_lock_path) rescue nil
  end

  def crash_hook(name)
    trigger = ENV["PSTORE_P2PC_CRASH"]
    Process.kill(:KILL, Process.pid) if trigger == name
  end

  def write_durable(path, data)
    temp = "#{path}.tmp.#{Process.pid}.#{rand(1_000_000)}"
    File.open(temp, File::WRONLY | File::CREAT | File::EXCL | File::BINARY,
              0o600, encoding: Encoding::ASCII_8BIT) do |file|
      file.write(data)
      file.flush
      file.fsync rescue nil
    end
    File.rename(temp, path)
    fsync_dir(File.dirname(path))
  end

  def fsync_dir(path)
    Dir.open(path) { |dir| dir.fsync rescue nil }
  end

  def open_lock_file(path)
    file = File.new(path, **PStore.const_get(:RDWR_ACCESS))
    file.flock(File::LOCK_EX)
    file
  end

  def self.read_record(path)
    Marshal.load(File.binread(path))
  rescue StandardError, TypeError
    nil
  end
  private_class_method :read_record

  def self.valid_marker(record, marker_path)
    journal_path = record.is_a?(Hash) ? record[:journal] : nil
    valid = record.is_a?(Hash) &&
            record[:version] == PROTOCOL_VERSION &&
            journal_path.is_a?(String) &&
            record[:txid].is_a?(String) &&
            record[:path].is_a?(String) &&
            record[:image].is_a?(String) &&
            READY_PATTERN.match?(File.basename(marker_path)) &&
            File.basename(marker_path) ==
              "#{File.basename(record[:path])}.p2pc.#{record[:txid]}.ready"
    unless valid
      raise PStore::Error, "corrupted PStore transaction marker: #{marker_path}"
    end
    journal_path
  end
  private_class_method :valid_marker

  def self.recover_one(journal_path, markers, data_locks)
    return unless File.file?(journal_path) || !markers.empty?

    journal = File.file?(journal_path) ? read_record(journal_path) : nil
    # Markers exist only after the prepare journal is durable, so markers
    # without a readable journal cannot be resolved and must fail loudly.
    unless journal.is_a?(Hash) && journal[:participants].is_a?(Array) &&
           journal[:participants].all? { |path| path.is_a?(String) } &&
           journal[:txid].is_a?(String) && journal[:state].is_a?(String) &&
           journal[:version] == PROTOCOL_VERSION
      raise PStore::Error, "corrupted or missing PStore transaction journal: #{journal_path}"
    end
    txid = journal[:txid]
    paths = journal[:participants].sort
    state = journal[:state]
    unless %w[committed prepared aborted].include?(state)
      raise PStore::Error, "unknown PStore transaction state #{state.inspect}: #{journal_path}"
    end

    by_path = {}
    markers.each do |marker_path, record, marker_txid|
      unless marker_txid == txid && record[:txid] == txid &&
             record[:journal] == journal_path && paths.include?(record[:path]) &&
             File.basename(marker_path) == "#{File.basename(record[:path])}.p2pc.#{txid}.ready"
        raise PStore::Error, "corrupted PStore transaction marker: #{marker_path}"
      end
      by_path[record[:path]] = [marker_path, record[:image]]
    end

    if state == "committed"
      # Each participant is either still unpublished (image present) or already
      # published (image consumed by the atomic rename, data file present).
      unresolved = paths.reject do |path|
        marker_path, image = by_path[path]
        File.file?(path) || (marker_path && File.file?(image))
      end
      unless unresolved.empty?
        raise PStore::Error, "incomplete committed PStore transaction: #{journal_path}"
      end
    end

    paths.each do |path|
      marker_path, image = by_path[path]
      if state == "committed" && marker_path && image && File.file?(image)
        File.rename(image, path)
      end
      File.unlink(image) if image && File.file?(image)
      File.unlink(marker_path) if marker_path && File.file?(marker_path)
      fsync_dir(File.dirname(path))
    end
    File.unlink(journal_path) if File.file?(journal_path)
    fsync_dir(File.dirname(journal_path))
  rescue PStore::Error
    raise
  rescue SystemCallError => error
    raise PStore::Error, "failed to recover PStore transaction #{journal_path}: #{error.message}"
  end
  private_class_method :recover_one

  def self.fsync_dir(path)
    Dir.open(path) { |dir| dir.fsync rescue nil }
  end
  private_class_method :fsync_dir
end
