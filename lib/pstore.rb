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
# == Journal Mode
#
# By default every successful transaction rewrites the entire store file,
# even when only a single small value changed.
# Passing +journal: true+ to PStore.new switches the store to journal mode:
#
#   store = PStore.new('big.store', journal: true)
#
# In journal mode the store consists of two files next to each other:
#
# - The store file itself holds a compacted _snapshot_ of the whole table.
# - A sibling file with a +.journal+ extension holds append-only
#   _commit records_, one per transaction that changed something.
#
# Each commit record is self-describing and carries a SHA-256 digest,
# so its integrity can be verified independently.
# Opening a store restores the table from the snapshot
# and then replays the valid commit records on top of it.
# A transaction that changes nothing writes nothing.
#
# In-place modifications of nested objects retrieved with #[] or #fetch
# (such as <tt>store[:items] << 1</tt>) are detected at commit time
# and included in the record; overriding #[]= is therefore not enough
# to track changes, and journal mode does not rely on it.
#
# Once the journal grows to the configured #compaction_threshold
# (1 MiB by default), the next changing transaction atomically rewrites
# a fresh snapshot and rotates the journal back to empty.
# +compaction_threshold:+ may be set to +nil+ to disable size based
# compaction.
#
# All journal operations are guarded by an exclusive cross-process lock
# held in a third, stable file (+.lock+); snapshot compaction,
# journal rotation and ordinary appends are therefore never performed
# concurrently by different processes.
#
# On startup, a trailing commit record that was not fully written
# (because the process crashed mid-write) is treated as a torn tail:
# it is ignored by read-only transactions and removed by read-write
# transactions. Corruption in the middle of the journal, with further
# valid records following it, raises PStore::Error instead,
# because silently dropping committed transactions would lose data.
#
# Stores written by ordinary (non-journal) \\PStore keep working:
# they can be opened and read in journal mode, and the first changing
# transaction migrates them to the snapshot format. Journal mode is
# opt in, so existing plain files are never touched unless a journal
# mode instance writes to them.
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
  # If keyword argument +journal+ is given as +true+, the store uses
  # append-only commit records instead of rewriting the whole file on
  # every transaction; see {Journal Mode}[rdoc-ref:PStore@Journal+Mode].
  #
  # Keyword argument +compaction_threshold+ sets the journal size in bytes
  # at which the next changing transaction compacts a journal store;
  # the default is 1 MiB and +nil+ disables size based compaction.
  # It has no effect unless +journal+ is +true+.
  #
  def initialize(file, thread_safe = false, journal: false, compaction_threshold: 1024 * 1024)
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
    @journal = journal
    if compaction_threshold &&
        (!(compaction_threshold.is_a?(Integer) && compaction_threshold >= 0))
      raise PStore::Error, "compaction_threshold must be a non-negative Integer or nil"
    end
    @compaction_threshold = compaction_threshold
    @lock = Thread::Mutex.new
  end

  # Returns +true+ if the store uses append-only journal mode.
  #
  # See {Journal Mode}[rdoc-ref:PStore@Journal+Mode].
  #
  def journal?
    @journal
  end

  # Returns the journal size, in bytes, at which the next changing
  # transaction compacts the store and rotates the journal.
  #
  # Returns +nil+ if size based compaction is disabled.
  # Only meaningful when #journal? is +true+.
  #
  attr_reader :compaction_threshold

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
    journal_track_read(key) if @journal_tracking
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
        journal_track_read(key) if @journal_tracking
        return default
      end
    end
    journal_track_read(key) if @journal_tracking
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
    journal_track_write(key) if @journal_tracking
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
    result = @table.delete(key)
    journal_track_delete(key) if @journal_tracking
    result
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
    return journal_transaction(read_only) { |store| yield(store) } if @journal
    classic_transaction(read_only) { |store| yield(store) }
  end

  private

  def classic_transaction(read_only)
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
      @journal_tracking = false
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

  #
  # Journal mode implementation.
  #
  # Three files are involved:
  #
  # - @filename holds a single checksummed snapshot frame.
  # - @filename + ".journal" holds appended checksummed commit frames.
  # - @filename + ".lock" is a stable flock target shared by every
  #   process, so that snapshot compaction and journal rotation cannot
  #   interleave with appends from another process. Unlike the snapshot
  #   file, it is never renamed, so flock stays attached for the whole
  #   transaction.
  #
  def journal_transaction(read_only)
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
      @journal_snapshot_present = false
      @journal_legacy = false
      @journal_replayed_size = 0
      @journal_tracking = false
      @journal_base_keys = nil
      @journal_base_values = nil
      @journal_written = nil
      @journal_deleted = nil

      # Read-only access never creates files; a completely missing
      # store is simply empty.
      if read_only && !File.exist?(@filename) && !File.exist?(journal_path)
        @table = {}
        catch(self) do
          value = yield(self)
        end
        return value
      end

      lock_file = journal_open_lock(read_only)
      begin
        journal_cleanup_temp_files unless read_only
        @table = journal_load(read_only)
        unless read_only
          journal_init_tracking
          @journal_tracking = true
        end

        catch(self) do
          value = yield(self)
        end

        journal_commit unless @abort || read_only
      ensure
        lock_file.close
      end
    ensure
      @lock.unlock
    end
    value
  end

  def journal_path
    @filename + JOURNAL_FILE_SUFFIX
  end

  def journal_lock_path
    @filename + JOURNAL_LOCK_SUFFIX
  end

  # Open the stable lock file and acquire the cross-process lock.
  # Read-only transactions take a shared lock, read-write transactions
  # an exclusive one.
  def journal_open_lock(read_only)
    file = File.new(journal_lock_path, **RDWR_ACCESS)
    file.flock(read_only ? File::LOCK_SH : File::LOCK_EX)
    file
  end

  # Remove temporary files left by a process that was killed while
  # compacting or rotating the journal. This runs under the exclusive
  # lock, so any concurrent writer has either finished its rename or is
  # waiting for this transaction to finish.
  def journal_cleanup_temp_files
    dir = File.dirname(@filename)
    base = File.basename(@filename)
    JOURNAL_TEMP_SUFFIXES.each do |suffix|
      pattern = /\A#{Regexp.escape(base)}#{Regexp.escape(suffix)}\d+\.\d+\z/
      Dir.children(dir).each do |name|
        File.unlink(File.join(dir, name)) rescue nil if pattern.match?(name)
      end
    end
  end

  # Restore the in-memory table from the snapshot followed by the
  # journal. For read-write transactions the journal is truncated back
  # to the last valid record (a torn tail is discarded) before the
  # transaction starts.
  def journal_load(read_only)
    table = {}
    snapshot_present = false

    legacy_data = nil
    if File.exist?(@filename)
      data = File.binread(@filename)
      if !data.empty?
        if data.start_with?(JOURNAL_MAGIC)
          result = journal_try_read_frame(data, 0, data.bytesize)
          raise Error, "PStore snapshot seems to be corrupted." unless result
          _snapshot_end, payload = result
          snapshot = load(payload)
          raise Error, "PStore snapshot seems to be corrupted." unless snapshot.is_a?(Hash)
          table = snapshot
          snapshot_present = true
        else
          # A plain Marshal file written by a non-journal PStore.
          begin
            legacy = load(data)
          rescue StandardError
          end
          unless legacy.is_a?(Hash)
            raise Error, "PStore file seems to be corrupted."
          end
          table = legacy
          legacy_data = data
        end
      end
    end
    @journal_snapshot_present = snapshot_present
    @journal_legacy = !legacy_data.nil?

    journal_size = 0
    if File.exist?(journal_path)
      data = File.binread(journal_path)
      journal_size = data.bytesize
      if !data.empty?
        if legacy_data
          # A journal next to a plain Marshal file cannot belong to
          # this store without a snapshot having existed.
          raise Error, "PStore journal without a snapshot seems to be corrupted."
        end
        unless snapshot_present
          raise Error, "PStore journal without a snapshot seems to be corrupted."
        end
        valid_size, torn = journal_replay(data, table)
        if torn
          if read_only
            # Ignore an incomplete trailing record; the data up to it
            # remains readable.
          else
            journal_truncate(valid_size)
          end
          journal_size = valid_size
        end
      end
    end
    @journal_replayed_size = journal_size
    table
  end

  # Validate and replay every commit frame in +data+ onto +table+.
  # Returns [size_of_valid_prefix, torn_tail_flag].
  # Raises PStore::Error on mid-journal corruption.
  def journal_replay(data, table)
    offset = 0
    total = data.bytesize
    while offset < total
      frame_offset = offset
      result = journal_try_read_frame(data, offset, total)
      unless result
        # The record at frame_offset cannot be verified. If another
        # intact, verified frame follows it, committed data would be
        # lost by truncating here: that is mid-journal corruption and
        # must be surfaced. Otherwise the garbage sits at the end of
        # the file, exactly where a crash leaves a half-written record.
        rescue_offset = journal_find_next_frame(data, frame_offset + 1, total)
        if rescue_offset
          raise Error, "PStore journal seems to be corrupted at byte #{frame_offset}"
        end
        return [frame_offset, true]
      end
      next_offset, payload = result
      changes = load(payload)
      journal_apply_changes(table, changes)
      offset = next_offset
    end
    [total, false]
  end

  # Try to read and verify one framed record starting at +offset+.
  # Returns [end_offset, payload] on success, or nil if the record is
  # truncated or fails verification.
  def journal_try_read_frame(data, offset, end_of_data)
    available = end_of_data - offset
    return nil if available < JOURNAL_HEADER_SIZE
    header = data.byteslice(offset, JOURNAL_HEADER_SIZE)
    return nil unless header.byteslice(0, JOURNAL_MAGIC.bytesize) == JOURNAL_MAGIC
    return nil unless header.getbyte(JOURNAL_MAGIC.bytesize) == JOURNAL_DIGEST_SHA256
    payload_size = header.byteslice(JOURNAL_MAGIC.bytesize + 1, 8).unpack1("Q>")
    frame_size = JOURNAL_HEADER_SIZE + payload_size + JOURNAL_DIGEST_SIZE
    return nil if available < frame_size
    payload = data.byteslice(offset + JOURNAL_HEADER_SIZE, payload_size)
    digest = data.byteslice(offset + JOURNAL_HEADER_SIZE + payload_size,
                           JOURNAL_DIGEST_SIZE)
    signed = data.byteslice(offset, JOURNAL_HEADER_SIZE + payload_size)
    return nil unless Digest::SHA256.digest(signed) == digest
    [offset + frame_size, payload]
  end

  # Search +data+ from +from_offset+ for the start of an intact frame.
  # Verifying the candidate (and not just matching magic) prevents a
  # payload that happens to contain the magic from being mistaken for
  # a real record boundary.
  def journal_find_next_frame(data, from_offset, total)
    search = from_offset
    while (candidate = data.index(JOURNAL_MAGIC, search))
      return candidate if journal_try_read_frame(data, candidate, total)
      search = candidate + 1
    end
    nil
  end

  # Apply one commit record to +table+.
  # A record is a Hash of the form {"u" => {key => value, ...},
  # "d" => [key, ...]}. Updates are applied before deletes.
  def journal_apply_changes(table, changes)
    unless changes.is_a?(Hash)
      raise Error, "PStore commit record seems to be corrupted."
    end
    updates = changes["u"]
    deletes = changes["d"]
    if updates
      raise Error, "PStore commit record seems to be corrupted." unless updates.is_a?(Hash)
      table.update(updates)
    end
    if deletes
      raise Error, "PStore commit record seems to be corrupted." unless deletes.is_a?(Array)
      deletes.each { |key| table.delete(key) }
    end
  end

  def journal_build_frame(payload)
    header = JOURNAL_MAGIC.dup
    header << JOURNAL_DIGEST_SHA256.chr.b
    header << [payload.bytesize].pack("Q>")
    digest = Digest::SHA256.digest(header + payload)
    header + payload + digest
  end

  #
  # Change tracking.
  #
  # []= and delete are recorded directly. In-place mutations of nested
  # objects (store[:a] << 1) never go through []=, so every key read
  # through [] or fetch also has its value marshalled lazily; at
  # commit time the current value is marshalled again, reloaded and
  # compared semantically. Comparing the marshalled bytes themselves
  # would flag unchanged objects whenever Marshal emits a fresh object
  # suffix. Only keys whose persisted value really changed enter the
  # commit record.
  #
  def journal_init_tracking
    @journal_base_keys = @table.keys
    # Marshalled form of every key present when the transaction began.
    # Keys obtained through keys()/key?() are not tracked by read, so
    # this is what catches a key object mutated in place (the mutated
    # object is simultaneously a table key and a member of
    # @journal_base_keys).
    @journal_base_key_dumps = {}
    @table.each_key do |key|
      @journal_base_key_dumps[dump(key)] = true
    end
    @journal_base_values = {}
    @journal_written = {}
    @journal_deleted = {}
  end

  def journal_track_read(key)
    return unless @journal_tracking && !@journal_base_values.key?(key)
    @journal_base_values[key] = @table.key?(key) ? dump(@table[key]) : JOURNAL_MISSING
  end

  def journal_track_write(key)
    # Snapshot whatever was stored before this assignment, unless it is
    # already known (via an earlier read or assignment). This lets a
    # write of an equal value be recognised as a no-op even when its
    # raw marshal bytes would differ.
    unless @journal_base_values.key?(key)
      @journal_base_values[key] = @table.key?(key) ? dump(@table[key]) : JOURNAL_MISSING
    end
    @journal_written[key] = true
    @journal_deleted.delete(key)
  end

  def journal_track_delete(key)
    if @journal_base_keys.include?(key)
      @journal_deleted[key] = true
    end
    @journal_written.delete(key)
    @journal_base_values.delete(key)
  end

  # Build the commit record and decide how to persist it.
  def journal_commit
    updates, deletes, key_anomaly = journal_collect_changes

    changed = !(updates.empty? && deletes.empty?)

    # A read-write transaction that changed nothing leaves every file
    # alone; in particular a plain-format file opened from journal mode
    # stays a plain-format file until the first real change.
    return unless changed || key_anomaly

    # Full compaction is required when no proper snapshot exists yet,
    # when the on-disk format predates journal mode, when the key set
    # changed through a path we did not track, or when the journal has
    # reached its size threshold.
    needs_compaction =
      !@journal_snapshot_present ||
      @journal_legacy ||
      key_anomaly ||
      (@compaction_threshold &&
       @journal_replayed_size >= @compaction_threshold)

    if needs_compaction
      journal_compact(updates, deletes)
    else
      journal_append_commit(updates, deletes)
    end
  end

  # Returns [updates_hash, deletes_array, key_anomaly].
  def journal_collect_changes
    updates = {}
    deletes = []

    @journal_deleted.each_key do |key|
      deletes << key unless @table.key?(key)
    end

    candidates = {}
    @journal_written.each_key { |key| candidates[key] = true }
    @journal_base_values.each_key { |key| candidates[key] = true }
    candidates.each_key do |key|
      next unless @table.key?(key)
      base = @journal_base_values[key]
      if base.nil?
        updates[key] = @table[key]
      elsif base.equal?(JOURNAL_MISSING)
        # The key did not exist when first read, it does now.
        updates[key] = @table[key]
      elsif load(dump(@table[key])) != load(base)
        updates[key] = @table[key]
      end
    end

    [updates, deletes, journal_key_set_anomaly?]
  end

  # Detect keys that appeared, disappeared or changed identity without
  # going through []= or delete (for example a key object mutated in
  # place via keys()). Forces a full snapshot so nothing is lost.
  def journal_key_set_anomaly?
    predicted = @journal_base_key_dumps.dup
    @journal_deleted.each_key { |key| predicted.delete(dump(key)) }
    @journal_written.each_key do |key|
      # A written key may already be present (replacement) or new. Use
      # its current representation for new keys; replacements of an
      # existing base key keep the base representation unless the key
      # object itself mutated, which the base/final comparison below
      # still catches via identity.
      predicted[dump(key)] = true
    end
    final_dumps = {}
    @table.each_key { |key| final_dumps[dump(key)] = true }
    final_dumps != predicted
  end

  # Append one verified commit record. The header, payload and digest
  # are written in distinct stages so that a crash at any stage leaves
  # at most an unverifiable torn tail, never a half-valid record.
  def journal_append_commit(updates, deletes)
    payload = dump("u" => updates, "d" => deletes)
    frame = journal_build_frame(payload)
    File.open(journal_path, File::RDWR | File::CREAT | File::APPEND | IO::BINARY,
              encoding: Encoding::ASCII_8BIT) do |journal|
      header = frame.byteslice(0, JOURNAL_HEADER_SIZE)
      body = frame.byteslice(JOURNAL_HEADER_SIZE,
                             frame.bytesize - JOURNAL_HEADER_SIZE -
                               JOURNAL_DIGEST_SIZE)
      digest = frame.byteslice(frame.bytesize - JOURNAL_DIGEST_SIZE,
                               JOURNAL_DIGEST_SIZE)
      journal.write(header)
      crash_point("append_header")
      journal.write(body)
      crash_point("append_payload")
      journal.flush
      crash_point("append_fsync")
      journal.write(digest)
      journal.flush
      crash_point("append_digest")
      journal_fsync(journal)
    end
  end

  # Rewrite a fresh snapshot of the whole table and rotate the journal
  # back to empty. All steps are idempotent: a crash at any point is
  # repaired by replay on the next open.
  def journal_compact(_updates, _deletes)
    snapshot_payload = dump(journal_canonical_table)
    frame = journal_build_frame(snapshot_payload)

    existing_file = File.exist?(@filename)
    mode = existing_file ? File.stat(@filename).mode : (0o666 & ~File.umask)
    temp_snapshot = "#{@filename}.snap.#{Process.pid}.#{rand(1000000)}"
    temp_file = File.new(temp_snapshot, **WR_ACCESS, perm: 0o600)
    begin
      temp_file.flock(File::LOCK_EX)
      temp_file.write(frame)
      crash_point("snapshot_write")
      temp_file.flush
      crash_point("snapshot_fsync")
      journal_fsync(temp_file)
      temp_file.chmod(mode)
      File.rename(temp_snapshot, @filename)
      temp_snapshot = nil
      crash_point("snapshot_rename")
      journal_fsync_dir(File.dirname(@filename))
      @journal_snapshot_present = true
      @journal_legacy = false
    ensure
      temp_file.close rescue nil
      File.unlink(temp_snapshot) rescue nil if temp_snapshot
    end

    journal_reset
  end

  # Return a deep copy of the transaction table whose keys and values
  # are freshly loaded objects. A key mutated in place while it was a
  # hash key keeps a stale hash code in the old table; inserting the
  # reloaded copy into a new Hash gives it a correct hash code and a
  # clean marshal representation.
  def journal_canonical_table
    load(dump(@table))
  end

  # Replace the journal with an empty file. Renaming an empty temp file
  # over the journal is atomic; if the process dies just before it, the
  # old journal simply gets replayed over the new snapshot on restart.
  def journal_reset
    temp_journal = "#{@filename}.jrnl.#{Process.pid}.#{rand(1000000)}"
    existing = File.exist?(journal_path)
    mode = existing ? File.stat(journal_path).mode : (0o666 & ~File.umask)
    temp_file = File.new(temp_journal, **WR_ACCESS, perm: 0o600)
    begin
      temp_file.flock(File::LOCK_EX)
      temp_file.chmod(mode)
      temp_file.flush
      journal_fsync(temp_file)
      File.rename(temp_journal, journal_path)
      temp_journal = nil
      crash_point("journal_rotate")
      journal_fsync_dir(File.dirname(journal_path))
      @journal_snapshot_present = true
      @journal_legacy = false
      @journal_replayed_size = 0
    ensure
      temp_file.close rescue nil
      File.unlink(temp_journal) rescue nil if temp_journal
    end
  end

  def journal_truncate(size)
    File.open(journal_path, File::RDWR | IO::BINARY,
              encoding: Encoding::ASCII_8BIT) do |journal|
      journal.flock(File::LOCK_EX)
      journal.truncate(size)
      journal_fsync(journal)
    end
  end

  def journal_fsync(io)
    io.fsync
  rescue NotImplementedError, Errno::EINVAL
    nil
  end

  def journal_fsync_dir(dir)
    directory = File.open(dir, IO::RDONLY | IO::BINARY)
    begin
      directory.fsync
    rescue NotImplementedError, Errno::EINVAL, Errno::EACCES
      nil
    ensure
      directory.close
    end
  end

  # Test hook: when ENV['PSTORE_CRASH_AT'] names this point the process
  # terminates with SIGKILL immediately, leaving any buffered or just
  # flushed data exactly where a real crash would.
  def crash_point(name)
    if ENV["PSTORE_CRASH_AT"] == name
      Process.kill(:KILL, Process.pid)
      sleep
    end
  end

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

  # Journal mode on-disk format.
  #
  # Both snapshot files and journal commit records use the same framed
  # layout:
  #
  #   magic (8 bytes) | digest id (1 byte) | payload length (8 bytes,
  #   big endian) | payload | digest (32 bytes for SHA-256)
  #
  # The digest is computed over the header and the payload, so a frame
  # can be verified without any external state. The digest bytes also
  # act as the commit marker: a record interrupted before they are all
  # written can be told apart from a fully committed one.
  JOURNAL_MAGIC = "PSTJFRM1".b
  JOURNAL_DIGEST_SHA256 = 2
  JOURNAL_DIGEST_SIZE = 32
  JOURNAL_HEADER_SIZE = JOURNAL_MAGIC.bytesize + 1 + 8
  JOURNAL_LOCK_SUFFIX = ".lock"
  JOURNAL_FILE_SUFFIX = ".journal"
  JOURNAL_TEMP_SUFFIXES = [".snap.", ".jrnl."]
  private_constant :JOURNAL_MAGIC, :JOURNAL_DIGEST_SHA256, :JOURNAL_DIGEST_SIZE,
                   :JOURNAL_HEADER_SIZE, :JOURNAL_LOCK_SUFFIX, :JOURNAL_FILE_SUFFIX,
                   :JOURNAL_TEMP_SUFFIXES

  # Distinguishes a key that was missing when first read in a
  # transaction from one whose value is nil.
  JOURNAL_MISSING = Object.new
  JOURNAL_MISSING.freeze
  private_constant :JOURNAL_MISSING

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
