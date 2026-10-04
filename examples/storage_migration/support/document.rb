# frozen_string_literal: true

require "shrine"
require "shrine/storage/file_system"

Shrine.plugin :model
Shrine.logger = Logger.new(nil)

# Uploader used by the example and the tests. Storages are assigned by the
# caller (two temporary directories simulate the source and target).
class MyUploader < Shrine
end

# Simulates the database table backing Document records. Kept separate from
# Document instances so a test can "reload" a record and simulate another
# process (e.g. a user) replacing the attachment mid-migration.
class DocumentStore
  def initialize
    @rows = {}
  end

  def create(id, image_data = nil)
    @rows[id] = image_data
  end

  def read(id)
    @rows[id]
  end

  def write(id, image_data)
    @rows[id] = image_data
  end
end

# Plain Ruby model with a Shrine attachment. Reads and writes go straight
# to the DocumentStore, so the column is always fresh.
class Document
  include MyUploader::Attachment(:image)

  attr_reader :id

  def initialize(store, id)
    @store = store
    @id    = id
  end

  def image_data
    @store.read(@id)
  end

  def image_data=(value)
    @store.write(@id, value)
  end

  def save
    true
  end

  def reload
    self
  end
end
