# frozen_string_literal: true

# Runnable demo of a storage migration. Two temporary directories simulate
# the source and target storages.
#
#   bundle exec ruby examples/storage_migration/example.rb

require "tmpdir"
require "stringio"
require "fileutils"

require_relative "lib/storage_migration"
require_relative "support/document"

source_dir   = Dir.mktmpdir("shrine-source")
target_dir   = Dir.mktmpdir("shrine-target")
cache_dir    = Dir.mktmpdir("shrine-cache")
manifest_dir = Dir.mktmpdir("shrine-manifest")

MyUploader.storages = {
  cache:   Shrine::Storage::FileSystem.new(cache_dir),
  store:   Shrine::Storage::FileSystem.new(source_dir),   # source storage
  archive: Shrine::Storage::FileSystem.new(target_dir),   # target storage
}

db = DocumentStore.new
documents = 3.times.map do |i|
  id   = i + 1
  file = MyUploader.upload(StringIO.new("file contents #{id}\n"), :store,
    metadata: { "filename" => "document-#{id}.txt", "mime_type" => "text/plain" })
  db.create(id, file.to_json)
  Document.new(db, id)
end

# The plan pins the source storage identity, the target location, and the
# metadata that must be verified before any attachment is switched.
plan = StorageMigration::Plan.new(
  source_storage:  :store,
  target_storage:  :archive,
  target_location: "migrated",
  verify_metadata: %w[size mime_type filename],
  manifest_path:   File.join(manifest_dir, "manifest.jsonl"),
)

executor = StorageMigration::Executor.new(plan, uploader: MyUploader, name: :image)

puts "== phase 1+2: copy, verify, switch =="
executor.run(documents)
documents.each do |doc|
  puts "  Document##{doc.id}: #{doc.image_data}"
end

puts
puts "== rerun: nothing is re-uploaded or switched again =="
executor.run(documents)

puts
puts "== phase 3: explicit source cleanup =="
executor.cleanup_phase(documents)

puts
puts "== manifest =="
executor.manifest.each do |entry|
  puts "  #{entry['key']}: #{entry['status']} " +       "(source: #{entry['source_id']}, target: #{entry['target_id']})"
end

puts
def count_files(dir)
  Dir.children(dir).sum do |child|
    path = File.join(dir, child)
    File.directory?(path) ? count_files(path) : 1
  end
end

puts "source objects left: #{count_files(source_dir)}"
puts "target objects:      #{count_files(target_dir)}"

[source_dir, target_dir, cache_dir, manifest_dir].each { FileUtils.remove_entry(_1) }
