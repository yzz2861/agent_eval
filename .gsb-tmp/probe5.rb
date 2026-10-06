require "sqlite3"
require "tmpdir"
path = File.join(ENV.fetch("TMPDIR", Dir.tmpdir), "sqlite3_ruby_meta_test.db")
File.delete(path) if File.exist?(path)
db = SQLite3::Database.new(path)
db.execute("CREATE TABLE things(id INTEGER PRIMARY KEY, label TEXT)")
db.execute("INSERT INTO things(label) VALUES(char(97))")
db.execute("CREATE TABLE other(x)")
stmt = db.prepare("SELECT id, label FROM things")
first = stmt.execute.to_a
p stmt.column_metadata.map { |m| m[:name] }
p stmt.stat(:reprepares)
db2 = SQLite3::Database.new(path)
db2.execute("ALTER TABLE things ADD COLUMN extra TEXT")
db2.execute("DROP TABLE other")
db2.close
p stmt.execute.to_a
p stmt.stat(:reprepares)
p stmt.column_metadata.map { |m| [m[:name], m[:column], m[:table]] }
p stmt.columns
p stmt.types
stmt.close
star = db.prepare("SELECT * FROM things")
p star.column_metadata.map { |m| m[:name] }
db2 = SQLite3::Database.new(path)
db2.execute("ALTER TABLE things ADD COLUMN extra2 TEXT")
db2.close
p star.execute.to_a
p star.column_metadata.map { |m| m[:name] }
p star.columns
star.close
db.close
File.delete(path) if File.exist?(path)