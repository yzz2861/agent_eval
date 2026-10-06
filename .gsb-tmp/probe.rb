require "sqlite3"
db = SQLite3::Database.new(":memory:")
db.execute("CREATE TABLE t(a INTEGER, b TEXT)")
db.execute(%q{INSERT INTO t VALUES(1,char(120))})
stmt = db.prepare("SELECT a, b AS bb, a+b AS c FROM t")
p stmt.respond_to?(:database_name)
p SQLite3::SQLITE_LOADED_VERSION
p stmt.column_name(0)
p (stmt.send(:database_name, 0) rescue $!)
