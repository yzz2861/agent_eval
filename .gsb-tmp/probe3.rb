require "fiddle"
require "fiddle/import"
module Sql
  extend Fiddle::Importer
  dlload "/opt/homebrew/Cellar/sqlite/3.53.1/lib/libsqlite3.3.53.1.dylib"
  extern "int sqlite3_open_v2(const char*, void**, int, const char*)"
  extern "int sqlite3_prepare_v2(void*, const char*, int, void**, const char**)"
  extern "int sqlite3_step(void*)"
  extern "int sqlite3_column_count(void*)"
  extern "const char* sqlite3_column_name(void*, int)"
  extern "const char* sqlite3_column_database_name(void*, int)"
  extern "const char* sqlite3_column_table_name(void*, int)"
  extern "const char* sqlite3_column_origin_name(void*, int)"
  extern "int sqlite3_finalize(void*)"
  extern "int sqlite3_close(void*)"
  extern "int sqlite3_exec(void*, const char*, void*, void*, const char**)"
end
dbp = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP)
Sql.sqlite3_open_v2(":memory:", dbp.ref, 0x6, nil)
db = dbp.ptr
def sql_exec(db, q); Sql.sqlite3_exec(db, q, nil, nil, nil); end
sql_exec(db, "CREATE TABLE t1(id INTEGER, name TEXT)")
sql_exec(db, "CREATE TABLE t2(id INTEGER, t1_id INTEGER)")
sql_exec(db, "CREATE VIEW v AS SELECT id, name FROM t1")
queries = [
  "SELECT t1.id, t2.id FROM t1 JOIN t2 ON t1.id=t2.t1_id",
  "SELECT id*2 AS d, 42 AS lit, name||id FROM t1",
  "SELECT id, name FROM v",
  "SELECT id FROM (SELECT id FROM t1)",
  "SELECT id FROM (SELECT id AS x FROM t1)",
  "WITH c AS (SELECT id FROM t1) SELECT id FROM c",
  "SELECT * FROM (SELECT id, id FROM t1)"
]
queries.each do |q|
  sp = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP)
  Sql.sqlite3_prepare_v2(db, q, -1, sp.ref, nil)
  s = sp.ptr
  n = Sql.sqlite3_column_count(s)
  info = (0...n).map do |i|
    [Sql.sqlite3_column_name(s,i).to_s,
     (p=Sql.sqlite3_column_database_name(s,i); p.null? ? nil : p.to_s),
     (p=Sql.sqlite3_column_table_name(s,i); p.null? ? nil : p.to_s),
     (p=Sql.sqlite3_column_origin_name(s,i); p.null? ? nil : p.to_s)]
  end
  p [q, info]
  Sql.sqlite3_finalize(s)
end
[ "INSERT INTO t1(name) VALUES(char(98)) RETURNING id, name",
  "UPDATE t1 SET name=char(99) RETURNING id, name",
  "DELETE FROM t1 RETURNING id" ].each do |q|
  sp = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP)
  Sql.sqlite3_prepare_v2(db, q, -1, sp.ref, nil)
  s = sp.ptr
  n = Sql.sqlite3_column_count(s)
  info = (0...n).map do |i|
    [Sql.sqlite3_column_name(s,i).to_s,
     (p=Sql.sqlite3_column_database_name(s,i); p.null? ? nil : p.to_s),
     (p=Sql.sqlite3_column_table_name(s,i); p.null? ? nil : p.to_s),
     (p=Sql.sqlite3_column_origin_name(s,i); p.null? ? nil : p.to_s)]
  end
  p [q, info]
  Sql.sqlite3_step(s)
  info2 = (0...n).map do |i|
    (p=Sql.sqlite3_column_origin_name(s,i); p.null? ? nil : p.to_s)
  end
  p ["after step", info2]
  Sql.sqlite3_finalize(s)
end
Sql.sqlite3_close(db)