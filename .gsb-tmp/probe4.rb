require "sqlite3"
p SQLite3::Statement.column_metadata_supported?
db = SQLite3::Database.new(":memory:")
db.execute("CREATE TABLE t1(id INTEGER, name TEXT)")
db.execute("CREATE TABLE t2(id INTEGER, t1_id INTEGER)")
db.execute("CREATE VIEW v AS SELECT id, name FROM t1")
db.execute("INSERT INTO t1 VALUES(1,char(97))")
db.execute("INSERT INTO t2 VALUES(10,1)")
queries = [
  "SELECT t1.id, t2.id FROM t1 JOIN t2 ON t1.id=t2.t1_id",
  "SELECT id, id FROM t1",
  "SELECT id*2 AS d, 42 AS lit, name||id FROM t1",
  "SELECT id, name FROM v",
  "SELECT id FROM (SELECT id FROM t1)",
  "SELECT x FROM (SELECT id AS x FROM t1)",
  "WITH c AS (SELECT id FROM t1) SELECT id FROM c",
  "SELECT * FROM (SELECT id, id FROM t1)"
]
queries.each do |q|
  s = db.prepare(q)
  p [q, s.column_metadata]
  s.close
end
["INSERT INTO t1(name) VALUES(char(98)) RETURNING id, name",
 "UPDATE t1 SET name=char(99) WHERE id=1 RETURNING id AS rid, name",
 "DELETE FROM t1 WHERE id=1 RETURNING id"].each do |q|
  s = db.prepare(q)
  p [q, s.column_metadata]
  s.execute.to_a
  s.close
end
db.close