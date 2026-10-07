#ifdef HAVE_SQLITE3_SNAPSHOT_GET

#include <sqlite3_ruby.h>

#define REQUIRE_OPEN_DB(_ctxt) \
  if(!_ctxt->db) \
    rb_raise(rb_path2class("SQLite3::Exception"), "cannot use a closed database");

#define REQUIRE_OPEN_SNAPSHOT(_ctxt) \
  if(!_ctxt->p) \
    rb_raise(rb_path2class("SQLite3::Exception"), "cannot use a closed snapshot");

VALUE cSqlite3Snapshot;

static void
snapshot_deallocate(void *data)
{
    sqlite3SnapshotRubyPtr ctx = (sqlite3SnapshotRubyPtr)data;
    if (ctx->p) {
        sqlite3_snapshot_free(ctx->p);
        ctx->p = NULL;
    }
    xfree(ctx);
}

static size_t
snapshot_memsize(const void *data)
{
    sqlite3SnapshotRubyPtr ctx = (sqlite3SnapshotRubyPtr)data;
    /* NB: can't account for ctx->p because the type is opaque. */
    return sizeof(*ctx);
}

static const rb_data_type_t snapshot_type = {
    "SQLite3::Snapshot",
    {
        NULL,
        snapshot_deallocate,
        snapshot_memsize,
    },
    0,
    0,
    RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED,
};

static VALUE
snapshot_allocate(VALUE klass)
{
    sqlite3SnapshotRubyPtr ctx;
    return TypedData_Make_Struct(klass, sqlite3SnapshotRuby, &snapshot_type, ctx);
}

/* call-seq: SQLite3::Snapshot#free
 *
 * Destroy the snapshot handle, releasing the resources it holds. The
 * snapshot is also freed by the garbage collector if it is not freed
 * explicitly. A freed snapshot can no longer be opened.
 */
static VALUE
snapshot_free(VALUE self)
{
    sqlite3SnapshotRubyPtr ctx;

    TypedData_Get_Struct(self, sqlite3SnapshotRuby, &snapshot_type, ctx);
    REQUIRE_OPEN_SNAPSHOT(ctx);
    sqlite3_snapshot_free(ctx->p);
    ctx->p = NULL;
    return Qnil;
}

/* call-seq: SQLite3::Snapshot#closed?
 *
 * Returns +true+ if the snapshot handle has been freed.
 */
static VALUE
snapshot_closed_p(VALUE self)
{
    sqlite3SnapshotRubyPtr ctx;

    TypedData_Get_Struct(self, sqlite3SnapshotRuby, &snapshot_type, ctx);
    return ctx->p ? Qfalse : Qtrue;
}

/* call-seq: db.snapshot_get(schema = "main") → SQLite3::Snapshot
 *
 * (private, see Database#snapshot)
 *
 * Records a snapshot of the current read transaction's view of +schema+.
 * The database must be in WAL journal mode and a read transaction must be
 * open on +schema+ (i.e. a SELECT must have been issued within the current
 * transaction).
 */
static VALUE
rb_sqlite3_snapshot_get(int argc, VALUE *argv, VALUE self)
{
    VALUE schema;
    sqlite3RubyPtr ctx;
    sqlite3_snapshot *pSnapshot = NULL;
    sqlite3SnapshotRubyPtr snapshot_ctx;
    VALUE snapshot_obj;
    int status;

    rb_scan_args(argc, argv, "01", &schema);
    if (NIL_P(schema)) { schema = rb_str_new_cstr("main"); }

    ctx = sqlite3_database_unwrap(self);
    REQUIRE_OPEN_DB(ctx);

    status = sqlite3_snapshot_get(ctx->db, StringValueCStr(schema), &pSnapshot);
    if (status != SQLITE_OK) {
        rb_raise(rb_path2class("SQLite3::SQLException"),
                 "cannot capture a snapshot of schema '%s' (is a read transaction open on it?)",
                 StringValueCStr(schema));
    }

    snapshot_obj = TypedData_Make_Struct(cSqlite3Snapshot, sqlite3SnapshotRuby, &snapshot_type,
                                         snapshot_ctx);
    snapshot_ctx->p = pSnapshot;

    return snapshot_obj;
}

/* call-seq: db.snapshot_open(snapshot, schema = "main") → nil
 *
 * (private, see Database#open_snapshot)
 *
 * Moves the current read transaction to the historical database state
 * described by +snapshot+. Raises if the snapshot has been invalidated by a
 * checkpoint or WAL recycling, or if it does not belong to this database;
 * it never silently falls back to the latest database state.
 */
static VALUE
rb_sqlite3_snapshot_open(int argc, VALUE *argv, VALUE self)
{
    VALUE snapshot, schema;
    sqlite3RubyPtr ctx;
    sqlite3SnapshotRubyPtr snapshot_ctx;
    int status;

    rb_scan_args(argc, argv, "11", &snapshot, &schema);
    if (NIL_P(schema)) { schema = rb_str_new_cstr("main"); }

    ctx = sqlite3_database_unwrap(self);
    REQUIRE_OPEN_DB(ctx);
    TypedData_Get_Struct(snapshot, sqlite3SnapshotRuby, &snapshot_type, snapshot_ctx);
    REQUIRE_OPEN_SNAPSHOT(snapshot_ctx);

    status = sqlite3_snapshot_open(ctx->db, StringValueCStr(schema), snapshot_ctx->p);
    if (status == SQLITE_ERROR_SNAPSHOT) {
        rb_raise(rb_path2class("SQLite3::SQLException"),
                 "snapshot is no longer valid: the WAL frames it refers to were removed by a checkpoint");
    } else if (status != SQLITE_OK) {
        rb_raise(rb_path2class("SQLite3::SQLException"),
                 "cannot open snapshot on schema '%s' (does it belong to this database?)",
                 StringValueCStr(schema));
    }

    return Qnil;
}

void
init_sqlite3_snapshot(void)
{
    VALUE cSqlite3Database;
#if 0
    VALUE mSqlite3 = rb_define_module("SQLite3");
#endif
    cSqlite3Database = rb_path2class("SQLite3::Database");

    cSqlite3Snapshot = rb_define_class_under(mSqlite3, "Snapshot", rb_cObject);

    rb_define_alloc_func(cSqlite3Snapshot, snapshot_allocate);
    rb_define_method(cSqlite3Snapshot, "free", snapshot_free, 0);
    rb_define_method(cSqlite3Snapshot, "close", snapshot_free, 0);
    rb_define_method(cSqlite3Snapshot, "closed?", snapshot_closed_p, 0);

    rb_define_private_method(cSqlite3Database, "snapshot_get", rb_sqlite3_snapshot_get, -1);
    rb_define_private_method(cSqlite3Database, "snapshot_open", rb_sqlite3_snapshot_open, -1);
}

#endif
