#include <snapshot.h>

#if defined(HAVE_SQLITE3_SNAPSHOT_GET) && \
    defined(HAVE_SQLITE3_SNAPSHOT_OPEN) && \
    defined(HAVE_SQLITE3_SNAPSHOT_FREE)

typedef struct {
    sqlite3_snapshot *snapshot;
} sqlite3SnapshotRuby;

typedef sqlite3SnapshotRuby *sqlite3SnapshotRubyPtr;

static VALUE cSqlite3Snapshot;
static const rb_data_type_t snapshot_type;

#ifndef SQLITE_ERROR_SNAPSHOT
#define SQLITE_ERROR_SNAPSHOT (SQLITE_ERROR | (3 << 8))
#endif

static sqlite3SnapshotRubyPtr
snapshot_unwrap(VALUE snapshot)
{
    sqlite3SnapshotRubyPtr ctx;
    TypedData_Get_Struct(snapshot, sqlite3SnapshotRuby, &snapshot_type, ctx);
    return ctx;
}

static void
snapshot_deallocate(void *data)
{
    sqlite3SnapshotRubyPtr ctx = (sqlite3SnapshotRubyPtr)data;

    if (ctx->snapshot) {
        sqlite3_snapshot_free(ctx->snapshot);
        ctx->snapshot = NULL;
    }

    xfree(ctx);
}

static size_t
snapshot_memsize(const void *data)
{
    return sizeof(sqlite3SnapshotRuby);
}

static const rb_data_type_t snapshot_type = {
    .wrap_struct_name = "SQLite3::Snapshot",
    .function = {
        .dfree = snapshot_deallocate,
        .dsize = snapshot_memsize,
    },
    .flags = RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED,
};

static VALUE
snapshot_allocate(VALUE klass)
{
    sqlite3SnapshotRubyPtr ctx;
    return TypedData_Make_Struct(klass, sqlite3SnapshotRuby, &snapshot_type, ctx);
}

static VALUE
snapshot_capture(VALUE self, VALUE database, VALUE schema)
{
    sqlite3RubyPtr db_ctx;
    sqlite3SnapshotRubyPtr snapshot_ctx;
    sqlite3_snapshot *snapshot = NULL;
    int status;

    TypedData_Get_Struct(self, sqlite3SnapshotRuby, &snapshot_type, snapshot_ctx);
    db_ctx = sqlite3_database_unwrap(database);

    if (!db_ctx->db) {
        rb_raise(rb_path2class("SQLite3::Exception"), "cannot use a closed database");
    }

    status = sqlite3_snapshot_get(db_ctx->db, StringValueCStr(schema), &snapshot);
    if (status != SQLITE_OK) {
        snapshot_ctx->snapshot = NULL;
        CHECK(db_ctx->db, status);
    }

    snapshot_ctx->snapshot = snapshot;
    return self;
}

static VALUE
snapshot_open(VALUE self, VALUE database, VALUE schema)
{
    sqlite3RubyPtr db_ctx;
    sqlite3SnapshotRubyPtr snapshot_ctx;
    int status;

    snapshot_ctx = snapshot_unwrap(self);
    db_ctx = sqlite3_database_unwrap(database);

    if (!db_ctx->db) {
        rb_raise(rb_path2class("SQLite3::Exception"), "cannot use a closed database");
    }
    if (!snapshot_ctx->snapshot) {
        rb_raise(rb_path2class("SQLite3::Exception"), "cannot use a released snapshot");
    }

    status = sqlite3_snapshot_open(
                 db_ctx->db,
                 StringValueCStr(schema),
                 snapshot_ctx->snapshot
             );
    if (status == SQLITE_ERROR_SNAPSHOT) {
        VALUE exception = rb_exc_new2(
                              rb_path2class("SQLite3::SQLException"),
                              "snapshot is no longer valid"
                          );
        rb_iv_set(exception, "@code", INT2FIX(status));
        rb_exc_raise(exception);
    }
    CHECK(db_ctx->db, status);

    return database;
}

static VALUE
snapshot_release(VALUE self)
{
    sqlite3SnapshotRubyPtr ctx = snapshot_unwrap(self);

    if (ctx->snapshot) {
        sqlite3_snapshot_free(ctx->snapshot);
        ctx->snapshot = NULL;
    }

    return Qnil;
}

static VALUE
snapshot_closed_p(VALUE self)
{
    return snapshot_unwrap(self)->snapshot ? Qfalse : Qtrue;
}

void
init_sqlite3_snapshot(void)
{
    cSqlite3Snapshot = rb_define_class_under(mSqlite3, "Snapshot", rb_cObject);

    rb_define_alloc_func(cSqlite3Snapshot, snapshot_allocate);
    rb_define_private_method(cSqlite3Snapshot, "capture!", snapshot_capture, 2);
    rb_define_private_method(cSqlite3Snapshot, "open!", snapshot_open, 2);
    rb_define_method(cSqlite3Snapshot, "close", snapshot_release, 0);
    rb_define_alias(cSqlite3Snapshot, "release", "close");
    rb_define_method(cSqlite3Snapshot, "closed?", snapshot_closed_p, 0);
    rb_define_const(mSqlite3, "SNAPSHOT_SUPPORTED", Qtrue);
}

#else

void
init_sqlite3_snapshot(void)
{
    rb_define_const(mSqlite3, "SNAPSHOT_SUPPORTED", Qfalse);
}

#endif
