#ifndef SQLITE3_STATEMENT_RUBY
#define SQLITE3_STATEMENT_RUBY

#include <sqlite3_ruby.h>

struct _sqlite3StmtRuby {
    sqlite3_stmt *st;
    sqlite3Ruby *db;
    unsigned long authorizer_version;
    int done_p;
};

typedef struct _sqlite3StmtRuby sqlite3StmtRuby;
typedef sqlite3StmtRuby *sqlite3StmtRubyPtr;

void init_sqlite3_statement();

#endif
