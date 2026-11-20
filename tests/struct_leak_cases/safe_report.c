/*
 * Safe construction snippet. This file is parsed only, never compiled:
 * types may be forward-declared and no standard headers are required.
 * Same-named fields are rewritten with safe constants instead of being
 * copied from the internal structure.
 */

struct diag_public {
    int id;
    const char *name;
};

struct diag_internal {
    int id;
    const char *name;
    char *secret_token;
};

void host_report(const struct diag_public *report);
struct diag_public *project_public(const struct diag_internal *source);

void report_safe(const struct diag_internal *source)
{
    struct diag_public report;

    /* Same field names as the internal struct, but safe constants. */
    report.id = 0;
    report.name = "redacted";

    host_report(&report);
}

void report_via_projection(const struct diag_internal *source)
{
    struct diag_public *report = project_public(source);
    host_report(report);
}

void report_indirect(void (*emit)(const struct diag_public *),
                     const struct diag_public *report)
{
    /* Indirect call: the callee is a function pointer that cannot be
       bound to a declared function, so it must stay in REVIEW. */
    emit(report);
}
