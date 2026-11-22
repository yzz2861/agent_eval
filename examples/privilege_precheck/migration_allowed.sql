-- Roles: analyst already has SELECT on public.orders.
BEGIN;

ALTER TABLE public.orders RENAME TO orders_archive;

GRANT SELECT, UPDATE ON TABLE public.orders_archive TO analyst;

SAVEPOINT before_destructive_grant;
GRANT DELETE ON TABLE public.orders_archive TO analyst;
ROLLBACK TO SAVEPOINT before_destructive_grant;

COMMIT;
