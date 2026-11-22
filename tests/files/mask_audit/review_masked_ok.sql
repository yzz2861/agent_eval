-- ticket OPS-12
ALTER TABLE <DB>.t_orders ADD COLUMN note VARCHAR(64);
CREATE TABLE <DB>.t_audit (id INT);
