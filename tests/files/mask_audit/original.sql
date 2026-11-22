-- ticket OPS-12
ALTER TABLE zone_a.t_orders ADD COLUMN note VARCHAR(64);
CREATE TABLE zone_b.t_audit (id INT);
