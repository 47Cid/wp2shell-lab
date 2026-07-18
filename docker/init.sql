-- Grant FILE privilege to the WP database user.
-- This is NOT the WordPress default — managed hosts grant per-database privileges
-- only. FILE shows up on self-managed VPS / DIY stacks that run GRANT ALL ON *.*.
-- The lab grants it to enable the INTO OUTFILE RCE variant.
GRANT FILE ON *.* TO 'wordpress'@'%';
FLUSH PRIVILEGES;
