-- Back up the database before applying this migration.
-- Existing values must be valid before the constraints are added.

ALTER TABLE users
    ADD CONSTRAINT ck_users_status CHECK (
        status IN ('active', 'inactive', 'locked')
    );

ALTER TABLE devices
    ADD CONSTRAINT ck_devices_status CHECK (
        status IN ('online', 'offline', 'maintenance', 'retired', 'unknown')
    );
