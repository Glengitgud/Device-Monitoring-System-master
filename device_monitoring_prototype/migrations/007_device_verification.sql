-- Back up the database before applying this additive migration.
-- Existing device rows are retained and start unverified until explicitly
-- confirmed by a successful QR agent registration.

ALTER TABLE devices
    ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT FALSE;
