-- Back up the database before applying this additive migration.

ALTER TABLE device_registration_tokens
    ADD COLUMN verified_at DATETIME NULL,
    ADD COLUMN download_confirmed_at DATETIME NULL;
