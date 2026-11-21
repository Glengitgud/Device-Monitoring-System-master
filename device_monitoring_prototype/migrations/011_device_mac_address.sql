-- Add endpoint MAC addresses to devices and their enrollment records.
ALTER TABLE devices
    ADD COLUMN mac_address VARCHAR(17) NULL;

ALTER TABLE device_registration_tokens
    ADD COLUMN mac_address VARCHAR(17) NULL;
