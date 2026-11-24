-- Device duplicate prevention by MAC address. Additive only; apply once.
--
-- Uniqueness is enforced in services.py, not by a UNIQUE key, because:
--   * an archived device keeps its MAC so its original owner can re-register it,
--   * soft-deleted devices keep their row (and MAC) for history,
--   * phones/tablets report no MAC (NULL), and placeholder MACs are ignored,
--   * existing installs may already hold duplicate rows that a UNIQUE key would reject.
-- The plain index keeps the duplicate lookup fast.

-- Normalise stored MACs to the format the application compares against.
UPDATE devices
    SET mac_address = UPPER(REPLACE(mac_address, '-', ':'))
    WHERE mac_address IS NOT NULL;

ALTER TABLE devices
    ADD KEY ix_devices_mac_address (mac_address);

-- Why the last enrollment attempt with a token was refused (shown on the website).
ALTER TABLE device_registration_tokens
    ADD COLUMN rejected_at DATETIME NULL,
    ADD COLUMN rejection_reason VARCHAR(255) NULL;
