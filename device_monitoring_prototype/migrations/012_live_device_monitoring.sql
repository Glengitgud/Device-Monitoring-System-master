-- Opt-in live monitoring: a per-device heartbeat credential and network throughput.
-- Additive only; existing rows keep NULL (monitoring off). Apply once.

ALTER TABLE devices
    ADD COLUMN monitoring_token_hash CHAR(64) NULL,
    ADD COLUMN monitoring_enabled_at DATETIME NULL,
    ADD COLUMN monitoring_stopped_at DATETIME NULL;

ALTER TABLE devices
    ADD UNIQUE KEY uq_devices_monitoring_token_hash (monitoring_token_hash);

ALTER TABLE device_metrics
    ADD COLUMN network_rx_bytes_per_sec BIGINT NULL,
    ADD COLUMN network_tx_bytes_per_sec BIGINT NULL;
