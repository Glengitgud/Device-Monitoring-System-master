-- Back up the database before applying this migration.

ALTER TABLE device_specifications
    ADD COLUMN ram_usage_bytes BIGINT NULL,
    ADD COLUMN storage_available_bytes BIGINT NULL,
    ADD COLUMN storage_devices JSON NULL,
    ADD COLUMN motherboard_brand VARCHAR(120) NULL,
    ADD COLUMN operating_system_name VARCHAR(120) NULL,
    ADD COLUMN network_adapters JSON NULL,
    ADD COLUMN ip_addresses JSON NULL,
    ADD CONSTRAINT ck_device_specifications_cpu_cores CHECK (
        cpu_cores IS NULL OR (cpu_cores >= 0 AND cpu_cores <= 512)
    ),
    ADD CONSTRAINT ck_device_specifications_memory CHECK (
        memory_bytes IS NULL OR memory_bytes >= 0
    ),
    ADD CONSTRAINT ck_device_specifications_ram_usage CHECK (
        ram_usage_bytes IS NULL OR
        (ram_usage_bytes >= 0 AND (memory_bytes IS NULL OR ram_usage_bytes <= memory_bytes))
    ),
    ADD CONSTRAINT ck_device_specifications_storage CHECK (
        storage_bytes IS NULL OR storage_bytes >= 0
    ),
    ADD CONSTRAINT ck_device_specifications_storage_available CHECK (
        storage_available_bytes IS NULL OR
        (storage_available_bytes >= 0 AND
         (storage_bytes IS NULL OR storage_available_bytes <= storage_bytes))
    );

CREATE TABLE device_registration_tokens (
    id BIGINT NOT NULL AUTO_INCREMENT,
    token_hash CHAR(64) NOT NULL,
    user_id BIGINT NOT NULL,
    device_id BIGINT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    revoked_at DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_device_registration_tokens_hash (token_hash),
    UNIQUE KEY uq_device_registration_tokens_device (device_id),
    KEY ix_device_registration_tokens_user_expiry (user_id, expires_at),
    CONSTRAINT fk_device_registration_tokens_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_device_registration_tokens_device FOREIGN KEY (device_id)
        REFERENCES devices (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
