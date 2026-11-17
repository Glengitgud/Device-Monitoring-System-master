-- Back up the database before applying this additive migration.
-- Existing accounts remain verified for backwards-compatible sign-in.

ALTER TABLE users
    ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN email_verified_at DATETIME NULL,
    ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN totp_secret_encrypted TEXT NULL,
    ADD COLUMN totp_verified_at DATETIME NULL,
    ADD COLUMN totp_last_counter BIGINT NULL,
    ADD COLUMN totp_attempts INT NOT NULL DEFAULT 0;

CREATE TABLE registration_challenges (
    id BIGINT NOT NULL AUTO_INCREMENT,
    username VARCHAR(64) NOT NULL,
    email VARCHAR(254) NOT NULL,
    display_name VARCHAR(120) NOT NULL,
    password_hash VARCHAR(255) NULL,
    email_code_hash CHAR(64) NULL,
    email_code_expires_at DATETIME NULL,
    email_verified_at DATETIME NULL,
    totp_secret_encrypted TEXT NULL,
    totp_verified_at DATETIME NULL,
    totp_last_counter BIGINT NULL,
    email_attempts INT NOT NULL DEFAULT 0,
    totp_attempts INT NOT NULL DEFAULT 0,
    email_send_count INT NOT NULL DEFAULT 1,
    last_email_sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    completed_at DATETIME NULL,
    PRIMARY KEY (id),
    KEY ix_registration_challenges_email_created (email, created_at),
    KEY ix_registration_challenges_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
