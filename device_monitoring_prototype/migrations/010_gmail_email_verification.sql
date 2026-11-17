-- Back up the database before applying this additive migration.
-- Existing accounts retain their current email_verified values.
ALTER TABLE users
    ALTER COLUMN email_verified SET DEFAULT FALSE;

CREATE TABLE email_verifications (
    id BIGINT NOT NULL AUTO_INCREMENT,
    registration_challenge_id BIGINT NOT NULL,
    email VARCHAR(254) NOT NULL,
    verification_code CHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at DATETIME NULL,
    PRIMARY KEY (id),
    KEY ix_email_verifications_challenge_created (registration_challenge_id, created_at),
    KEY ix_email_verifications_email_created (email, created_at),
    KEY ix_email_verifications_expiry (expires_at),
    CONSTRAINT fk_email_verifications_registration_challenge
        FOREIGN KEY (registration_challenge_id)
        REFERENCES registration_challenges (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
