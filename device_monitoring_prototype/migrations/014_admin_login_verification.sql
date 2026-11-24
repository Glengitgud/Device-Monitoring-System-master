-- Administrator sign-in: password plus a 6-digit code emailed to the administrator
-- address (expires after 5 minutes). Additive only; apply once.

CREATE TABLE login_verifications (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    code_hash CHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at DATETIME NULL,
    PRIMARY KEY (id),
    KEY ix_login_verifications_user_created (user_id, created_at),
    KEY ix_login_verifications_expiry (expires_at),
    CONSTRAINT fk_login_verifications_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The built-in administrator receives its sign-in codes at the system mailbox.
-- Only the bootstrap address is replaced, and only when the mailbox is unused.
-- (If ADMIN_EMAIL is set to another address, `init-db` applies that one instead.)
UPDATE users
    SET email = 'devmonitor.system@gmail.com'
    WHERE LOWER(username) = 'admin'
      AND LOWER(email) = 'admin@localhost'
      AND NOT EXISTS (
          SELECT 1 FROM (
              SELECT id FROM users WHERE LOWER(email) = 'devmonitor.system@gmail.com'
          ) AS taken
      );
