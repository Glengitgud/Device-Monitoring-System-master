"""Email verification and TOTP helpers for account registration and sign-in."""

import base64
import hashlib
import hmac
import re
import secrets
import smtplib
import struct
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import quote

import qrcode
from qrcode.image.svg import SvgPathImage
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from device_monitoring_prototype.models import (
    ActivityLog,
    EmailVerification,
    RegistrationChallenge,
    Role,
    User,
    db,
)
from device_monitoring_prototype.services import (
    EMAIL_PATTERN,
    DatabaseSetupError,
    ValidationError,
    hash_password,
    validate_password,
    verify_password,
)

EMAIL_CODE_LIFETIME = timedelta(minutes=5)
REGISTRATION_LIFETIME = timedelta(minutes=30)
EMAIL_RESEND_INTERVAL = timedelta(seconds=60)
EMAIL_SENDS_PER_HOUR = 5
MAX_VERIFICATION_ATTEMPTS = 5
EMAIL_CODE_PATTERN = re.compile(r"[0-9]{6}")
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{3,64}")
TOTP_PERIOD_SECONDS = 30
# RFC 6238 recommends accepting at most one time step of drift either way.
# Registration and sign-in share this window so an enrolled authenticator that
# passes registration also passes sign-in.
TOTP_VALID_WINDOW_STEPS = 1


class RegistrationRestartRequired(ValidationError):
    """Raised when a pending registration is closed and must be started again."""


class EmailDeliveryError(RuntimeError):
    """Raised when the configured email transport cannot send verification mail."""

    def __init__(self, message, challenge_id=None):
        super().__init__(message)
        self.challenge_id = challenge_id


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _fernet():
    secret = current_app.config.get("TOTP_ENCRYPTION_KEY") or current_app.config["SECRET_KEY"]
    if isinstance(secret, bytes):
        secret = secret.decode("utf-8")
    key = hashlib.sha256(
        b"DevMonitor TOTP secret encryption v1:" + str(secret).encode("utf-8")
    ).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_totp_secret(secret):
    return _fernet().encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_totp_secret(encrypted_secret):
    try:
        return _fernet().decrypt(encrypted_secret.encode("ascii")).decode("ascii")
    except (InvalidToken, UnicodeDecodeError, ValueError) as error:
        raise RuntimeError("The authenticator secret cannot be decrypted.") from error


def _email_code_hash(challenge_id, code):
    secret = current_app.config["SECRET_KEY"]
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    value = f"{challenge_id}:{code}".encode("ascii")
    return hmac.new(secret, value, hashlib.sha256).hexdigest()


def _validate_registration(data, exclude_challenge_id=None):
    def required_text(name, limit):
        value = data.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{name.replace('_', ' ').capitalize()} is required.")
        value = value.strip()
        if len(value) > limit:
            raise ValidationError(f"{name.replace('_', ' ').capitalize()} is too long.")
        return value

    full_name = required_text("full_name", 120)
    username = required_text("username", 64)
    email = required_text("email", 254).lower()
    password = data.get("password")
    validate_password(password)
    if data.get("confirm_password") != password:
        raise ValidationError("Passwords do not match.")
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValidationError(
            "Username must be 3-64 letters, numbers, dots, dashes, or underscores."
        )
    if username.casefold() == "admin":
        raise ValidationError("The username 'admin' is reserved for the system Administrator.")
    if not EMAIL_PATTERN.fullmatch(email):
        raise ValidationError("Enter a valid email address.")
    if User.query.filter(
        or_(func.lower(User.username) == username.lower(), func.lower(User.email) == email)
    ).first():
        raise ValidationError("That username or email address is already registered.")
    existing_challenges = RegistrationChallenge.query.filter(
        RegistrationChallenge.expires_at > utcnow(),
        RegistrationChallenge.completed_at.is_(None),
        or_(
            func.lower(RegistrationChallenge.username) == username.lower(),
            func.lower(RegistrationChallenge.email) == email,
        ),
    )
    if exclude_challenge_id is not None:
        existing_challenges = existing_challenges.filter(
            RegistrationChallenge.id != exclude_challenge_id
        )
    if existing_challenges.first():
        raise ValidationError(
            "A registration verification is already in progress for that username or email."
        )
    return full_name, username, email, password


def _send_email(email, code):
    host = current_app.config.get("MAIL_SERVER")
    if not host:
        current_app.logger.error("SMTP host is not configured.")
        raise EmailDeliveryError(
            "Email verification is not configured. Please contact the system administrator."
        )
    if not EMAIL_PATTERN.fullmatch(email or "") or not EMAIL_CODE_PATTERN.fullmatch(code or ""):
        current_app.logger.error("Refusing to send a malformed verification email.")
        raise EmailDeliveryError(
            "We could not prepare the verification email. Please check the address and try again."
        )

    message = EmailMessage()
    message["Subject"] = "Your DevMonitor verification code"
    username = current_app.config.get("MAIL_USERNAME")
    sender = current_app.config.get("MAIL_DEFAULT_SENDER") or username
    if host.lower() == "smtp.gmail.com" and (
        not username or sender.lower() != username.lower()
    ):
        current_app.logger.error(
            "Gmail sender must match the authenticated SMTP username."
        )
        raise EmailDeliveryError(
            "Email sender settings are inconsistent. Please contact the system administrator."
        )
    message["From"] = f"DevMonitor <{sender}>" if sender else "DevMonitor"
    message["To"] = email
    message.set_content(
        "DevMonitor\n\n"
        f"Your email verification code is: {code}\n\n"
        "This code expires in 5 minutes. If you did not request an account, "
        "you can ignore this message."
    )
    message.add_alternative(
        "<!doctype html><html><body style=\"font-family:Arial,sans-serif;color:#172033\">"
        "<main style=\"max-width:560px;margin:24px auto;padding:24px;border:1px solid #dbe2ea;"
        "border-radius:12px\"><p style=\"color:#26408b;font-weight:bold\">DevMonitor</p>"
        "<h1 style=\"font-size:22px\">Verify your email address</h1>"
        "<p>Use this verification code to continue creating your account:</p>"
        f"<p style=\"font-size:30px;font-weight:bold;letter-spacing:6px\">{code}</p>"
        "<p>This code expires in <strong>5 minutes</strong>. If you did not request "
        "an account, you can ignore this message.</p></main></body></html>",
        subtype="html",
    )

    port = int(current_app.config.get("MAIL_PORT", 587))
    timeout = int(current_app.config.get("MAIL_TIMEOUT", 15))
    password = current_app.config.get("MAIL_PASSWORD")
    use_tls = current_app.config.get("MAIL_USE_TLS", True)
    smtp = None
    try:
        if not username or not password:
            current_app.logger.error("SMTP authentication settings are incomplete.")
            raise EmailDeliveryError(
                "Email verification is not configured. Please contact the system administrator."
            )
        if host == "smtp.gmail.com" and port != 465 and not use_tls:
            current_app.logger.error("Gmail SMTP requires TLS on the configured port.")
            raise EmailDeliveryError(
                "Email verification is not configured. Please contact the system administrator."
            )

        smtp = _open_smtp(host, port, timeout, username, password, use_tls)
        refused = smtp.send_message(message)
        if isinstance(refused, dict) and refused:
            current_app.logger.error(
                "SMTP refused %d verification email recipient(s) (codes=%s).",
                len(refused),
                sorted(
                    response[0]
                    for response in refused.values()
                    if isinstance(response, tuple) and response
                ),
            )
            raise EmailDeliveryError(
                "We could not deliver the verification email. Check the address or try again later."
            )
        current_app.logger.info("SMTP accepted a DevMonitor verification email.")
    except EmailDeliveryError:
        raise
    except (OSError, smtplib.SMTPException) as error:
        current_app.logger.error(
            "Registration email delivery failed (%s, code=%s).",
            type(error).__name__,
            getattr(error, "smtp_code", None),
        )
        raise EmailDeliveryError(
            "We could not send the verification email. Check the address or try again later."
        ) from error
    finally:
        if smtp is not None:
            smtp.close()


def _open_smtp(host, port, timeout, username, password, use_tls):
    smtp = None
    try:
        if port == 465:
            smtp = smtplib.SMTP_SSL(host, port, timeout=timeout)
            smtp.ehlo()
        else:
            smtp = smtplib.SMTP(host, port, timeout=timeout)
            smtp.ehlo()
            if use_tls:
                smtp.starttls()
                smtp.ehlo()
        smtp.login(username, password)
        return smtp
    except smtplib.SMTPAuthenticationError as error:
        current_app.logger.error(
            "SMTP authentication failed (code=%s).", error.smtp_code
        )
        if smtp is not None:
            smtp.close()
        raise EmailDeliveryError(
            "Email service authentication failed. Please contact the system administrator."
        ) from error
    except (OSError, smtplib.SMTPException) as error:
        current_app.logger.error(
            "SMTP connection or authentication failed (%s, code=%s).",
            type(error).__name__,
            getattr(error, "smtp_code", None),
        )
        if smtp is not None:
            smtp.close()
        raise EmailDeliveryError(
            "We could not connect to the email service. Please try again later."
        ) from error


def check_smtp_connection():
    host = current_app.config.get("MAIL_SERVER")
    username = current_app.config.get("MAIL_USERNAME")
    password = current_app.config.get("MAIL_PASSWORD")
    if not host or not username or not password:
        raise EmailDeliveryError("SMTP host, username, and password must be configured.")
    port = int(current_app.config.get("MAIL_PORT", 587))
    timeout = int(current_app.config.get("MAIL_TIMEOUT", 15))
    use_tls = current_app.config.get("MAIL_USE_TLS", True)
    if host == "smtp.gmail.com" and port != 465 and not use_tls:
        raise EmailDeliveryError("Gmail SMTP requires TLS.")
    smtp = _open_smtp(host, port, timeout, username, password, use_tls)
    try:
        code, _ = smtp.noop()
        if code != 250:
            current_app.logger.error("SMTP connectivity check returned code %s.", code)
            raise EmailDeliveryError("SMTP server did not accept the connectivity check.")
    except (OSError, smtplib.SMTPException) as error:
        current_app.logger.error(
            "SMTP connectivity check failed (%s, code=%s).",
            type(error).__name__,
            getattr(error, "smtp_code", None),
        )
        raise EmailDeliveryError("SMTP connectivity check failed.") from error
    finally:
        smtp.close()


def _new_email_code(challenge_id, previous_hash=None):
    for _ in range(10):
        code = f"{secrets.randbelow(1_000_000):06d}"
        if not hmac.compare_digest(
            _email_code_hash(challenge_id, code), previous_hash or ""
        ):
            return code
    raise RuntimeError("Could not generate a fresh verification code.")


def start_registration(data, existing_challenge=None):
    full_name, username, email, password = _validate_registration(
        data,
        exclude_challenge_id=existing_challenge.id if existing_challenge else None,
    )
    if existing_challenge and existing_challenge.completed_at is None:
        if (
            existing_challenge.expires_at > utcnow()
            and existing_challenge.username == username
            and existing_challenge.email == email
            and existing_challenge.display_name == full_name
            and existing_challenge.password_hash
            and existing_challenge.totp_attempts < MAX_VERIFICATION_ATTEMPTS
            and verify_password(password, existing_challenge.password_hash)
        ):
            return existing_challenge
    if Role.query.filter_by(name="User").one_or_none() is None:
        raise DatabaseSetupError(
            "Database roles are missing; run "
            "`flask --app device_monitoring_prototype.app init-db` from the repository root."
        )
    recent_sends = RegistrationChallenge.query.filter(
        func.lower(RegistrationChallenge.email) == email,
        RegistrationChallenge.created_at > utcnow() - timedelta(hours=1),
    ).count()
    if recent_sends >= EMAIL_SENDS_PER_HOUR:
        raise ValidationError(
            "Too many verification requests. Please wait before trying again."
        )
    if existing_challenge and existing_challenge.completed_at is None:
        cancel_registration(existing_challenge)
    now = utcnow()
    challenge = RegistrationChallenge(
        username=username,
        email=email,
        display_name=full_name,
        password_hash=hash_password(password),
        email_attempts=0,
        totp_attempts=0,
        email_send_count=1,
        last_email_sent_at=now,
        expires_at=now + REGISTRATION_LIFETIME,
    )
    db.session.add(challenge)
    db.session.flush()
    code = _new_email_code(challenge.id)
    verification = EmailVerification(
        registration_challenge_id=challenge.id,
        email=email,
        verification_code=_email_code_hash(challenge.id, code),
        created_at=now,
        expires_at=now + EMAIL_CODE_LIFETIME,
    )
    db.session.add(verification)
    try:
        db.session.commit()
    except IntegrityError as error:
        db.session.rollback()
        raise ValidationError("That username or email address is already registered.") from error
    try:
        _send_email(email, code)
    except EmailDeliveryError as error:
        verification.expires_at = utcnow()
        challenge.last_email_sent_at = now - EMAIL_RESEND_INTERVAL - timedelta(seconds=1)
        challenge.email_send_count = 0
        db.session.commit()
        current_app.logger.warning(
            "Initial registration email delivery failed (challenge_id=%s).",
            challenge.id,
        )
        raise EmailDeliveryError(str(error), challenge_id=challenge.id) from error
    return challenge


def _ensure_challenge_is_open(challenge):
    if challenge.completed_at is not None:
        raise ValidationError("This registration has already been completed. Please sign in.")
    if challenge.expires_at <= utcnow():
        raise RegistrationRestartRequired("This registration has expired. Please start again.")


def resend_email_code(challenge):
    _ensure_challenge_is_open(challenge)
    now = utcnow()
    if challenge.email_verified_at is not None:
        raise ValidationError("Your email is already verified.")
    if challenge.last_email_sent_at + EMAIL_RESEND_INTERVAL > now:
        wait_seconds = int(
            (challenge.last_email_sent_at + EMAIL_RESEND_INTERVAL - now).total_seconds()
        ) + 1
        raise ValidationError(f"Please wait {wait_seconds} seconds before requesting another code.")
    if challenge.email_send_count >= EMAIL_SENDS_PER_HOUR:
        raise ValidationError(
            "You have reached the resend limit. Please start registration again later."
        )
    previous_verification = (
        EmailVerification.query.filter_by(registration_challenge_id=challenge.id)
        .order_by(EmailVerification.created_at.desc(), EmailVerification.id.desc())
        .first()
    )
    previous_hash = previous_verification.verification_code if previous_verification else None
    code = _new_email_code(challenge.id, previous_hash)
    if previous_verification and not previous_verification.verified:
        previous_verification.expires_at = now
    verification = EmailVerification(
        registration_challenge_id=challenge.id,
        email=challenge.email,
        verification_code=_email_code_hash(challenge.id, code),
        created_at=now,
        expires_at=now + EMAIL_CODE_LIFETIME,
    )
    db.session.add(verification)
    challenge.last_email_sent_at = now
    challenge.email_send_count += 1
    challenge.email_attempts = 0
    try:
        _send_email(challenge.email, code)
    except EmailDeliveryError:
        db.session.rollback()
        failed_challenge = db.session.get(RegistrationChallenge, challenge.id)
        failed_challenge.last_email_sent_at = now
        failed_challenge.email_send_count += 1
        db.session.commit()
        current_app.logger.warning(
            "Resend email delivery failed (challenge_id=%s).",
            challenge.id,
        )
        raise
    db.session.commit()


def cancel_registration(challenge):
    if challenge.completed_at is not None:
        raise ValidationError("This registration has already been completed.")
    challenge.expires_at = utcnow()
    challenge.password_hash = None
    challenge.email_code_hash = None
    challenge.email_code_expires_at = None
    challenge.totp_secret_encrypted = None
    db.session.commit()


def registration_authenticator_qr(challenge):
    if not challenge.totp_secret_encrypted:
        raise ValidationError("Authenticator setup is not available yet.")
    secret = decrypt_totp_secret(challenge.totp_secret_encrypted)
    label = quote(f"DevMonitor:{challenge.email}")
    issuer = quote("DevMonitor")
    uri = (
        f"otpauth://totp/{label}?secret={secret}&issuer={issuer}"
        f"&algorithm=SHA1&digits=6&period={TOTP_PERIOD_SECONDS}"
    )
    image = qrcode.make(uri, image_factory=SvgPathImage, box_size=8, border=4)
    root = ET.fromstring(image.to_string())
    namespace = "{http://www.w3.org/2000/svg}"
    root.insert(
        0,
        ET.Element(
            f"{namespace}rect",
            {"width": "100%", "height": "100%", "fill": "#ffffff"},
        ),
    )
    for path in root.iter(f"{namespace}path"):
        path.set("fill", "#111827")
    encoded = base64.b64encode(ET.tostring(root, encoding="utf-8")).decode("ascii")
    return "data:image/svg+xml;base64," + encoded


def verify_email_code(challenge, code):
    _ensure_challenge_is_open(challenge)
    if challenge.email_verified_at is not None:
        raise ValidationError("Your email is already verified.")
    if challenge.email_attempts >= MAX_VERIFICATION_ATTEMPTS:
        raise ValidationError("Too many incorrect codes. Request a new code to continue.")
    if not EMAIL_CODE_PATTERN.fullmatch(code or ""):
        challenge.email_attempts += 1
        db.session.commit()
        current_app.logger.warning(
            "Email verification rejected (challenge_id=%s, reason=malformed_code, attempt=%s).",
            challenge.id,
            challenge.email_attempts,
        )
        if challenge.email_attempts >= MAX_VERIFICATION_ATTEMPTS:
            raise ValidationError("Too many incorrect codes. Request a new code to continue.")
        raise ValidationError("Enter the 6-digit code sent to your email.")
    verification = (
        EmailVerification.query.filter_by(
            registration_challenge_id=challenge.id,
            email=challenge.email,
            verified=False,
        )
        .order_by(EmailVerification.created_at.desc(), EmailVerification.id.desc())
        .first()
    )
    if verification is None or verification.expires_at <= utcnow():
        current_app.logger.warning(
            "Email verification rejected (challenge_id=%s, reason=expired_or_missing_code).",
            challenge.id,
        )
        raise ValidationError("That email code has expired. Request a new code.")
    expected = _email_code_hash(challenge.id, code)
    if not hmac.compare_digest(verification.verification_code, expected):
        challenge.email_attempts += 1
        db.session.commit()
        current_app.logger.warning(
            "Email verification rejected (challenge_id=%s, reason=incorrect_code, attempt=%s).",
            challenge.id,
            challenge.email_attempts,
        )
        if challenge.email_attempts >= MAX_VERIFICATION_ATTEMPTS:
            raise ValidationError("Too many incorrect codes. Request a new code to continue.")
        raise ValidationError("That verification code is incorrect. Please try again.")

    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    challenge.email_verified_at = utcnow()
    verification.verified = True
    verification.used_at = challenge.email_verified_at
    challenge.totp_secret_encrypted = encrypt_totp_secret(secret)
    db.session.commit()
    current_app.logger.info("Email verified for registration challenge_id=%s.", challenge.id)
    return registration_authenticator_qr(challenge)


def totp_counter(secret, code, now=None):
    if not EMAIL_CODE_PATTERN.fullmatch(code or ""):
        return None
    try:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except (ValueError, TypeError):
        return None
    current = int((now if now is not None else time.time()) // TOTP_PERIOD_SECONDS)
    for counter in range(
        current - TOTP_VALID_WINDOW_STEPS, current + TOTP_VALID_WINDOW_STEPS + 1
    ):
        if counter < 0:
            continue
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        expected = f"{number % 1_000_000:06d}"
        if hmac.compare_digest(expected, code):
            return counter
    return None


def _close_locked_registration(challenge):
    """Invalidate a challenge that exhausted its authenticator attempts.

    The challenge used to stay open with its attempt counter at the limit, so
    reloading the page or resubmitting the same details resumed it and every
    later code (even a valid one) was refused. Closing it lets the next
    sign-up submission create a fresh challenge with a new secret.
    """
    cancel_registration(challenge)
    current_app.logger.warning(
        "Registration closed after too many authenticator attempts (challenge_id=%s).",
        challenge.id,
    )
    raise RegistrationRestartRequired(
        "Too many incorrect authenticator codes. Start registration again."
    )


def verify_registration_totp(challenge, code):
    _ensure_challenge_is_open(challenge)
    if challenge.email_verified_at is None or not challenge.totp_secret_encrypted:
        raise ValidationError("Verify your email before setting up the authenticator.")
    if challenge.totp_verified_at is not None:
        raise ValidationError("The authenticator code has already been verified.")
    if challenge.totp_attempts >= MAX_VERIFICATION_ATTEMPTS:
        _close_locked_registration(challenge)
    secret = decrypt_totp_secret(challenge.totp_secret_encrypted)
    counter = totp_counter(secret, code)
    if counter is None or (
        challenge.totp_last_counter is not None and counter <= challenge.totp_last_counter
    ):
        challenge.totp_attempts += 1
        db.session.commit()
        current_app.logger.warning(
            "Authenticator verification rejected (challenge_id=%s, attempt=%s).",
            challenge.id,
            challenge.totp_attempts,
        )
        if challenge.totp_attempts >= MAX_VERIFICATION_ATTEMPTS:
            _close_locked_registration(challenge)
        remaining = MAX_VERIFICATION_ATTEMPTS - challenge.totp_attempts
        raise ValidationError(
            "That authenticator code is invalid or expired. Make sure your phone's date "
            "and time are set automatically, then enter the newest code shown for "
            f"DevMonitor. {remaining} attempt{'s' if remaining != 1 else ''} remaining."
        )
    challenge.totp_last_counter = counter
    challenge.totp_verified_at = utcnow()


def complete_registration(challenge):
    _ensure_challenge_is_open(challenge)
    if (
        challenge.email_verified_at is None
        or challenge.totp_verified_at is None
        or not challenge.password_hash
        or not challenge.totp_secret_encrypted
    ):
        raise ValidationError("Complete both verification steps before creating your account.")
    role = Role.query.filter_by(name="User").one_or_none()
    if role is None:
        raise RuntimeError("Database roles are missing; run the application init-db command.")
    user = User(
        username=challenge.username,
        email=challenge.email,
        display_name=challenge.display_name,
        password_hash=challenge.password_hash,
        status="active",
        email_verified=True,
        email_verified_at=challenge.email_verified_at,
        totp_enabled=True,
        totp_secret_encrypted=challenge.totp_secret_encrypted,
        totp_verified_at=challenge.totp_verified_at,
        totp_last_counter=challenge.totp_last_counter,
    )
    user.roles.append(role)
    db.session.add(user)
    try:
        db.session.flush()
        db.session.add(
            ActivityLog(
                actor_user_id=user.id,
                event_type="auth.registration_completed",
                entity_type="user",
                entity_id=user.id,
                details={"username": user.username},
            )
        )
        challenge.completed_at = utcnow()
        challenge.password_hash = None
        challenge.email_code_hash = None
        challenge.email_code_expires_at = None
        challenge.totp_secret_encrypted = None
        db.session.commit()
        current_app.logger.info(
            "Account registration completed (challenge_id=%s, user_id=%s).",
            challenge.id,
            user.id,
        )
        return user
    except IntegrityError as error:
        db.session.rollback()
        raise ValidationError("That username or email address is already registered.") from error


def verify_login_totp(user, code):
    if not user.totp_enabled or not user.totp_secret_encrypted:
        return False
    secret = decrypt_totp_secret(user.totp_secret_encrypted)
    counter = totp_counter(secret, code)
    if counter is None or (
        user.totp_last_counter is not None and counter <= user.totp_last_counter
    ):
        return False
    user.totp_last_counter = counter
    return True


def utc_timestamp(value):
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()
