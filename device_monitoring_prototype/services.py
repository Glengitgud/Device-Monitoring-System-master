"""Validated database operations used by the Flask views."""

import hashlib
import ipaddress
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from sqlalchemy import or_, update
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash

from device_monitoring_prototype.models import (
    ActivityLog,
    Device,
    DeviceRegistrationToken,
    DeviceSpecification,
    Log,
    NetworkRecord,
    Role,
    User,
    db,
)
from device_monitoring_prototype.system_info import collect_hardware, collect_network

REGISTRATION_TOKEN_LIFETIME = timedelta(minutes=30)
# A user may hold a few live direct-download/app-link tokens at once, so a
# second download or a "Link this device" tap does not silently invalidate an
# agent that was already downloaded. Older extras are revoked.
MAX_PENDING_DIRECT_TOKENS = 5
SPECIFICATION_KEYS = {
    "cpu_name",
    "ram_capacity_bytes",
    "ram_usage_bytes",
    "cpu_cores",
    "storage_devices",
    "storage_total_bytes",
    "storage_available_bytes",
    "gpu_information",
    "motherboard_brand",
    "operating_system_name",
    "operating_system_version",
    "network_adapters",
    "ip_addresses",
}
OPTIONAL_SPECIFICATION_KEYS = {"mac_address"}
# Types an enrollment agent may report (desktop agents and the mobile apps).
AGENT_DEVICE_TYPES = {"Desktop", "Laptop", "Phone", "Tablet"}
# Types a user may choose when adding or editing a device manually.
MANUAL_DEVICE_TYPES = {"Desktop", "Laptop", "Server", "Workstation", "Phone", "Tablet", "Other"}
EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)


class ValidationError(ValueError):
    """Raised when submitted data fails application validation."""


class RegistrationTokenError(ValidationError):
    """Raised when a one-time device enrollment token cannot be accepted."""


class DatabaseSetupError(RuntimeError):
    """Raised when required seed data is missing from the database."""


def hash_password(password):
    """Hash new passwords with bcrypt while accepting legacy Werkzeug hashes."""
    if not isinstance(password, str):
        raise ValidationError("Password must be text.")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password, password_hash):
    if not isinstance(password, str) or not isinstance(password_hash, str):
        return False
    if password_hash.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
        except (ValueError, TypeError):
            return False
    try:
        return check_password_hash(password_hash, password)
    except (ValueError, TypeError):
        return False


def validate_password(password):
    if not isinstance(password, str) or not 8 <= len(password) <= 16:
        raise ValidationError("Password must be 8-16 characters long.")
    if not any("A" <= char <= "Z" for char in password):
        raise ValidationError("Password must include at least one capital letter.")
    if not any(not char.isalnum() and not char.isspace() for char in password):
        raise ValidationError("Password must include at least one special character.")
    return password


def _text(data, key, *, required=False, limit):
    value = data.get(key)
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValidationError(f"{key.replace('_', ' ').capitalize()} must be text.")
    value = value.strip()
    if required and not value:
        raise ValidationError(f"{key.replace('_', ' ').capitalize()} is required.")
    if len(value) > limit:
        raise ValidationError(f"{key.replace('_', ' ').capitalize()} is too long.")
    return value or None


def _required_text(data, key, limit):
    value = _text(data, key, required=True, limit=limit)
    if value is None:
        raise ValidationError(f"{key.replace('_', ' ').capitalize()} is required.")
    return value


def validate_contact_message(data):
    """Clean a "Contact us" submission from the public homepage."""
    name = _required_text(data, "name", limit=120)
    email = _required_text(data, "email", limit=254)
    if not EMAIL_PATTERN.fullmatch(email):
        raise ValidationError("Enter a valid email address so we can reply.")
    subject = _required_text(data, "subject", limit=150)
    message = _required_text(data, "message", limit=4000)
    if len(message) < 10:
        raise ValidationError("Please write a little more in your message.")
    if any(character in value for value in (name, email, subject) for character in "\r\n"):
        raise ValidationError("Name, email and subject must each be a single line.")
    return {"name": name, "email": email, "subject": subject, "message": message}


def _role(name):
    role = Role.query.filter_by(name=name).one_or_none()
    if role is None:
        raise DatabaseSetupError(
            "Database roles are missing; run "
            "`flask --app device_monitoring_prototype.app init-db` from the repository root."
        )
    return role


def _log(event_type, entity_type=None, entity_id=None, details=None):
    from flask_login import current_user

    actor_id = current_user.id if current_user.is_authenticated else None
    db.session.add(
        ActivityLog(
            actor_user_id=actor_id,
            event_type=event_type,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
        )
    )


def _log_device_event(device, event):
    db.session.add(Log(device=device, event=event))


def create_user(data, *, role_name="User"):
    full_name = _required_text(data, "full_name", limit=120)
    username = _required_text(data, "username", limit=64)
    email = _required_text(data, "email", limit=254).lower()
    password = data.get("password")
    validate_password(password)
    confirm_password = data.get("confirm_password")
    if not isinstance(confirm_password, str) or password != confirm_password:
        raise ValidationError("Passwords do not match.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
        raise ValidationError("Username must be 3-64 letters, numbers, dots, dashes, or underscores.")
    if username.casefold() == "admin":
        raise ValidationError("The username 'admin' is reserved for the system Administrator.")
    if not EMAIL_PATTERN.fullmatch(email):
        raise ValidationError("Enter a valid email address.")
    if User.query.filter(
        or_(User.username == username, db.func.lower(User.email) == email)
    ).first():
        raise ValidationError("That username or email address is already registered.")

    user = User(
        full_name=full_name,
        username=username,
        email=email,
        password_hash=hash_password(password),
        status="active",
        email_verified=True,
    )
    user.roles.append(_role(role_name))
    db.session.add(user)
    try:
        db.session.flush()
        _log("user.created", "user", user.id)
        db.session.commit()
    except IntegrityError as error:
        db.session.rollback()
        raise ValidationError("That username or email address is already registered.") from error
    return user


def update_user(user, data):
    if user.username.casefold() == "admin":
        raise ValidationError("The system Administrator account cannot be changed here.")
    if "full_name" in data:
        user.full_name = _required_text(data, "full_name", limit=120)
    if "email" in data:
        email = _required_text(data, "email", limit=254).lower()
        if not EMAIL_PATTERN.fullmatch(email):
            raise ValidationError("Enter a valid email address.")
        if User.query.filter(
            db.func.lower(User.email) == email, User.id != user.id
        ).first():
            raise ValidationError("That email address is already registered.")
        user.email = email
    if "role" in data:
        role_name = data["role"]
        if not isinstance(role_name, str) or role_name not in {"Administrator", "User"}:
            raise ValidationError("Role must be Administrator or User.")
        if user.is_admin and role_name != "Administrator" and user.status == "active":
            active_admins = (
                User.query.join(User.roles)
                .filter(Role.name == "Administrator", User.status == "active")
                .count()
            )
            if active_admins <= 1:
                raise ValidationError("The final administrator cannot be demoted.")
        user.roles = [_role(role_name)]
    if "status" in data:
        status = data["status"]
        if not isinstance(status, str) or status not in {"active", "inactive", "locked"}:
            raise ValidationError("Invalid account status.")
        if user.is_admin and user.status == "active" and status != "active":
            active_admins = (
                User.query.join(User.roles)
                .filter(Role.name == "Administrator", User.status == "active")
                .count()
            )
            if active_admins <= 1:
                raise ValidationError("The final administrator cannot be deactivated.")
        user.status = status
    _log("user.updated", "user", user.id)
    try:
        db.session.commit()
    except IntegrityError as error:
        db.session.rollback()
        raise ValidationError("That email address is already registered.") from error
    return user


def deactivate_user(user):
    if user.username.casefold() == "admin":
        raise ValidationError("The system Administrator account cannot be deactivated.")
    active_admins = (
        User.query.join(User.roles)
        .filter(Role.name == "Administrator", User.status == "active")
        .count()
    )
    if user.is_admin and user.status == "active" and active_admins <= 1:
        raise ValidationError("The final administrator cannot be deactivated.")
    user.status = "inactive"
    _log("user.deactivated", "user", user.id)
    db.session.commit()


def create_device(owner, data):
    name = _required_text(data, "name", limit=120)
    hostname = _text(data, "hostname", limit=255) or name
    device_type = _required_text(data, "type", limit=64)
    operating_system = _required_text(data, "os", limit=120)
    if device_type not in MANUAL_DEVICE_TYPES:
        raise ValidationError("Select a supported device type.")
    status = data.get("status", "unknown")
    status = status.strip().lower() if isinstance(status, str) else ""
    if status not in {"online", "offline", "maintenance", "unknown"}:
        raise ValidationError("Invalid device status.")

    device = Device(
        asset_tag=f"DM-{uuid.uuid4().hex[:16].upper()}",
        device_name=name,
        hostname=hostname,
        device_type=device_type,
        operating_system=operating_system,
        operating_system_version=operating_system,
        status=status,
        owner=owner,
        registered_by=owner,
    )
    device.hardware_spec = DeviceSpecification(**collect_hardware())
    device.network_records.append(NetworkRecord(**collect_network()))
    db.session.add(device)
    db.session.flush()
    _log_device_event(device, "Device registered")
    _log("device.created", "device", device.id)
    db.session.commit()
    return device


def issue_device_registration_token(user, *, revoke_unused=True):
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    if revoke_unused:
        DeviceRegistrationToken.query.filter_by(
            user_id=user.id,
            used_at=None,
            revoked_at=None,
        ).update(
            {"revoked_at": now},
            synchronize_session=False,
        )
    registration = DeviceRegistrationToken(
        token_hash=hashlib.sha256(token.encode("ascii")).hexdigest(),
        user=user,
        created_at=now,
        expires_at=now + REGISTRATION_TOKEN_LIFETIME,
    )
    db.session.add(registration)
    db.session.add(
        ActivityLog(
            actor=user,
            event_type="device.registration_token_created",
            entity_type="device_registration_token",
        )
    )
    db.session.commit()
    return token, registration.expires_at


def issue_direct_agent_download_token(user, *, channel="download"):
    """Issue an owner-confirmed token for a per-user agent build or app link.

    The QR flow confirmed the account and the download on a second device.
    Here the owner requests the agent (or a "Link this device" hand-off to an
    installed app) from their own authenticated, CSRF-protected session, so
    both confirmations are recorded at once. The token keeps the same
    one-use, hashed, short-lived guarantees.
    """
    if user.is_admin or user.status != "active":
        raise ValidationError("Device registration is only available to active standard users.")
    token, expires_at = issue_device_registration_token(user, revoke_unused=False)
    registration = find_valid_registration_token(token)
    now = datetime.now(timezone.utc)
    registration.verified_at = now
    registration.download_confirmed_at = now
    pending = (
        DeviceRegistrationToken.query.filter(
            DeviceRegistrationToken.user_id == user.id,
            DeviceRegistrationToken.used_at.is_(None),
            DeviceRegistrationToken.revoked_at.is_(None),
            DeviceRegistrationToken.id != registration.id,
        )
        .order_by(DeviceRegistrationToken.created_at.desc(), DeviceRegistrationToken.id.desc())
        .all()
    )
    for older in pending[MAX_PENDING_DIRECT_TOKENS - 1:]:
        older.revoked_at = now
    db.session.add(
        ActivityLog(
            actor=user,
            event_type=f"device.agent_direct_{channel}",
            entity_type="device_registration_token",
            entity_id=registration.id,
        )
    )
    db.session.commit()
    return token, expires_at


def pending_agent_enrollment(user):
    """Latest downloaded agent / app link that has not submitted a device yet."""
    now = datetime.now(timezone.utc)
    for registration in (
        DeviceRegistrationToken.query.filter(
            DeviceRegistrationToken.user_id == user.id,
            DeviceRegistrationToken.used_at.is_(None),
            DeviceRegistrationToken.revoked_at.is_(None),
            DeviceRegistrationToken.download_confirmed_at.isnot(None),
        )
        .order_by(DeviceRegistrationToken.created_at.desc(), DeviceRegistrationToken.id.desc())
        .limit(MAX_PENDING_DIRECT_TOKENS)
    ):
        expires_at = registration.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at > now:
            prepared_at = registration.download_confirmed_at
            if prepared_at.tzinfo is None:
                prepared_at = prepared_at.replace(tzinfo=timezone.utc)
            return {"prepared_at": prepared_at.isoformat(), "expires_at": expires_at.isoformat()}
    return None


def find_valid_registration_token(token):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", token):
        return None
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    registration = DeviceRegistrationToken.query.filter_by(
        token_hash=token_hash,
        used_at=None,
        revoked_at=None,
    ).one_or_none()
    if registration is None:
        return None
    expires_at = registration.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        return None
    return registration


def _inventory_text(specifications, key, limit):
    value = specifications.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(f"{key.replace('_', ' ').capitalize()} must be text.")
    value = value.strip()
    if len(value) > limit or any(ord(char) < 32 for char in value):
        raise ValidationError(f"{key.replace('_', ' ').capitalize()} is invalid or too long.")
    return value or None


def _inventory_bytes(specifications, key, *, nullable=False, maximum=2**63 - 1):
    value = specifications.get(key)
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValidationError(f"{key.replace('_', ' ').capitalize()} must be a non-negative integer.")
    return value


def validate_detected_specifications(specifications):
    if (
        not isinstance(specifications, dict)
        or not SPECIFICATION_KEYS.issubset(specifications)
        or set(specifications) - SPECIFICATION_KEYS - OPTIONAL_SPECIFICATION_KEYS
    ):
        raise ValidationError("Detected specifications are incomplete or contain unsupported fields.")

    cpu_name = _inventory_text(specifications, "cpu_name", 255)
    motherboard_brand = _inventory_text(specifications, "motherboard_brand", 120)
    os_name = _inventory_text(specifications, "operating_system_name", 120)
    os_version = _inventory_text(specifications, "operating_system_version", 255)
    mac_address = _inventory_text(specifications, "mac_address", 17)
    if mac_address and not re.fullmatch(
        r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac_address
    ):
        raise ValidationError("MAC address must use the format 00:11:22:33:44:55.")
    if mac_address:
        mac_address = mac_address.upper()
    gpu_values = specifications.get("gpu_information")
    if not isinstance(gpu_values, list) or len(gpu_values) > 32:
        raise ValidationError("GPU information must be a list of at most 32 names.")
    gpu_information = []
    for value in gpu_values:
        if not isinstance(value, str) or not value.strip() or len(value.strip()) > 255:
            raise ValidationError("GPU information contains an invalid name.")
        gpu_information.append(value.strip())

    cores = specifications.get("cpu_cores")
    if cores is not None and (
        isinstance(cores, bool) or not isinstance(cores, int) or not 0 <= cores <= 512
    ):
        raise ValidationError("CPU core count must be an integer from 0 to 512.")
    ram_capacity = _inventory_bytes(
        specifications, "ram_capacity_bytes", nullable=True
    )
    ram_usage = _inventory_bytes(specifications, "ram_usage_bytes", nullable=True)
    if ram_capacity is not None and ram_usage is not None and ram_usage > ram_capacity:
        raise ValidationError("RAM usage cannot exceed RAM capacity.")

    storage_devices = specifications.get("storage_devices")
    if not isinstance(storage_devices, list) or len(storage_devices) > 64:
        raise ValidationError("Storage devices must be a list of at most 64 items.")
    validated_storage = []
    for device in storage_devices:
        if not isinstance(device, dict) or set(device) != {
            "name", "total_bytes", "available_bytes"
        }:
            raise ValidationError("A storage device contains unsupported or missing fields.")
        name = device["name"]
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 128:
            raise ValidationError("A storage device name is invalid.")
        total = _inventory_bytes(device, "total_bytes")
        available = _inventory_bytes(device, "available_bytes")
        if available > total:
            raise ValidationError("Available storage cannot exceed total storage.")
        validated_storage.append(
            {"name": name.strip(), "total_bytes": total, "available_bytes": available}
        )

    storage_total = _inventory_bytes(specifications, "storage_total_bytes")
    storage_available = _inventory_bytes(specifications, "storage_available_bytes")
    if (
        storage_total != sum(item["total_bytes"] for item in validated_storage)
        or storage_available
        != sum(item["available_bytes"] for item in validated_storage)
    ):
        raise ValidationError("Storage totals do not match the listed storage devices.")

    adapters = specifications.get("network_adapters")
    if not isinstance(adapters, list) or len(adapters) > 64:
        raise ValidationError("Network adapters must be a list of at most 64 names.")
    network_adapters = []
    for adapter in adapters:
        if not isinstance(adapter, str) or not adapter.strip() or len(adapter.strip()) > 128:
            raise ValidationError("A network adapter name is invalid.")
        network_adapters.append(adapter.strip())

    addresses = specifications.get("ip_addresses")
    if not isinstance(addresses, list) or len(addresses) > 64:
        raise ValidationError("IP addresses must be a list of at most 64 addresses.")
    ip_addresses = []
    for address in addresses:
        if not isinstance(address, str) or len(address) > 45:
            raise ValidationError("An IP address is invalid.")
        try:
            normalized = str(ipaddress.ip_address(address))
        except ValueError as error:
            raise ValidationError("An IP address is invalid.") from error
        if normalized not in ip_addresses:
            ip_addresses.append(normalized)

    return {
        "cpu_name": cpu_name,
        "ram_capacity_bytes": ram_capacity,
        "ram_usage_bytes": ram_usage,
        "cpu_cores": cores,
        "storage_devices": validated_storage,
        "storage_total_bytes": storage_total,
        "storage_available_bytes": storage_available,
        "gpu_information": gpu_information,
        "motherboard_brand": motherboard_brand,
        "operating_system_name": os_name,
        "operating_system_version": os_version,
        "network_adapters": network_adapters,
        "ip_addresses": ip_addresses,
        "mac_address": mac_address,
    }


def register_agent_device(token, data):
    if not isinstance(data, dict) or set(data) != {
        "name", "device_type", "specifications"
    }:
        raise ValidationError("Registration must contain a device name, type, and specifications.")
    name = _required_text(data, "name", limit=120)
    device_type = data.get("device_type")
    if not isinstance(device_type, str) or device_type not in AGENT_DEVICE_TYPES:
        raise ValidationError("Device type must be Desktop, Laptop, Phone, or Tablet.")
    specifications = validate_detected_specifications(data["specifications"])

    registration = find_valid_registration_token(token)
    if registration is None or registration.user.status != "active":
        raise RegistrationTokenError(
            "This registration token is invalid, expired, or already used."
        )
    if registration.verified_at is None or registration.download_confirmed_at is None:
        raise RegistrationTokenError(
            "Verify the account and confirm the Device Agent download before registering a device."
        )

    now = datetime.now(timezone.utc)
    claim = db.session.execute(
        update(DeviceRegistrationToken)
        .where(
            DeviceRegistrationToken.id == registration.id,
            DeviceRegistrationToken.used_at.is_(None),
            DeviceRegistrationToken.revoked_at.is_(None),
            DeviceRegistrationToken.expires_at > now,
        )
        .values(used_at=now)
        .execution_options(synchronize_session=False)
    )
    if claim.rowcount != 1:
        db.session.rollback()
        raise RegistrationTokenError(
            "This registration token is invalid, expired, or already used."
        )

    user = registration.user
    device = Device(
        asset_tag=f"DM-{uuid.uuid4().hex[:16].upper()}",
        device_name=name,
        hostname=name,
        device_type=device_type,
        operating_system=specifications["operating_system_name"] or "Unknown",
        operating_system_version=specifications["operating_system_version"],
        mac_address=specifications["mac_address"],
        status="online" if specifications["ip_addresses"] else "unknown",
        last_seen_at=now if specifications["ip_addresses"] else None,
        is_verified=True,
        owner=user,
        registered_by=user,
        hardware_spec=DeviceSpecification(
            cpu_model=specifications["cpu_name"],
            cpu_cores=specifications["cpu_cores"],
            memory_bytes=specifications["ram_capacity_bytes"],
            ram_usage_bytes=specifications["ram_usage_bytes"],
            storage_bytes=specifications["storage_total_bytes"],
            storage_available_bytes=specifications["storage_available_bytes"],
            storage_devices=specifications["storage_devices"],
            gpu_model=", ".join(specifications["gpu_information"]) or None,
            motherboard_model=specifications["motherboard_brand"],
            motherboard_brand=specifications["motherboard_brand"],
            operating_system_name=specifications["operating_system_name"],
            operating_system_version=specifications["operating_system_version"],
            network_adapters=specifications["network_adapters"],
            ip_addresses=specifications["ip_addresses"],
        ),
    )
    if specifications["ip_addresses"]:
        device.network_records.append(
            NetworkRecord(
                ip_address=specifications["ip_addresses"][0],
                connectivity_status="connected",
            )
        )
    db.session.add(device)
    db.session.flush()
    registration.device = device
    registration.mac_address = device.mac_address
    _log_device_event(device, "Device registered with QR-based agent")
    db.session.add(
        ActivityLog(
            actor=user,
            event_type="device.registered_by_agent",
            entity_type="device",
            entity_id=device.id,
            details={"registration_token_id": registration.id},
        )
    )
    try:
        db.session.commit()
    except IntegrityError as error:
        db.session.rollback()
        raise ValidationError("The device could not be registered; review the information and try again.") from error
    return device


def update_device(device, data):
    if "name" in data:
        device.device_name = _required_text(data, "name", limit=120)
    if "hostname" in data:
        device.hostname = _required_text(data, "hostname", limit=255)
    if "type" in data:
        device_type = _required_text(data, "type", limit=64)
        if device_type not in MANUAL_DEVICE_TYPES:
            raise ValidationError("Select a supported device type.")
        device.device_type = device_type
    if "os" in data:
        device.operating_system = _required_text(data, "os", limit=120)
    if "status" in data:
        status = data["status"]
        if not isinstance(status, str) or status.lower() not in {
            "online", "offline", "maintenance", "unknown"
        }:
            raise ValidationError("Invalid device status.")
        device.status = status.lower()
    _log_device_event(device, "Device updated")
    _log("device.updated", "device", device.id)
    db.session.commit()
    return device


def archive_device(device):
    if device.lifecycle_status != "active":
        raise ValidationError("Only active devices can be archived.")
    from flask_login import current_user

    device.lifecycle_status = "archived"
    device.archived_at = db.func.current_timestamp()
    device.archived_by_user_id = (
        current_user.id if current_user.is_authenticated else None
    )
    _log_device_event(device, "Device archived")
    _log("device.archived", "device", device.id)
    db.session.commit()


def restore_device(device):
    if device.lifecycle_status != "archived":
        raise ValidationError("Only archived devices can be restored.")
    device.lifecycle_status = "active"
    device.archived_at = None
    device.archived_by_user_id = None
    if device.status == "retired":
        device.status = "unknown"
    _log_device_event(device, "Device restored")
    _log("device.restored", "device", device.id)
    db.session.commit()


def soft_delete_device(device):
    if device.lifecycle_status == "deleted":
        raise ValidationError("This device is already deleted.")
    device.lifecycle_status = "deleted"
    device.deleted_at = db.func.current_timestamp()
    _log_device_event(device, "Device marked deleted")
    _log("device.deleted", "device", device.id)
    db.session.commit()

