"""Flask-SQLAlchemy models for the device monitoring system."""
###
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, UniqueConstraint, func


db = SQLAlchemy()
ID_TYPE = db.BigInteger().with_variant(db.Integer, "sqlite")

user_roles = db.Table(
    "user_roles",
    db.Column(
        "user_id",
        ID_TYPE,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "role_id",
        ID_TYPE,
        db.ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

role_permissions = db.Table(
    "role_permissions",
    db.Column(
        "role_id",
        ID_TYPE,
        db.ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "permission_id",
        ID_TYPE,
        db.ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'inactive', 'locked')",
            name="ck_users_status",
        ),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    username = db.Column(db.String(64), nullable=False, unique=True)
    email = db.Column(db.String(254), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(120))
    status = db.Column(db.String(16), nullable=False, server_default="active")
    email_verified = db.Column(db.Boolean, nullable=False, server_default="0")
    email_verified_at = db.Column(db.DateTime(timezone=True))
    totp_enabled = db.Column(db.Boolean, nullable=False, server_default="0")
    totp_secret_encrypted = db.Column(db.Text)
    totp_verified_at = db.Column(db.DateTime(timezone=True))
    totp_last_counter = db.Column(db.BigInteger)
    totp_attempts = db.Column(db.Integer, nullable=False, server_default="0")
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )
    last_login_at = db.Column(db.DateTime(timezone=True))

    roles = db.relationship("Role", secondary=user_roles, back_populates="users")

    @property
    def full_name(self):
        return self.display_name

    @full_name.setter
    def full_name(self, value):
        self.display_name = value

    @property
    def role_name(self):
        return "Administrator" if self.is_admin else "User"

    @property
    def is_admin(self):
        return self.username.casefold() == "admin" or any(
            role.name == "Administrator" for role in self.roles
        )

    @property
    def is_active(self):
        return self.email_verified and (self.is_admin or self.status == "active")

    owned_devices = db.relationship(
        "Device", foreign_keys="Device.owner_user_id", back_populates="owner"
    )
    registered_devices = db.relationship(
        "Device", foreign_keys="Device.registered_by_user_id", back_populates="registered_by"
    )
    registration_tokens = db.relationship(
        "DeviceRegistrationToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    diagnostic_runs = db.relationship("DiagnosticRun", back_populates="initiated_by")
    activity_logs = db.relationship("ActivityLog", back_populates="actor")


class RegistrationChallenge(db.Model):
    __tablename__ = "registration_challenges"
    __table_args__ = (
        db.Index("ix_registration_challenges_email_created", "email", "created_at"),
        db.Index("ix_registration_challenges_expiry", "expires_at"),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(254), nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255))
    email_code_hash = db.Column(db.String(64))
    email_code_expires_at = db.Column(db.DateTime(timezone=True))
    email_verified_at = db.Column(db.DateTime(timezone=True))
    totp_secret_encrypted = db.Column(db.Text)
    totp_verified_at = db.Column(db.DateTime(timezone=True))
    totp_last_counter = db.Column(db.BigInteger)
    email_attempts = db.Column(db.Integer, nullable=False, server_default="0")
    totp_attempts = db.Column(db.Integer, nullable=False, server_default="0")
    email_send_count = db.Column(db.Integer, nullable=False, server_default="1")
    last_email_sent_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    completed_at = db.Column(db.DateTime(timezone=True))


class EmailVerification(db.Model):
    __tablename__ = "email_verifications"
    __table_args__ = (
        db.Index(
            "ix_email_verifications_challenge_created",
            "registration_challenge_id",
            "created_at",
        ),
        db.Index("ix_email_verifications_email_created", "email", "created_at"),
        db.Index("ix_email_verifications_expiry", "expires_at"),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    registration_challenge_id = db.Column(
        ID_TYPE,
        db.ForeignKey("registration_challenges.id", ondelete="CASCADE"),
        nullable=False,
    )
    email = db.Column(db.String(254), nullable=False)
    verification_code = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    verified = db.Column(db.Boolean, nullable=False, server_default="0")
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    used_at = db.Column(db.DateTime(timezone=True))

    registration_challenge = db.relationship(
        "RegistrationChallenge",
        backref=db.backref("email_verifications", cascade="all, delete-orphan"),
    )


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(ID_TYPE, primary_key=True)
    name = db.Column(db.String(64), nullable=False, unique=True)
    description = db.Column(db.String(255))
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    users = db.relationship("User", secondary=user_roles, back_populates="roles")
    permissions = db.relationship(
        "Permission", secondary=role_permissions, back_populates="roles"
    )


class Permission(db.Model):
    __tablename__ = "permissions"

    id = db.Column(ID_TYPE, primary_key=True)
    code = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(255))

    roles = db.relationship(
        "Role", secondary=role_permissions, back_populates="permissions"
    )


class Device(db.Model):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint(
            "status IN ('online', 'offline', 'maintenance', 'retired', 'unknown')",
            name="ck_devices_status",
        ),
        CheckConstraint(
            "lifecycle_status IN ('active', 'archived', 'deleted')",
            name="ck_devices_lifecycle_status",
        ),
        db.Index("ix_devices_owner_status", "owner_user_id", "status"),
        db.Index("ix_devices_lifecycle_owner", "lifecycle_status", "owner_user_id"),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    asset_tag = db.Column(db.String(64), nullable=False, unique=True)
    device_name = db.Column(db.String(120), nullable=False)
    hostname = db.Column(db.String(255), nullable=False)
    device_type = db.Column(db.String(64), nullable=False)
    serial_number = db.Column(db.String(128), unique=True)
    manufacturer = db.Column(db.String(120))
    model = db.Column(db.String(120))
    operating_system = db.Column(db.String(120))
    operating_system_version = db.Column(db.String(120))
    status = db.Column(db.String(16), nullable=False, server_default="unknown")
    is_verified = db.Column(db.Boolean, nullable=False, server_default=db.false())
    lifecycle_status = db.Column(
        db.String(16), nullable=False, server_default="active"
    )
    archived_at = db.Column(db.DateTime(timezone=True))
    archived_by_user_id = db.Column(
        ID_TYPE, db.ForeignKey("users.id", ondelete="SET NULL")
    )
    deleted_at = db.Column(db.DateTime(timezone=True))
    owner_user_id = db.Column(
        ID_TYPE, db.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    registered_by_user_id = db.Column(
        ID_TYPE, db.ForeignKey("users.id", ondelete="SET NULL")
    )
    registered_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )
    last_seen_at = db.Column(db.DateTime(timezone=True))

    owner = db.relationship(
        "User", foreign_keys=[owner_user_id], back_populates="owned_devices"
    )
    registered_by = db.relationship(
        "User", foreign_keys=[registered_by_user_id], back_populates="registered_devices"
    )
    hardware_spec = db.relationship(
        "DeviceSpecification",
        back_populates="device",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    registration_token = db.relationship(
        "DeviceRegistrationToken", back_populates="device", uselist=False
    )
    network_interfaces = db.relationship(
        "NetworkInterface",
        back_populates="device",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    network_records = db.relationship(
        "NetworkRecord",
        back_populates="device",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    logs = db.relationship(
        "Log",
        back_populates="device",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    diagnostic_runs = db.relationship(
        "DiagnosticRun",
        back_populates="device",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    metric_samples = db.relationship(
        "DeviceMetric",
        back_populates="device",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class DeviceSpecification(db.Model):
    __tablename__ = "device_specifications"
    __table_args__ = (
        CheckConstraint(
            "cpu_cores IS NULL OR (cpu_cores >= 0 AND cpu_cores <= 512)",
            name="ck_device_specifications_cpu_cores",
        ),
        CheckConstraint(
            "memory_bytes IS NULL OR memory_bytes >= 0",
            name="ck_device_specifications_memory",
        ),
        CheckConstraint(
            "ram_usage_bytes IS NULL OR (ram_usage_bytes >= 0 AND "
            "(memory_bytes IS NULL OR ram_usage_bytes <= memory_bytes))",
            name="ck_device_specifications_ram_usage",
        ),
        CheckConstraint(
            "storage_bytes IS NULL OR storage_bytes >= 0",
            name="ck_device_specifications_storage",
        ),
        CheckConstraint(
            "storage_available_bytes IS NULL OR (storage_available_bytes >= 0 AND "
            "(storage_bytes IS NULL OR storage_available_bytes <= storage_bytes))",
            name="ck_device_specifications_storage_available",
        ),
    )

    device_id = db.Column(
        ID_TYPE,
        db.ForeignKey("devices.id", ondelete="CASCADE"),
        primary_key=True,
    )
    cpu_model = db.Column(db.String(255))
    cpu_cores = db.Column(db.SmallInteger)
    cpu_threads = db.Column(db.SmallInteger)
    memory_bytes = db.Column(ID_TYPE)
    ram_usage_bytes = db.Column(ID_TYPE)
    storage_bytes = db.Column(ID_TYPE)
    storage_available_bytes = db.Column(ID_TYPE)
    storage_devices = db.Column(db.JSON)
    gpu_model = db.Column(db.String(255))
    bios_version = db.Column(db.String(120))
    motherboard_model = db.Column(db.String(120))
    motherboard_brand = db.Column(db.String(120))
    operating_system_name = db.Column(db.String(120))
    operating_system_version = db.Column(db.String(255))
    network_adapters = db.Column(db.JSON)
    ip_addresses = db.Column(db.JSON)
    collected_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    device = db.relationship("Device", back_populates="hardware_spec")


class DeviceRegistrationToken(db.Model):
    __tablename__ = "device_registration_tokens"
    __table_args__ = (
        db.Index("ix_device_registration_tokens_user_expiry", "user_id", "expires_at"),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True)
    user_id = db.Column(
        ID_TYPE, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    device_id = db.Column(
        ID_TYPE, db.ForeignKey("devices.id", ondelete="SET NULL"), unique=True
    )
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    verified_at = db.Column(db.DateTime(timezone=True))
    download_confirmed_at = db.Column(db.DateTime(timezone=True))
    used_at = db.Column(db.DateTime(timezone=True))
    revoked_at = db.Column(db.DateTime(timezone=True))

    user = db.relationship("User", back_populates="registration_tokens")
    device = db.relationship("Device", back_populates="registration_token")


class NetworkInterface(db.Model):
    __tablename__ = "network_interfaces"
    __table_args__ = (
        UniqueConstraint("device_id", "interface_name", name="uq_interface_device_name"),
        db.Index("ix_network_interfaces_mac", "mac_address"),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    device_id = db.Column(
        ID_TYPE,
        db.ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    interface_name = db.Column(db.String(128), nullable=False)
    mac_address = db.Column(db.String(17))
    interface_type = db.Column(db.String(32))
    is_primary = db.Column(db.Boolean, nullable=False, server_default=db.false())
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    device = db.relationship("Device", back_populates="network_interfaces")
    observations = db.relationship(
        "NetworkObservation",
        back_populates="interface",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class NetworkObservation(db.Model):
    __tablename__ = "network_observations"
    __table_args__ = (
        db.Index("ix_network_observations_interface_time", "interface_id", "observed_at"),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    interface_id = db.Column(
        ID_TYPE,
        db.ForeignKey("network_interfaces.id", ondelete="CASCADE"),
        nullable=False,
    )
    ip_address = db.Column(db.String(45))
    subnet_prefix = db.Column(db.SmallInteger)
    gateway = db.Column(db.String(45))
    dns_servers = db.Column(db.JSON)
    ssid = db.Column(db.String(255))
    connection_type = db.Column(db.String(32))
    observed_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    interface = db.relationship("NetworkInterface", back_populates="observations")


class NetworkRecord(db.Model):
    __tablename__ = "network_records"
    __table_args__ = (
        CheckConstraint(
            "connectivity_status IN ('connected', 'disconnected', 'unknown')",
            name="ck_network_records_connectivity",
        ),
        db.Index("ix_network_records_device_time", "device_id", "recorded_at"),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    device_id = db.Column(
        ID_TYPE,
        db.ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    ip_address = db.Column(db.String(45))
    subnet_mask = db.Column(db.String(45))
    default_gateway = db.Column(db.String(45))
    dns_server = db.Column(db.String(255))
    connectivity_status = db.Column(
        db.String(16), nullable=False, server_default="unknown"
    )
    recorded_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    device = db.relationship("Device", back_populates="network_records")


class DiagnosticRun(db.Model):
    __tablename__ = "diagnostic_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'completed', 'failed', 'cancelled')",
            name="ck_diagnostic_runs_status",
        ),
        db.Index("ix_diagnostic_runs_device_started", "device_id", "started_at"),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    device_id = db.Column(
        ID_TYPE,
        db.ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    initiated_by_user_id = db.Column(
        ID_TYPE, db.ForeignKey("users.id", ondelete="SET NULL")
    )
    status = db.Column(db.String(16), nullable=False, server_default="running")
    summary = db.Column(db.Text)
    detected_problem = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    started_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    finished_at = db.Column(db.DateTime(timezone=True))

    device = db.relationship("Device", back_populates="diagnostic_runs")
    initiated_by = db.relationship("User", back_populates="diagnostic_runs")
    checks = db.relationship(
        "DiagnosticCheck",
        back_populates="run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class DiagnosticCheck(db.Model):
    __tablename__ = "diagnostic_checks"
    __table_args__ = (
        CheckConstraint(
            "status IN ('passed', 'warning', 'failed', 'skipped')",
            name="ck_diagnostic_checks_status",
        ),
        UniqueConstraint("run_id", "check_name", name="uq_diagnostic_check_run_name"),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    run_id = db.Column(
        ID_TYPE,
        db.ForeignKey("diagnostic_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    check_name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(16), nullable=False)
    result_summary = db.Column(db.Text)
    details = db.Column(db.JSON)
    measured_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    run = db.relationship("DiagnosticRun", back_populates="checks")


class DeviceMetric(db.Model):
    __tablename__ = "device_metrics"
    __table_args__ = (
        CheckConstraint(
            "cpu_percent IS NULL OR (cpu_percent >= 0 AND cpu_percent <= 100)",
            name="ck_device_metrics_cpu_percent",
        ),
        CheckConstraint(
            "memory_percent IS NULL OR (memory_percent >= 0 AND memory_percent <= 100)",
            name="ck_device_metrics_memory_percent",
        ),
        CheckConstraint(
            "storage_percent IS NULL OR (storage_percent >= 0 AND storage_percent <= 100)",
            name="ck_device_metrics_storage_percent",
        ),
        db.Index("ix_device_metrics_device_time", "device_id", "collected_at"),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    device_id = db.Column(
        ID_TYPE,
        db.ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    cpu_percent = db.Column(db.Numeric(5, 2))
    memory_percent = db.Column(db.Numeric(5, 2))
    storage_percent = db.Column(db.Numeric(5, 2))
    memory_used_bytes = db.Column(ID_TYPE)
    storage_used_bytes = db.Column(ID_TYPE)
    network_rx_bytes = db.Column(ID_TYPE)
    network_tx_bytes = db.Column(ID_TYPE)
    collected_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    device = db.relationship("Device", back_populates="metric_samples")


class ActivityLog(db.Model):
    __tablename__ = "activity_logs"
    __table_args__ = (
        db.Index("ix_activity_logs_actor_time", "actor_user_id", "occurred_at"),
        db.Index("ix_activity_logs_entity", "entity_type", "entity_id"),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    actor_user_id = db.Column(
        ID_TYPE, db.ForeignKey("users.id", ondelete="SET NULL")
    )
    event_type = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(64))
    entity_id = db.Column(ID_TYPE)
    details = db.Column(db.JSON)
    occurred_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    actor = db.relationship("User", back_populates="activity_logs")


class Log(db.Model):
    """A device-specific event shown in the device's history."""

    __tablename__ = "logs"
    __table_args__ = (
        db.Index("ix_logs_device_timestamp", "device_id", "timestamp"),
    )

    id = db.Column(ID_TYPE, primary_key=True)
    device_id = db.Column(
        ID_TYPE,
        db.ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    event = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    device = db.relationship("Device", back_populates="logs")
