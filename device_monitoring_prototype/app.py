"""Flask application with database-backed accounts and device inventory."""

import os
import re
import secrets
import uuid
import base64
import hashlib
import io
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit
#
import click
from device_monitoring_prototype.agent_builder import (
    DeviceAgentBuildError,
    build_agent_executable,
)
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from dotenv import load_dotenv
import qrcode
from qrcode.image.svg import SvgPathImage
from sqlalchemy import (
    CheckConstraint,
    String,
    UniqueConstraint,
    and_,
    cast,
    func,
    inspect as sqlalchemy_inspect,
    or_,
    select,
)
from sqlalchemy.exc import SQLAlchemyError
from device_monitoring_prototype.authentication import (
    EmailDeliveryError,
    cancel_registration,
    check_smtp_connection,
    complete_registration,
    resend_email_code,
    start_registration,
    verify_email_code,
    verify_login_totp,
    verify_registration_totp,
)
from device_monitoring_prototype.diagnostics import (
    REPORT_LIMIT_BYTES,
    DiagnosticValidationError,
    complete_diagnostic_run,
    create_diagnostic_run,
    diagnostic_run_payload,
)
from device_monitoring_prototype.models import (
    ActivityLog,
    Device,
    DeviceRegistrationToken,
    DiagnosticRun,
    DeviceSpecification,
    Log,
    NetworkRecord,
    Permission,
    RegistrationChallenge,
    Role,
    User,
    db,
)
from device_monitoring_prototype.services import (
    DatabaseSetupError,
    ValidationError,
    archive_device,
    create_device,
    create_user,
    deactivate_user,
    record_diagnostic,
    find_valid_registration_token,
    issue_device_registration_token,
    hash_password,
    register_agent_device,
    RegistrationTokenError,
    restore_device,
    soft_delete_device,
    validate_password,
    verify_password,
    update_device,
    update_user,
)


def diagnostic_sort_key(run):
    return (run.finished_at or run.started_at, run.id)


def latest_completed_diagnostic(device):
    return max(
        (run for run in device.diagnostic_runs if run.status == "completed"),
        key=diagnostic_sort_key,
        default=None,
    )


login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "warning"
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"


def _database_uri():
    """Build the MySQL connection string from environment settings."""
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    # XAMPP's local MySQL defaults are root, localhost, and port 3306.
    user = quote(os.environ.get("MYSQL_USER", "root"), safe="")
    password = quote(os.environ.get("MYSQL_PASSWORD", ""), safe="")
    host = os.environ.get("MYSQL_HOST", "localhost")
    port = os.environ.get("MYSQL_PORT", "3306")
    database = quote(os.environ.get("MYSQL_DATABASE", "devmonitor"), safe="")
    return f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}?charset=utf8mb4"


def _database_error_message(error):
    original = getattr(error, "orig", None)
    arguments = getattr(original, "args", ())
    code = arguments[0] if arguments and isinstance(arguments[0], int) else None
    description = str(original or "").lower()

    if code in {1051, 1054, 1146} or any(
        marker in description
        for marker in (
            "no such table",
            "no such column",
            "doesn't exist",
            "unknown column",
        )
    ):
        return (
            "The database schema is incomplete. Back up the database and apply the "
            "required migrations from the project README; `init-db` creates missing "
            "tables but does not update existing tables."
        )
    if code == 1045:
        return (
            "MySQL rejected the configured credentials. Check MYSQL_USER and "
            "MYSQL_PASSWORD in device_monitoring_prototype\\.env."
        )
    if code == 1049:
        return (
            "The configured MySQL database does not exist. Check MYSQL_DATABASE in "
            "device_monitoring_prototype\\.env and create the database before setup."
        )
    return (
        "The database is unavailable. Check that MySQL is running and verify the "
        "connection settings in device_monitoring_prototype\\.env."
    )


def create_app(test_config=None):
    project_dir = Path(__file__).resolve().parent
    load_dotenv(dotenv_path=project_dir / ".env")
    app = Flask(
        __name__,
        template_folder=str(project_dir / "templates"),
        static_folder=str(project_dir / "static"),
    )
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        PUBLIC_BASE_URL=os.environ.get("PUBLIC_BASE_URL", "").rstrip("/"),
        TOTP_ENCRYPTION_KEY=os.environ.get("TOTP_ENCRYPTION_KEY"),
        MAIL_SERVER=os.environ.get("MAIL_SERVER"),
        MAIL_PORT=int(os.environ.get("MAIL_PORT", "587")),
        MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
        MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
        MAIL_DEFAULT_SENDER=os.environ.get("MAIL_DEFAULT_SENDER"),
        MAIL_USE_TLS=os.environ.get("MAIL_USE_TLS", "true").lower() == "true",
        MAIL_TIMEOUT=int(os.environ.get("MAIL_TIMEOUT", "15")),
        SQLALCHEMY_DATABASE_URI=_database_uri(),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "").lower() == "true",
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "").lower() == "true",
        MAX_CONTENT_LENGTH=1024 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    if not os.environ.get("SECRET_KEY") and not app.testing:
        app.logger.warning("SECRET_KEY is unset; configure a persistent random secret in production.")

    # Connect the shared SQLAlchemy extension after the app has loaded its settings.
    db.init_app(app)
    login_manager.init_app(app)

    @app.errorhandler(SQLAlchemyError)
    def handle_database_error(error):
        db.session.rollback()
        original = getattr(error, "orig", None)
        arguments = getattr(original, "args", ())
        code = arguments[0] if arguments and isinstance(arguments[0], int) else None
        app.logger.error(
            "Database request failed (%s, code=%s).",
            type(error).__name__,
            code,
        )
        message = _database_error_message(error)
        if request.path.startswith("/api/"):
            return jsonify(error=message), 503
        return render_template("service_unavailable.html", message=message), 503

    @app.errorhandler(403)
    def handle_forbidden(error):
        message = "Administrator access is required for this action."
        if request.path.startswith("/api/"):
            return jsonify(error=message), 403
        return render_template("access_denied.html", message=message), 403

    @login_manager.unauthorized_handler
    def handle_unauthorized():
        if request.path.startswith("/api/"):
            return jsonify(error="Authentication required."), 401
        return redirect(url_for("login", next=request.url))

    @login_manager.user_loader
    def load_user(user_id):
        try:
            user = db.session.get(User, int(user_id))
            return user if user and user.email_verified else None
        except (TypeError, ValueError):
            return None

    @app.before_request
    def validate_csrf():
        if current_user.is_authenticated and not current_user.is_active:
            logout_user()
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify(error="This account is inactive."), 401
            return redirect(url_for("login"))
        if (
            current_user.is_authenticated
            and not current_user.is_admin
            and not verified_device_count(current_user.id)
            and request.endpoint not in {
                "login",
                "register",
                "logout",
                "static",
                "device_verification",
                "create_device_registration_token",
                "device_registration_token_status",
                "device_verification_status",
                "device_enrollment",
                "verify_device_enrollment",
                "download_device_agent",
                "submit_agent_enrollment",
            }
        ):
            if request.path.startswith("/api/"):
                return jsonify(
                    error="Verify and register a device before accessing this resource."
                ), 403
            return redirect(url_for("device_verification"))
        if request.method == "POST" and request.endpoint not in {
            "submit_agent_enrollment",
            "submit_agent_diagnostic",
        }:
            submitted = request.headers.get("X-CSRF-Token")
            if not submitted:
                submitted = request.form.get("csrf_token")
            if not submitted or not secrets.compare_digest(
                submitted, session.get("_csrf_token", "")
            ):
                if request.path.startswith("/api/"):
                    return jsonify(error="Invalid or missing CSRF token."), 400
                abort(400, description="Invalid or missing CSRF token.")

    @app.context_processor
    def inject_template_values():
        def csrf_token():
            token = session.get("_csrf_token")
            if token is None:
                token = secrets.token_urlsafe(32)
                session["_csrf_token"] = token
            return token

        return {"csrf_token": csrf_token}

    def admin_required(view):
        from functools import wraps

        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if not current_user.is_admin:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    def api_data():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ValidationError("Request body must be a JSON object.")
        return data

    def api_error(error, status=400):
        return jsonify(error=str(error)), status

    def enrollment_page(download_url=None, message=None, status=200, verified=False):
        response = app.make_response(
            render_template(
                "enroll.html",
                download_url=download_url,
                message=message,
                verified=verified,
            )
        )
        response.status_code = status
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def registration_qr_payload(token, expires_at):
        base_url = app.config["PUBLIC_BASE_URL"] or request.url_root.rstrip("/")
        parsed_base = urlsplit(base_url)
        if (
            parsed_base.scheme not in {"http", "https"}
            or not parsed_base.netloc
            or parsed_base.username
            or parsed_base.password
            or parsed_base.path not in {"", "/"}
            or parsed_base.query
            or parsed_base.fragment
        ):
            raise ValueError(
                "Set PUBLIC_BASE_URL to the reachable application origin before generating a QR code."
            )
        enrollment_url = f"{base_url}{url_for('device_enrollment', token=token)}"
        qr_code = qrcode.make(
            enrollment_url,
            image_factory=SvgPathImage,
            box_size=8,
            border=4,
        )
        svg_root = ET.fromstring(qr_code.to_string())
        svg_namespace = "{http://www.w3.org/2000/svg}"
        svg_root.insert(
            0,
            ET.Element(
                f"{svg_namespace}rect",
                {"width": "100%", "height": "100%", "fill": "#ffffff"},
            ),
        )
        for path in svg_root.iter(f"{svg_namespace}path"):
            path.set("fill", "#111827")
        encoded_qr = base64.b64encode(
            ET.tostring(svg_root, encoding="utf-8")
        ).decode("ascii")
        return {
            "enrollment_url": enrollment_url,
            "qr_code": f"data:image/svg+xml;base64,{encoded_qr}",
            "expires_at": expires_at.isoformat(),
            "server_time": datetime.now(timezone.utc).isoformat(),
        }

    def can_manage_device(device):
        can_access_device(device)
        if device.lifecycle_status != "active" or device.status == "retired":
            abort(404)

    def can_access_device(device):
        if device.lifecycle_status == "deleted" and not current_user.is_admin:
            abort(404)
        if not current_user.is_admin and (
            device.owner_user_id != current_user.id
            and device.registered_by_user_id != current_user.id
        ):
            abort(404)

    def serialize_device(device):
        spec = device.hardware_spec
        latest_diagnostic = latest_completed_diagnostic(device)
        health_check = next(
            (
                check
                for check in (latest_diagnostic.checks if latest_diagnostic else [])
                if check.check_name == "Overall scores"
            ),
            None,
        )
        health_details = health_check.details if health_check else {}
        health_scores = (
            health_details.get("scores", {})
            if isinstance(health_details, dict)
            else {}
        )
        return {
            "id": device.id,
            "name": device.device_name,
            "hostname": device.hostname,
            "owner": device.owner.full_name,
            "owner_id": device.owner_user_id,
            "type": device.device_type,
            "os": device.operating_system or "",
            "cpu": spec.cpu_model if spec and spec.cpu_model else "—",
            "ram": (
                f"{spec.memory_bytes // (1024 ** 3)} GB"
                if spec and spec.memory_bytes
                else "—"
            ),
            "storage": (
                f"{spec.storage_bytes // (1024 ** 3)} GB"
                if spec and spec.storage_bytes
                else "—"
            ),
            "healthScore": health_scores.get("overall"),
            "healthRunId": latest_diagnostic.id if latest_diagnostic else None,
            "status": device.status.capitalize(),
            "isVerified": device.is_verified,
            "lifecycleStatus": device.lifecycle_status,
            "archivedAt": device.archived_at.isoformat() if device.archived_at else "",
            "registered": device.registered_at.isoformat() if device.registered_at else "",
            "lastUpdated": (
                device.last_seen_at.isoformat()
                if device.last_seen_at
                else device.updated_at.isoformat()
                if device.updated_at
                else ""
            ),
        }

    def serialize_user(user):
        return {
            "id": user.id,
            "fullName": user.full_name or "",
            "username": user.username,
            "email": user.email,
            "role": user.role_name,
            "status": user.status.capitalize(),
        }

    def verified_device_count(user_id):
        return Device.query.filter_by(
            owner_user_id=user_id,
            is_verified=True,
        ).filter(Device.lifecycle_status != "deleted").count()

    @app.route("/", methods=["GET", "POST"])
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated and request.method == "GET":
            destination = (
                "dashboard" if current_user.is_admin else "device_verification"
            )
            return redirect(url_for(destination))
        if request.method == "POST":
            pending_user_id = session.get("pending_login_user_id")
            if pending_user_id:
                user = db.session.get(User, pending_user_id)
                if not user or not user.is_active or not user.totp_enabled:
                    session.pop("pending_login_user_id", None)
                    session.pop("pending_login_next", None)
                    flash("Sign-in expired. Please enter your credentials again.", "warning")
                    return render_template("login.html"), 401
                if not verify_login_totp(user, request.form.get("totp_code", "")):
                    user.totp_attempts += 1
                    db.session.add(
                        ActivityLog(
                            actor_user_id=user.id,
                            event_type="auth.login_2fa_failed",
                            entity_type="user",
                            entity_id=user.id,
                            details={"username": user.username},
                        )
                    )
                    db.session.commit()
                    if user.totp_attempts >= 5:
                        session.pop("pending_login_user_id", None)
                        session.pop("pending_login_next", None)
                        flash(
                            "Too many incorrect authenticator codes. Sign in again to retry.",
                            "danger",
                        )
                        return render_template("login.html"), 401
                    flash("That authenticator code is invalid or expired. Please try again.", "danger")
                    return render_template("login.html", requires_totp=True), 401
                next_url = session.pop("pending_login_next", "")
                session.pop("pending_login_user_id", None)
                user.totp_attempts = 0
                login_user(user, remember=False, fresh=True)
                user.last_login_at = datetime.now(timezone.utc)
                db.session.add(
                    ActivityLog(
                        actor_user_id=user.id,
                        event_type="auth.login_succeeded",
                        entity_type="user",
                        entity_id=user.id,
                        details={"username": user.username, "two_factor": True},
                    )
                )
                db.session.commit()
                if not user.is_admin:
                    return redirect(url_for("device_verification"))
                return redirect(next_url or url_for("dashboard"))

            identifier = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if "@" in identifier:
                user = User.query.filter(
                    func.lower(User.email) == identifier.lower()
                ).first()
            else:
                user = User.query.filter(
                    func.lower(User.username) == identifier.lower()
                ).first()
            if (
                not user
                or not user.is_active
                or not verify_password(password, user.password_hash)
            ):
                db.session.add(
                    ActivityLog(
                        actor_user_id=user.id if user else None,
                        event_type="auth.login_failed",
                        entity_type="user" if user else None,
                        entity_id=user.id if user else None,
                        details={"username": identifier},
                    )
                )
                db.session.commit()
                flash("Invalid username or password.", "danger")
                return render_template("login.html"), 401
            next_url = request.form.get("next", "") or request.args.get("next", "")
            if next_url:
                target = urlsplit(urljoin(request.host_url, next_url))
                if target.scheme not in {"http", "https"} or target.netloc != request.host:
                    next_url = ""
            if user.totp_enabled:
                session.clear()
                user.totp_attempts = 0
                db.session.commit()
                session["pending_login_user_id"] = user.id
                session["pending_login_next"] = next_url
                return render_template("login.html", requires_totp=True)
            session.clear()
            login_user(user, remember=False, fresh=True)
            user.last_login_at = datetime.now(timezone.utc)
            db.session.add(
                ActivityLog(
                    actor_user_id=user.id,
                    event_type="auth.login_succeeded",
                    entity_type="user",
                    entity_id=user.id,
                    details={"username": user.username},
                )
            )
            db.session.commit()
            if not user.is_admin:
                return redirect(url_for("device_verification"))
            return redirect(next_url or url_for("dashboard"))
        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated and request.method == "GET":
            return redirect(
                url_for("dashboard")
                if current_user.is_admin
                else url_for("device_verification")
            )
        if request.method == "POST":
            return begin_registration()
        return render_template("register.html")

    def registration_challenge():
        challenge_id = session.get("registration_challenge_id")
        if not isinstance(challenge_id, int):
            raise ValidationError("Registration session expired. Please start again.")
        challenge = db.session.get(RegistrationChallenge, challenge_id)
        if not challenge:
            raise ValidationError("Registration session expired. Please start again.")
        return challenge

    @app.post("/api/registration/start")
    def begin_registration():
        try:
            challenge = start_registration(request.form)
        except ValidationError as error:
            app.logger.warning("Registration start rejected: %s", error)
            return jsonify(error=str(error)), 400
        except EmailDeliveryError as error:
            if error.challenge_id is not None:
                session["registration_challenge_id"] = error.challenge_id
            return jsonify(error=str(error)), 503
        except DatabaseSetupError as error:
            app.logger.error("Account registration blocked: %s", error)
            return jsonify(error=str(error)), 503
        session.pop("registration_challenge_id", None)
        session["registration_challenge_id"] = challenge.id
        return jsonify(
            message="We sent a 6-digit verification code to your email address.",
        )

    @app.post("/api/registration/resend-code")
    def resend_registration_code():
        try:
            resend_email_code(registration_challenge())
        except ValidationError as error:
            return jsonify(error=str(error)), 400
        except EmailDeliveryError as error:
            return jsonify(error=str(error)), 503
        return jsonify(message="A new verification code has been sent.")

    @app.post("/api/registration/cancel")
    def cancel_registration_verification():
        if not session.get("registration_challenge_id"):
            session.pop("registration_challenge_id", None)
            return jsonify(message="Registration canceled.")
        try:
            cancel_registration(registration_challenge())
        except ValidationError as error:
            session.pop("registration_challenge_id", None)
            return jsonify(error=str(error)), 400
        session.pop("registration_challenge_id", None)
        return jsonify(message="Registration canceled.")

    @app.post("/api/registration/verify-email")
    def verify_registration_email():
        try:
            qr_code = verify_email_code(
                registration_challenge(), request.form.get("code", "")
            )
        except ValidationError as error:
            app.logger.warning(
                "Registration email verification request rejected (challenge_id=%s): %s",
                session.get("registration_challenge_id"),
                error,
            )
            return jsonify(error=str(error)), 400
        return jsonify(
            message="Email verified. Scan the QR code with Google Authenticator.",
            qr_code=qr_code,
        )

    @app.post("/api/registration/verify-authenticator")
    def verify_registration_authenticator():
        try:
            challenge = registration_challenge()
            verify_registration_totp(challenge, request.form.get("code", ""))
            user = complete_registration(challenge)
        except ValidationError as error:
            app.logger.warning(
                "Registration completion rejected (challenge_id=%s): %s",
                session.get("registration_challenge_id"),
                error,
            )
            return jsonify(error=str(error)), 400
        except RuntimeError as error:
            app.logger.error("Account registration could not be completed: %s", error)
            return jsonify(error="Account setup is temporarily unavailable."), 503
        session.pop("registration_challenge_id", None)
        login_user(user, remember=False, fresh=True)
        device_qr = None
        try:
            token, expires_at = issue_device_registration_token(user)
            device_qr = registration_qr_payload(token, expires_at)
        except (DatabaseSetupError, ValueError) as error:
            app.logger.error("Device enrollment QR generation blocked: %s", error)
        return jsonify(
            message="Your account is verified and ready.",
            redirect_url=url_for("device_verification"),
            device_qr=device_qr,
        )

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        session.clear()
        flash("You have been signed out.", "info")
        return redirect(url_for("login"))

    @app.get("/device-verification")
    @login_required
    def device_verification():
        if current_user.is_admin:
            abort(404)
        return render_template(
            "device_verification.html",
            active_page="device-verification",
            verified_device_count=verified_device_count(current_user.id),
            registration_qr=None,
            registration_complete=False,
        )

    @app.get("/dashboard")
    @login_required
    def dashboard():
        registration_count = 0 if current_user.is_admin else verified_device_count(current_user.id)
        if not current_user.is_admin and not registration_count:
            flash(
                "Verify at least one device with the QR registration workflow before opening the dashboard.",
                "warning",
            )
            return redirect(url_for("device_verification"))
        return render_template(
            "dashboard.html",
            active_page="dashboard",
            verified_device_count=registration_count,
        )

    @app.get("/devices")
    @login_required
    def devices():
        return render_template("devices.html", active_page="devices")

    @app.get("/devices/<int:device_id>/specifications")
    @login_required
    def device_specifications(device_id):
        device = db.get_or_404(Device, device_id)
        can_access_device(device)
        specification = device.hardware_spec

        def display_names(value):
            if not isinstance(value, list):
                return []
            return [item for item in value if isinstance(item, str) and item.strip()]

        fields = [
            (
                "Device Verification Status",
                "Verified" if device.is_verified else "Not verified",
            ),
            (
                "Registration Date and Time",
                device.registered_at.isoformat() if device.registered_at else None,
            ),
            (
                "Last Updated Date and Time",
                device.updated_at.isoformat() if device.updated_at else None,
            ),
            ("Device Status", device.status),
        ]
        if specification:
            def format_bytes(value):
                if isinstance(value, bool) or not isinstance(value, int):
                    return None
                return f"{value:,} bytes ({value / (1024 ** 3):.2f} GiB)"

            storage_devices = []
            if isinstance(specification.storage_devices, list):
                for item in specification.storage_devices:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name")
                    total = format_bytes(item.get("total_bytes"))
                    available = format_bytes(item.get("available_bytes"))
                    if isinstance(name, str) and (total or available):
                        storage_devices.append(
                            f"{name}: {total or 'Not available'} total, "
                            f"{available or 'Not available'} available"
                        )
            fields = [
                ("CPU Name", specification.cpu_model),
                ("RAM Capacity", format_bytes(specification.memory_bytes)),
                ("RAM Usage", format_bytes(specification.ram_usage_bytes)),
                ("Number of CPU Cores", specification.cpu_cores),
                ("Storage Devices", ", ".join(storage_devices)),
                ("Total Storage Capacity", format_bytes(specification.storage_bytes)),
                (
                    "Available Storage Capacity",
                    format_bytes(specification.storage_available_bytes),
                ),
                ("GPU Information", specification.gpu_model),
                ("Motherboard Brand", specification.motherboard_brand),
                ("Operating System Name", specification.operating_system_name),
                ("Operating System Version", specification.operating_system_version),
                (
                    "Installed Network Adapters",
                    ", ".join(display_names(specification.network_adapters)),
                ),
                ("IP Address", ", ".join(display_names(specification.ip_addresses))),
            ] + fields
        registration_history = Log.query.filter_by(device_id=device.id).order_by(
            Log.timestamp.desc(), Log.id.desc()
        ).all()
        try:
            diagnostic_history = [
                diagnostic_run_payload(run)
                for run in sorted(
                    device.diagnostic_runs,
                    key=diagnostic_sort_key,
                    reverse=True,
                )[:10]
            ]
            app.logger.debug(
                "Device specifications and latest diagnostics retrieved "
                "(device_id=%s, diagnostic_run_id=%s).",
                device_id,
                diagnostic_history[0]["id"] if diagnostic_history else None,
            )
            return render_template(
                "device_specifications.html",
                active_page="devices",
                device=device,
                specification_fields=fields,
                has_specification=specification is not None,
                registration_history=registration_history,
                diagnostic_history=diagnostic_history,
            )
        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception(
                "Could not retrieve detected specifications (device_id=%s).",
                device_id,
            )
            flash(
                "Device information could not be retrieved. Please try again.",
                "danger",
            )
            return redirect(url_for("devices"))

    @app.get("/archived-devices")
    @login_required
    def archived_devices():
        return render_template("archived_devices.html", active_page="archived-devices")

    @app.get("/admin")
    @admin_required
    def admin():
        return render_template("admin.html", active_page="admin")

    @app.post("/api/device-registration-tokens")
    @login_required
    def create_device_registration_token():
        if current_user.is_admin:
            return api_error(
                "Device registration is only available to standard users.", 403
            )
        try:
            base_url = app.config["PUBLIC_BASE_URL"] or request.url_root.rstrip("/")
            parsed_base = urlsplit(base_url)
            if (
                parsed_base.scheme not in {"http", "https"}
                or not parsed_base.netloc
                or parsed_base.username
                or parsed_base.password
                or parsed_base.path not in {"", "/"}
                or parsed_base.query
                or parsed_base.fragment
            ):
                return api_error(
                    "Set PUBLIC_BASE_URL to the reachable application origin before generating a QR code.",
                    500,
                )
            token, expires_at = issue_device_registration_token(current_user)
            qr_payload = registration_qr_payload(token, expires_at)
        except ValueError as error:
            return api_error(error, 500)
        response = jsonify(**qr_payload)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/device-registration-tokens/<token>/status")
    @login_required
    def device_registration_token_status(token):
        if current_user.is_admin:
            return api_error(
                "Device registration is only available to standard users.", 403
            )
        if not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", token):
            return api_error("Registration token not found.", 404)

        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        registration = DeviceRegistrationToken.query.filter_by(
            token_hash=token_hash
        ).one_or_none()
        if registration is None or registration.user_id != current_user.id:
            return api_error("Registration token not found.", 404)

        expires_at = registration.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if registration.used_at:
            status = "used"
        elif registration.revoked_at:
            status = "revoked"
        elif expires_at <= datetime.now(timezone.utc):
            status = "expired"
        elif registration.download_confirmed_at:
            status = "download_confirmed"
        elif registration.verified_at:
            status = "verified"
        else:
            status = "active"

        response = jsonify(
            status=status,
            expires_at=expires_at.isoformat(),
            server_time=datetime.now(timezone.utc).isoformat(),
            device=(
                {
                    "id": registration.device.id,
                    "name": registration.device.device_name,
                    "specifications_url": url_for(
                        "device_specifications",
                        device_id=registration.device.id,
                    ),
                }
                if registration.used_at and registration.device
                else None
            ),
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/enroll/<token>")
    def device_enrollment(token):
        if current_user.is_authenticated and current_user.is_admin:
            return enrollment_page(
                message="Device registration is only available to standard users.",
                status=403,
            )
        if find_valid_registration_token(token) is None:
            return enrollment_page(
                message="This device registration QR code has expired or was already used.",
                status=410,
            )
        registration = find_valid_registration_token(token)
        if registration is None:
            return enrollment_page(
                message="This device registration QR code has expired or was already used.",
                status=410,
            )
        return enrollment_page(verified=registration.verified_at is not None)

    @app.post("/enroll/<token>/verify")
    def verify_device_enrollment(token):
        if current_user.is_authenticated and current_user.is_admin:
            return enrollment_page(
                message="Device registration is only available to standard users.",
                status=403,
            )
        registration = find_valid_registration_token(token)
        if registration is None or registration.user.status != "active":
            return enrollment_page(
                message="This device registration QR code has expired or was already used.",
                status=410,
            )
        if registration.verified_at is None:
            registration.verified_at = datetime.now(timezone.utc)
            db.session.commit()
        return redirect(url_for("device_enrollment", token=token))

    @app.route("/enroll/<token>/agent.exe", methods=["GET", "POST"])
    def download_device_agent(token):
        if current_user.is_authenticated and current_user.is_admin:
            return enrollment_page(
                message="Device registration is only available to standard users.",
                status=403,
            )
        registration = find_valid_registration_token(token)
        if registration is None or registration.user.status != "active":
            return enrollment_page(
                message="This device registration QR code has expired or was already used.",
                status=410,
            )
        if request.method == "GET":
            return enrollment_page(
                message="Use the confirmation button to request the Device Agent download.",
                verified=registration.verified_at is not None,
            )
        if registration.verified_at is None:
            return enrollment_page(
                message="Verify the account before downloading the Device Agent.",
                status=403,
            )
        if request.form.get("trust_device_agent") != "yes":
            return enrollment_page(
                message="Confirm that you trust this application before downloading the Device Agent.",
                status=400,
                verified=True,
            )
        registration.download_confirmed_at = datetime.now(timezone.utc)
        db.session.commit()
        base_url = app.config["PUBLIC_BASE_URL"] or request.url_root.rstrip("/")
        parsed_base = urlsplit(base_url)
        if (
            parsed_base.scheme not in {"http", "https"}
            or not parsed_base.netloc
            or parsed_base.username
            or parsed_base.password
            or parsed_base.path not in {"", "/"}
            or parsed_base.query
            or parsed_base.fragment
        ):
            abort(503)
        if (
            parsed_base.scheme != "https"
            and parsed_base.hostname not in {"localhost", "127.0.0.1", "::1"}
        ):
            abort(503)
        submission_url = f"{base_url}{url_for('submit_agent_enrollment')}"
        try:
            agent_bytes = build_agent_executable(token, submission_url)
        except DeviceAgentBuildError:
            app.logger.exception("Could not build the Device Agent executable.")
            return enrollment_page(
                message=(
                    "The Windows Device Agent could not be prepared. "
                    "Please retry or contact the system administrator."
                ),
                status=503,
                verified=True,
            )
        response = send_file(
            io.BytesIO(agent_bytes),
            mimetype="application/vnd.microsoft.portable-executable",
            as_attachment=True,
            download_name="devmonitor-device-agent.exe",
            max_age=0,
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.post("/api/device-agent/enroll")
    def submit_agent_enrollment():
        if current_user.is_authenticated and current_user.is_admin:
            return api_error(
                "Device registration is only available to standard users.", 403
            )
        authorization = request.headers.get("Authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.casefold() != "bearer":
            return api_error("A valid device registration token is required.", 401)
        try:
            device = register_agent_device(token, api_data())
        except RegistrationTokenError as error:
            return api_error(error, 401)
        except ValidationError as error:
            return api_error(error)
        return jsonify(
            device_id=device.id,
            asset_tag=device.asset_tag,
            name=device.device_name,
            owner_user_id=device.owner_user_id,
            registered_at=device.registered_at.isoformat(),
        ), 201

    @app.post("/api/device-agent/diagnostics/<int:run_id>")
    def submit_agent_diagnostic(run_id):
        authorization = request.headers.get("Authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.casefold() != "bearer":
            return api_error("A valid diagnostic authorization is required.", 401)
        if request.content_length and request.content_length > REPORT_LIMIT_BYTES + 1024:
            return api_error("The diagnostic report exceeds the size limit.", 413)
        data = api_data()
        if not isinstance(data, dict) or set(data) != {"report"}:
            return api_error("Submission must contain one diagnostic report.")
        try:
            run = complete_diagnostic_run(run_id, token, data["report"])
        except DiagnosticValidationError as error:
            return api_error(error, 401 if "token" in str(error).lower() or "authorization" in str(error).lower() else 400)
        app.logger.info(
            "Diagnostic report stored (run_id=%s, device_id=%s, checks=%d, issues=%d).",
            run_id,
            run.device_id,
            len(data["report"]["checks"]),
            len(data["report"]["issues"]),
        )
        return jsonify(run_id=run.id, status=run.status), 201

    @app.get("/api/devices")
    @login_required
    def list_devices():
        query = Device.query.filter(
            Device.lifecycle_status == "active",
            Device.status != "retired",
        )
        if not current_user.is_admin:
            query = query.filter(
                or_(
                    Device.owner_user_id == current_user.id,
                    Device.registered_by_user_id == current_user.id,
                )
            )
        response = jsonify(
            [
                serialize_device(device)
                for device in query.order_by(Device.id.desc()).all()
            ]
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/archived-devices")
    @login_required
    def list_archived_devices():
        query = Device.query.filter_by(lifecycle_status="archived")
        if not current_user.is_admin:
            query = query.filter(
                or_(
                    Device.owner_user_id == current_user.id,
                    Device.registered_by_user_id == current_user.id,
                )
            )
        return jsonify(
            [
                serialize_device(device)
                for device in query.order_by(Device.archived_at.desc(), Device.id.desc())
            ]
        )

    @app.post("/api/devices")
    @login_required
    def add_device():
        if current_user.is_admin:
            return api_error(
                "Device registration is only available to standard users.", 403
            )
        try:
            device = create_device(current_user, api_data())
        except ValidationError as error:
            return api_error(error)
        return jsonify(serialize_device(device)), 201

    @app.patch("/api/devices/<int:device_id>")
    @login_required
    def edit_device(device_id):
        device = db.get_or_404(Device, device_id)
        can_manage_device(device)
        try:
            update_device(device, api_data())
        except ValidationError as error:
            return api_error(error)
        return jsonify(serialize_device(device))

    @app.get("/api/devices/<int:device_id>")
    @login_required
    def device_details(device_id):
        device = db.get_or_404(Device, device_id)
        can_access_device(device)
        diagnostic_ids = [run.id for run in device.diagnostic_runs]
        activity_query = ActivityLog.query.filter(
            or_(
                (ActivityLog.entity_type == "device")
                & (ActivityLog.entity_id == device.id),
                (ActivityLog.entity_type == "diagnostic_run")
                & (ActivityLog.entity_id.in_(diagnostic_ids or [-1])),
            )
        )
        details = jsonify(
            id=device.id,
            asset_tag=device.asset_tag,
            device_name=device.device_name,
            hostname=device.hostname,
            device_type=device.device_type,
            serial_number=device.serial_number,
            manufacturer=device.manufacturer,
            model=device.model,
            operating_system=device.operating_system,
            operating_system_version=device.operating_system_version,
            status=device.status,
            lifecycle_status=device.lifecycle_status,
            archived_at=device.archived_at.isoformat() if device.archived_at else None,
            archived_by_user_id=device.archived_by_user_id,
            deleted_at=device.deleted_at.isoformat() if device.deleted_at else None,
            owner_user_id=device.owner_user_id,
            registered_by_user_id=device.registered_by_user_id,
            owner={
                "id": device.owner.id,
                "username": device.owner.username,
                "full_name": device.owner.full_name,
                "email": device.owner.email,
            },
            registered_by={
                "id": device.registered_by.id,
                "username": device.registered_by.username,
                "full_name": device.registered_by.full_name,
                "email": device.registered_by.email,
            } if device.registered_by else None,
            registered_at=device.registered_at.isoformat() if device.registered_at else None,
            updated_at=device.updated_at.isoformat() if device.updated_at else None,
            last_seen_at=device.last_seen_at.isoformat() if device.last_seen_at else None,
            specification={
                "device_id": device.hardware_spec.device_id,
                "cpu_model": device.hardware_spec.cpu_model,
                "cpu_cores": device.hardware_spec.cpu_cores,
                "cpu_threads": device.hardware_spec.cpu_threads,
                "memory_bytes": device.hardware_spec.memory_bytes,
                "ram_usage_bytes": device.hardware_spec.ram_usage_bytes,
                "storage_bytes": device.hardware_spec.storage_bytes,
                "storage_available_bytes": device.hardware_spec.storage_available_bytes,
                "storage_devices": device.hardware_spec.storage_devices or [],
                "gpu_model": device.hardware_spec.gpu_model,
                "bios_version": device.hardware_spec.bios_version,
                "motherboard_model": device.hardware_spec.motherboard_model,
                "motherboard_brand": device.hardware_spec.motherboard_brand,
                "operating_system_name": device.hardware_spec.operating_system_name,
                "operating_system_version": device.hardware_spec.operating_system_version,
                "network_adapters": device.hardware_spec.network_adapters or [],
                "ip_addresses": device.hardware_spec.ip_addresses or [],
                "collected_at": (
                    device.hardware_spec.collected_at.isoformat()
                    if device.hardware_spec.collected_at else None
                ),
            } if device.hardware_spec else None,
            network_records=[
                {
                    "id": record.id,
                    "device_id": record.device_id,
                    "ip_address": record.ip_address,
                    "subnet_mask": record.subnet_mask,
                    "default_gateway": record.default_gateway,
                    "dns_server": record.dns_server,
                    "connectivity_status": record.connectivity_status,
                    "recorded_at": record.recorded_at.isoformat(),
                }
                for record in sorted(
                    device.network_records,
                    key=lambda item: item.recorded_at,
                    reverse=True,
                )
            ],
            network_interfaces=[
                {
                    "id": interface.id,
                    "device_id": interface.device_id,
                    "interface_name": interface.interface_name,
                    "mac_address": interface.mac_address,
                    "interface_type": interface.interface_type,
                    "is_primary": interface.is_primary,
                    "created_at": interface.created_at.isoformat(),
                    "observations": [
                        {
                            "id": observation.id,
                            "interface_id": observation.interface_id,
                            "ip_address": observation.ip_address,
                            "subnet_prefix": observation.subnet_prefix,
                            "gateway": observation.gateway,
                            "dns_servers": observation.dns_servers,
                            "ssid": observation.ssid,
                            "connection_type": observation.connection_type,
                            "observed_at": observation.observed_at.isoformat(),
                        }
                        for observation in sorted(
                            interface.observations,
                            key=lambda item: item.observed_at,
                            reverse=True,
                        )
                    ],
                }
                for interface in device.network_interfaces
            ],
            diagnostics=[
                {
                    "id": run.id,
                    "device_id": run.device_id,
                    "initiated_by_user_id": run.initiated_by_user_id,
                    "initiated_by": {
                        "username": run.initiated_by.username,
                        "full_name": run.initiated_by.full_name,
                    } if run.initiated_by else None,
                    "status": run.status,
                    "summary": run.summary,
                    "detected_problem": run.detected_problem,
                    "recommendation": run.recommendation,
                    "started_at": run.started_at.isoformat(),
                    "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                    "checks": [
                        {
                            "id": check.id,
                            "run_id": check.run_id,
                            "check_name": check.check_name,
                            "category": check.category,
                            "status": check.status,
                            "result_summary": check.result_summary,
                            "details": check.details,
                            "measured_at": check.measured_at.isoformat(),
                        }
                        for check in run.checks
                    ],
                }
                for run in sorted(
                    device.diagnostic_runs,
                    key=lambda item: item.started_at,
                    reverse=True,
                )
            ],
            metrics=[
                {
                    "id": metric.id,
                    "device_id": metric.device_id,
                    "cpu_percent": metric.cpu_percent,
                    "memory_percent": metric.memory_percent,
                    "storage_percent": metric.storage_percent,
                    "memory_used_bytes": metric.memory_used_bytes,
                    "storage_used_bytes": metric.storage_used_bytes,
                    "network_rx_bytes": metric.network_rx_bytes,
                    "network_tx_bytes": metric.network_tx_bytes,
                    "collected_at": metric.collected_at.isoformat(),
                }
                for metric in sorted(
                    device.metric_samples,
                    key=lambda item: item.collected_at,
                    reverse=True,
                )
            ],
            logs=[
                {
                    "id": entry.id,
                    "device_id": entry.device_id,
                    "event": entry.event,
                    "timestamp": entry.timestamp.isoformat(),
                }
                for entry in sorted(
                    device.logs,
                    key=lambda item: item.timestamp,
                    reverse=True,
                )
            ],
            activity_logs=[
                {
                    "event": entry.event_type,
                    "actor_user_id": entry.actor_user_id,
                    "entity_type": entry.entity_type,
                    "entity_id": entry.entity_id,
                    "actor": entry.actor.full_name or entry.actor.username
                    if entry.actor else "System",
                    "details": entry.details,
                    "id": entry.id,
                    "occurred_at": entry.occurred_at.isoformat(),
                }
                for entry in activity_query.order_by(ActivityLog.occurred_at.desc())
            ],
        ).get_json()
        if current_user.is_admin:
            details["view_mode"] = "administrator"
            return jsonify(details)
        latest_network = (
            details["network_records"][0] if details["network_records"] else {}
        )
        return jsonify(
            view_mode="user",
            device_name=device.device_name,
            device_type=device.device_type,
            operating_system=device.operating_system,
            status=device.status,
            ip_address=latest_network.get("ip_address"),
            specification=details["specification"],
            registered_at=details["registered_at"],
        )

    @app.post("/api/devices/<int:device_id>/archive")
    @login_required
    def archive_device_route(device_id):
        device = db.get_or_404(Device, device_id)
        can_manage_device(device)
        try:
            archive_device(device)
        except ValidationError as error:
            return api_error(error)
        return "", 204

    @app.post("/api/devices/<int:device_id>/restore")
    @login_required
    def restore_device_route(device_id):
        device = db.get_or_404(Device, device_id)
        can_access_device(device)
        try:
            restore_device(device)
        except ValidationError as error:
            return api_error(error)
        return "", 204

    @app.delete("/api/devices/<int:device_id>")
    @admin_required
    def delete_device(device_id):
        device = db.get_or_404(Device, device_id)
        can_access_device(device)
        try:
            soft_delete_device(device)
        except ValidationError as error:
            return api_error(error)
        return "", 204

    @app.post("/api/devices/<int:device_id>/diagnostics")
    @login_required
    def scan_device(device_id):
        device = db.get_or_404(Device, device_id)
        can_manage_device(device)
        base_url = app.config["PUBLIC_BASE_URL"] or request.url_root.rstrip("/")
        parsed_base = urlsplit(base_url)
        if (
            parsed_base.scheme not in {"http", "https"}
            or not parsed_base.netloc
            or parsed_base.username
            or parsed_base.password
            or parsed_base.path not in {"", "/"}
            or parsed_base.query
            or parsed_base.fragment
            or (
                parsed_base.scheme != "https"
                and parsed_base.hostname not in {"localhost", "127.0.0.1", "::1"}
            )
        ):
            return api_error(
                "Set PUBLIC_BASE_URL to a reachable HTTPS origin before downloading a diagnostic agent.",
                503,
            )
        run, token = create_diagnostic_run(device, current_user)
        submission_url = urljoin(
            base_url, url_for("submit_agent_diagnostic", run_id=run.id)
        )
        dashboard_url = urljoin(base_url, url_for("dashboard"))
        try:
            agent_bytes = build_agent_executable(
                None,
                submission_url,
                mode="diagnostic",
                diagnostic_run_id=run.id,
                diagnostic_token=token,
                dashboard_url=dashboard_url,
            )
        except DeviceAgentBuildError:
            run.status = "failed"
            run.summary = "The endpoint diagnostic agent could not be prepared."
            run.recommendation = None
            run.finished_at = datetime.now(timezone.utc)
            db.session.add(
                Log(device_id=device.id, event="Endpoint diagnostics agent build failed")
            )
            db.session.commit()
            app.logger.exception("Could not build diagnostic agent (run_id=%s).", run.id)
            return api_error("The diagnostic agent could not be prepared.", 503)
        response = send_file(
            io.BytesIO(agent_bytes),
            mimetype="application/vnd.microsoft.portable-executable",
            as_attachment=True,
            download_name="devmonitor-device-diagnostics.exe",
            max_age=0,
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Diagnostic-Run-ID"] = str(run.id)
        response.headers["X-Device-ID"] = str(device.id)
        response.headers["X-Device-Specifications-URL"] = url_for(
            "device_specifications", device_id=device.id
        )
        return response

    @app.get("/api/devices/<int:device_id>/diagnostics/<int:run_id>")
    @login_required
    def diagnostic_run_status(device_id, run_id):
        device = db.get_or_404(Device, device_id)
        can_manage_device(device)
        run = db.session.get(DiagnosticRun, run_id)
        if run is None or run.device_id != device.id:
            abort(404)
        app.logger.debug(
            "Diagnostic report retrieved (run_id=%s, device_id=%s, status=%s).",
            run.id,
            device.id,
            run.status,
        )
        response = jsonify(diagnostic_run_payload(run))
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/devices/<int:device_id>/history")
    @login_required
    def device_history(device_id):
        device = db.get_or_404(Device, device_id)
        can_manage_device(device)
        response = jsonify(
            diagnostics=[
                diagnostic_run_payload(run)
                for run in sorted(
                    device.diagnostic_runs,
                    key=diagnostic_sort_key,
                    reverse=True,
                )
            ],
            network=[
                {
                    "ip_address": record.ip_address,
                    "subnet_mask": record.subnet_mask,
                    "default_gateway": record.default_gateway,
                    "dns_server": record.dns_server,
                    "connectivity_status": record.connectivity_status,
                    "recorded_at": record.recorded_at.isoformat(),
                }
                for record in sorted(device.network_records, key=lambda item: item.recorded_at, reverse=True)
            ],
            logs=[
                {
                    "id": entry.id,
                    "event": entry.event,
                    "timestamp": entry.timestamp.isoformat(),
                }
                for entry in sorted(
                    device.logs, key=lambda item: item.timestamp, reverse=True
                )
            ],
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/users")
    @admin_required
    def list_users():
        users = User.query.filter(
            func.lower(User.username) != DEFAULT_ADMIN_USERNAME
        ).order_by(User.id.asc()).all()
        return jsonify([serialize_user(user) for user in users])

    @app.post("/api/users")
    @admin_required
    def add_user():
        try:
            data = api_data()
            role_name = data.get("role", "User")
            if not isinstance(role_name, str) or role_name not in {"Administrator", "User"}:
                return api_error("Role must be Administrator or User.")
            user = create_user(data, role_name=role_name)
        except ValidationError as error:
            return api_error(error)
        return jsonify(serialize_user(user)), 201

    @app.patch("/api/users/<int:user_id>")
    @admin_required
    def edit_user(user_id):
        user = db.get_or_404(User, user_id)
        try:
            data = api_data()
        except ValidationError as error:
            return api_error(error)
        if user.id == current_user.id and (
            data.get("status", "active") != "active"
            or data.get("role", "Administrator") != "Administrator"
        ):
            return api_error("You cannot deactivate or demote your own account.")
        try:
            update_user(user, data)
        except ValidationError as error:
            db.session.rollback()
            return api_error(error)
        return jsonify(serialize_user(user))

    @app.delete("/api/users/<int:user_id>")
    @admin_required
    def delete_user(user_id):
        user = db.get_or_404(User, user_id)
        if user.id == current_user.id:
            return api_error("You cannot deactivate your own account.")
        try:
            deactivate_user(user)
        except ValidationError as error:
            db.session.rollback()
            return api_error(error)
        return "", 204

    @app.get("/api/dashboard")
    @login_required
    def dashboard_data():
        if not current_user.is_admin and not verified_device_count(current_user.id):
            return api_error(
                "Verify a device with the QR registration workflow to access the dashboard.",
                403,
            )
        query = Device.query.filter(
            Device.lifecycle_status == "active",
            Device.status != "retired",
        )
        if not current_user.is_admin:
            query = query.filter(
                or_(
                    Device.owner_user_id == current_user.id,
                    Device.registered_by_user_id == current_user.id,
                )
            )
        devices = query.order_by(Device.id.desc()).all()
        serialized_devices = [serialize_device(device) for device in devices]
        app.logger.debug(
            "Dashboard device health retrieved (user_id=%s, device_count=%d).",
            current_user.id,
            len(serialized_devices),
        )
        response = jsonify(
            devices=serialized_devices,
            total=len(devices),
            online=sum(device.status == "online" for device in devices),
            offline=sum(device.status == "offline" for device in devices),
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/device-verification-status")
    @login_required
    def device_verification_status():
        if current_user.is_admin:
            return api_error(
                "Device verification is only available to standard users.", 403
            )
        count = verified_device_count(current_user.id)
        latest_device = Device.query.filter_by(
            owner_user_id=current_user.id,
            is_verified=True,
        ).filter(Device.lifecycle_status != "deleted").order_by(
            Device.id.desc()
        ).first()
        response = jsonify(
            verified=count > 0,
            verified_devices=count,
            scan_status="Completed" if latest_device else "Pending",
            registration_status="Registered" if latest_device else "Pending",
            latest_device=(
                {
                    "id": latest_device.id,
                    "name": latest_device.device_name,
                    "specifications_url": url_for(
                        "device_specifications", device_id=latest_device.id
                    ),
                }
                if latest_device
                else None
            ),
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.cli.command("check-mail")
    def check_mail_command():
        """Validate configured SMTP connectivity and authentication without sending mail."""
        try:
            check_smtp_connection()
        except EmailDeliveryError as error:
            raise click.ClickException(str(error)) from error
        click.echo("SMTP connectivity and authentication succeeded.")

    @app.cli.command("init-db")
    def init_db_command():
        """Create missing model tables and seed standard RBAC roles/permissions."""
        # Existing tables are not altered; apply the documented schema migration
        # before this command when upgrading an existing database.
        try:
            db.create_all()
            inspector = sqlalchemy_inspect(db.engine)
            existing_tables = set(inspector.get_table_names())
            missing_columns = []
            for table in db.metadata.sorted_tables:
                if table.name not in existing_tables:
                    continue
                existing_columns = {
                    item["name"] for item in inspector.get_columns(table.name)
                }
                missing_columns.extend(
                    f"{table.name}.{column.name}"
                    for column in table.columns
                    if column.name not in existing_columns
                )
        except SQLAlchemyError as error:
            db.session.rollback()
            raise click.ClickException(_database_error_message(error)) from error
        if missing_columns:
            raise click.ClickException(
                "The existing database schema is incomplete (missing "
                + ", ".join(missing_columns)
                + "). Back up the database, apply the required migrations, "
                "and run `check-db`; `init-db` does not alter existing tables."
            )
        role_definitions = {
            "Administrator": "Full administrative access",
            "User": "Standard device owner access",
        }
        roles = {}
        for name, description in role_definitions.items():
            role = Role.query.filter_by(name=name).one_or_none()
            if role is None:
                role = Role(name=name, description=description)
                db.session.add(role)
            roles[name] = role
        permissions = {
            "devices.read": "View authorized devices",
            "devices.write": "Register and update authorized devices",
            "users.manage": "Manage user accounts",
            "diagnostics.read": "View diagnostic history",
            "diagnostics.write": "Record diagnostic results",
        }
        permission_rows = {}
        for code, description in permissions.items():
            permission = Permission.query.filter_by(code=code).one_or_none()
            if permission is None:
                permission = Permission(code=code, description=description)
                db.session.add(permission)
            permission_rows[code] = permission
        db.session.flush()
        administrator_permissions = list(permission_rows.values())
        user_permissions = [
            permission_rows["devices.read"],
            permission_rows["devices.write"],
            permission_rows["diagnostics.read"],
            permission_rows["diagnostics.write"],
        ]
        for role, permissions_to_add in (
            (roles["Administrator"], administrator_permissions),
            (roles["User"], user_permissions),
        ):
            for permission in permissions_to_add:
                if permission not in role.permissions:
                    role.permissions.append(permission)
        db.session.commit()

        default_admin = User.query.filter(
            func.lower(User.username) == DEFAULT_ADMIN_USERNAME
        ).one_or_none()
        created_admin = default_admin is None
        if default_admin is None:
            if User.query.filter(func.lower(User.email) == "admin@localhost").first():
                raise click.ClickException(
                    "Cannot create the default admin account because admin@localhost is already in use."
                )
            default_admin = User(
                username=DEFAULT_ADMIN_USERNAME,
                email="admin@localhost",
                full_name="Administrator",
                password_hash=hash_password(DEFAULT_ADMIN_PASSWORD),
                status="active",
                email_verified=True,
            )
            db.session.add(default_admin)
            db.session.flush()
            db.session.add(
                ActivityLog(
                    actor_user_id=None,
                    event_type="auth.admin_bootstrapped",
                    entity_type="user",
                    entity_id=default_admin.id,
                    details={"username": default_admin.username},
                )
            )
        if roles["Administrator"] not in default_admin.roles:
            default_admin.roles.append(roles["Administrator"])
        db.session.commit()
        click.echo(
            "Created the default Administrator account."
            if created_admin
            else "The existing Administrator account and credentials were preserved."
        )
        click.echo("Database tables and default RBAC roles are ready.")

    @app.cli.command("seed-sample-data")
    @click.option("--username", default="sample_user", show_default=True)
    def seed_sample_data_command(username):
        """Create a test user, device, network record, and device log."""
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
            raise click.ClickException(
                "Username must be 3-64 letters, numbers, dots, dashes, or underscores."
            )
        if User.query.filter_by(username=username).first():
            raise click.ClickException(f"User {username!r} already exists.")

        role = Role.query.filter_by(name="User").one_or_none()
        if role is None:
            raise click.ClickException(
                "Run `flask --app device_monitoring_prototype.app init-db` first."
            )

        password = click.prompt(
            "Sample account password",
            hide_input=True,
            confirmation_prompt=True,
        )
        try:
            validate_password(password)
        except ValidationError as error:
            raise click.ClickException(str(error)) from error

        user = User(
            username=username,
            email=f"{username}@example.test",
            full_name="Sample User",
            password_hash=hash_password(password),
            status="active",
            email_verified=True,
        )
        user.roles.append(role)
        device = Device(
            asset_tag=f"DM-{uuid.uuid4().hex[:16].upper()}",
            device_name="Sample Laptop",
            hostname="sample-laptop",
            device_type="Laptop",
            operating_system="Windows 11",
            operating_system_version="Windows 11",
            status="online",
            owner=user,
            registered_by=user,
        )
        device.network_records.append(
            NetworkRecord(
                ip_address="192.0.2.10",
                subnet_mask="255.255.255.0",
                connectivity_status="connected",
            )
        )
        device.logs.append(Log(event="Sample device registered for testing"))
        db.session.add(user)
        db.session.commit()
        click.echo(
            f"Created sample user {username!r} and a linked device with a log entry."
        )

    @app.cli.command("check-db")
    def check_database_command():
        """Check database tables, columns, indexes, foreign keys, and row counts."""
        try:
            inspector = sqlalchemy_inspect(db.engine)
            actual_tables = set(inspector.get_table_names())
            issues = []
            for table in db.metadata.sorted_tables:
                if table.name not in actual_tables:
                    issues.append(f"missing table {table.name}")
                    continue

                actual_columns = {
                    column["name"] for column in inspector.get_columns(table.name)
                }
                issues.extend(
                    f"missing column {table.name}.{column.name}"
                    for column in table.columns
                    if column.name not in actual_columns
                )

                actual_indexes = {
                    index.get("name")
                    for index in inspector.get_indexes(table.name)
                } | {
                    constraint.get("name")
                    for constraint in inspector.get_unique_constraints(table.name)
                }
                issues.extend(
                    f"missing index {table.name}.{index.name}"
                    for index in table.indexes
                    if index.name not in actual_indexes
                )

                actual_unique_constraints = {
                    tuple(constraint.get("column_names") or ())
                    for constraint in inspector.get_unique_constraints(table.name)
                }
                expected_unique_constraints = {
                    tuple(column.name for column in constraint.columns)
                    for constraint in table.constraints
                    if isinstance(constraint, UniqueConstraint)
                }
                issues.extend(
                    f"missing unique constraint on {table.name}"
                    for constraint in expected_unique_constraints
                    if constraint not in actual_unique_constraints
                )

                actual_primary_key = tuple(
                    inspector.get_pk_constraint(table.name).get(
                        "constrained_columns"
                    )
                    or ()
                )
                expected_primary_key = tuple(
                    column.name for column in table.primary_key.columns
                )
                if actual_primary_key != expected_primary_key:
                    issues.append(f"primary key mismatch on {table.name}")

                actual_foreign_keys = {
                    (
                        tuple(foreign_key["constrained_columns"]),
                        foreign_key["referred_table"],
                        tuple(foreign_key["referred_columns"]),
                    )
                    for foreign_key in inspector.get_foreign_keys(table.name)
                }
                for constraint in table.foreign_key_constraints:
                    elements = list(constraint.elements)
                    expected = (
                        tuple(element.parent.name for element in elements),
                        elements[0].column.table.name,
                        tuple(element.column.name for element in elements),
                    )
                    if expected not in actual_foreign_keys:
                        issues.append(f"missing foreign key on {table.name}")

                actual_checks = {
                    check.get("name")
                    for check in inspector.get_check_constraints(table.name)
                }
                issues.extend(
                    f"missing check constraint {table.name}.{constraint.name}"
                    for constraint in table.constraints
                    if isinstance(constraint, CheckConstraint)
                    and constraint.name
                    and constraint.name not in actual_checks
                )

            for table in db.metadata.sorted_tables:
                if table.name not in actual_tables:
                    continue
                available_columns = {
                    column["name"] for column in inspector.get_columns(table.name)
                }
                for constraint in table.foreign_key_constraints:
                    elements = list(constraint.elements)
                    referenced_table = elements[0].column.table
                    if referenced_table.name not in actual_tables:
                        continue
                    referenced_columns = {
                        column["name"]
                        for column in inspector.get_columns(referenced_table.name)
                    }
                    if any(
                        element.parent.name not in available_columns
                        or element.column.name not in referenced_columns
                        for element in elements
                    ):
                        continue
                    join_condition = and_(
                        *(
                            element.parent == element.column
                            for element in elements
                        )
                    )
                    missing_reference = and_(
                        *(element.column.is_(None) for element in elements)
                    )
                    populated_key = and_(
                        *(element.parent.is_not(None) for element in elements)
                    )
                    orphan_count = db.session.execute(
                        select(func.count())
                        .select_from(
                            table.outerjoin(referenced_table, join_condition)
                        )
                        .where(populated_key, missing_reference)
                    ).scalar_one()
                    if orphan_count:
                        issues.append(
                            f"{orphan_count} orphan record(s) in {table.name} "
                            f"for foreign key to {referenced_table.name}"
                        )
        except SQLAlchemyError as error:
            db.session.rollback()
            raise click.ClickException(_database_error_message(error)) from error

        if issues:
            raise click.ClickException(
                "Database schema mismatch:\n- " + "\n- ".join(issues)
            )

        try:
            counts = {
                "users": User.query.count(),
                "devices": Device.query.count(),
                "archived devices": Device.query.filter_by(
                    lifecycle_status="archived"
                ).count(),
                "device specifications": DeviceSpecification.query.count(),
                "device registration tokens": DeviceRegistrationToken.query.count(),
                "registration challenges": RegistrationChallenge.query.filter_by(
                    completed_at=None
                ).count(),
            }
        except SQLAlchemyError as error:
            db.session.rollback()
            raise click.ClickException(_database_error_message(error)) from error

        click.echo(
            f"Database schema is valid ({len(actual_tables)} tables, "
            f"{sum(len(table.indexes) for table in db.metadata.sorted_tables)} "
            "model indexes, primary/unique keys, foreign keys, and check constraints; "
            "no orphaned foreign-key records)."
        )
        click.echo(
            "Row counts: "
            + ", ".join(f"{name}={count}" for name, count in counts.items())
        )

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--email", prompt=True)
    @click.option("--full-name", prompt="Full name")
    def create_admin_command(username, email, full_name):
        """Create an administrator account without exposing a password in shell history."""
        username = username.strip()
        email = email.strip().lower()
        full_name = full_name.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
            raise click.ClickException("Username must be 3-64 letters, numbers, dots, dashes, or underscores.")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise click.ClickException("Enter a valid email address.")
        if not full_name or len(full_name) > 120:
            raise click.ClickException("Full name is required and must be at most 120 characters.")
        if User.query.filter(
            (func.lower(User.username) == username.lower())
            | (func.lower(User.email) == email.lower())
        ).first():
            raise click.ClickException("That username or email address already exists.")
        role = Role.query.filter_by(name="Administrator").one_or_none()
        if role is None:
            raise click.ClickException(
                "Run `flask --app device_monitoring_prototype.app init-db` from the repository root."
            )
        password = click.prompt(
            "Password", hide_input=True, confirmation_prompt=True
        )
        try:
            validate_password(password)
        except ValidationError as error:
            raise click.ClickException(str(error)) from error
        user = User(
            username=username,
            email=email,
            full_name=full_name,
            password_hash=hash_password(password),
            status="active",
            email_verified=True,
        )
        user.roles.append(role)
        db.session.add(user)
        db.session.commit()
        click.echo("Administrator account created.")

    @app.get("/api/admin/logs")
    @admin_required
    def admin_logs():
        kind = request.args.get("kind", "all")
        query_text = request.args.get("q", "").strip()
        try:
            limit = int(request.args.get("limit", 200))
            offset = int(request.args.get("offset", 0))
        except ValueError:
            return api_error("Log limit and offset must be integers.")
        if kind not in {"all", "activity", "device"}:
            return api_error("Log kind must be all, activity, or device.")
        if len(query_text) > 100:
            return api_error("Log search text must be 100 characters or fewer.")
        if not 1 <= limit <= 200 or offset < 0:
            return api_error("Log limit must be 1-200 and offset cannot be negative.")

        pattern = f"%{query_text}%"
        results = []
        if kind in {"all", "activity"}:
            activity_query = ActivityLog.query.outerjoin(
                User, ActivityLog.actor_user_id == User.id
            )
            if query_text:
                activity_query = activity_query.filter(
                    or_(
                        ActivityLog.event_type.ilike(pattern),
                        ActivityLog.entity_type.ilike(pattern),
                        User.username.ilike(pattern),
                        User.display_name.ilike(pattern),
                        cast(ActivityLog.details, String).ilike(pattern),
                    )
                )
            results.extend(
                {
                    "id": entry.id,
                    "kind": "activity",
                    "event": entry.event_type,
                    "entity": entry.entity_type,
                    "entity_id": entry.entity_id,
                    "actor": entry.actor.full_name or entry.actor.username
                    if entry.actor else "System",
                    "details": entry.details,
                    "timestamp": entry.occurred_at.isoformat(),
                }
                for entry in activity_query.order_by(
                    ActivityLog.occurred_at.desc(), ActivityLog.id.desc()
                ).offset(offset if kind == "activity" else 0).limit(
                    limit if kind == "activity" else 200
                )
            )

        if kind in {"all", "device"}:
            device_query = Log.query.join(Device, Log.device_id == Device.id)
            if query_text:
                device_query = device_query.filter(
                    or_(
                        Log.event.ilike(pattern),
                        Device.device_name.ilike(pattern),
                        cast(Log.device_id, String).ilike(pattern),
                    )
                )
            results.extend(
                {
                    "id": entry.id,
                    "kind": "device",
                    "event": entry.event,
                    "entity": "device",
                    "entity_id": entry.device_id,
                    "actor": "—",
                    "details": {"device_name": entry.device.device_name},
                    "timestamp": entry.timestamp.isoformat(),
                }
                for entry in device_query.order_by(
                    Log.timestamp.desc(), Log.id.desc()
                ).offset(offset if kind == "device" else 0).limit(
                    limit if kind == "device" else 200
                )
            )

        results.sort(key=lambda entry: entry["timestamp"], reverse=True)
        if kind == "all":
            results = results[offset:offset + limit]
        return jsonify(results)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "").lower() == "true", port=5000)
