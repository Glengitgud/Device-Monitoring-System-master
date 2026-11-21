"""Throwaway DevMonitor backend for CI end-to-end tests of the native agents.

Runs the real Flask application against a temporary SQLite file, never the
project database:

    python agents/ci/ci_backend.py serve --db /tmp/ci.db --port 5077 --link-file /tmp/link.txt &
    python agents/ci/ci_backend.py check --db /tmp/ci.db --expect-type Laptop Desktop --expect-os macOS
    python agents/ci/ci_backend.py validate-specs specs.json
"""

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

CI_USERNAME = "ci_device_owner"


def make_app(db_path):
    from device_monitoring_prototype.app import create_app

    return create_app({
        "TESTING": True,
        "SECRET_KEY": "devmonitor-ci-only",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{Path(db_path).resolve().as_posix()}",
        "MAIL_SERVER": None,
    })


def serve(args):
    from werkzeug.serving import make_server

    from device_monitoring_prototype.models import Role, User, db
    from device_monitoring_prototype.services import (
        hash_password,
        issue_direct_agent_download_token,
    )

    app = make_app(args.db)
    with app.app_context():
        db.create_all()
        db.session.add_all([Role(name="Administrator"), Role(name="User")])
        user = User(
            username=CI_USERNAME,
            email="ci-owner@example.com",
            password_hash=hash_password("Ci-Only-Passw0rd!"),
            display_name="CI Device Owner",
            status="active",
            email_verified=True,
        )
        db.session.add(user)
        db.session.commit()
        links = []
        for _ in range(args.links):
            token, _expires = issue_direct_agent_download_token(user, channel="link")
            server = f"http://{args.link_host}:{args.port}"
            links.append("devmonitor://enroll?" + urlencode({"server": server, "token": token}))
    Path(args.link_file).write_text("\n".join(links) + "\n", encoding="utf-8")
    print(f"CI backend ready on 127.0.0.1:{args.port}; {len(links)} link(s) in {args.link_file}", flush=True)
    make_server("127.0.0.1", args.port, app, threaded=True).serve_forever()


def check(args):
    from device_monitoring_prototype.models import Device, User

    app = make_app(args.db)
    with app.app_context():
        user = User.query.filter_by(username=CI_USERNAME).one()
        devices = Device.query.filter_by(owner_user_id=user.id, is_verified=True).all()
        for device in devices:
            print(f"registered: #{device.id} {device.device_name!r} type={device.device_type} "
                  f"os={device.operating_system!r} cpu={device.hardware_spec.cpu_model if device.hardware_spec else None!r}")
        problems = []
        if len(devices) != args.expect_count:
            problems.append(f"expected {args.expect_count} verified device(s), found {len(devices)}")
        for device in devices:
            if args.expect_type and device.device_type not in args.expect_type:
                problems.append(f"device type {device.device_type} not in {args.expect_type}")
            if args.expect_os and args.expect_os.lower() not in (device.operating_system or "").lower():
                problems.append(f"operating system {device.operating_system!r} lacks {args.expect_os!r}")
        if problems:
            print("CHECK FAILED: " + "; ".join(problems))
            return 1
    print("CHECK PASSED")
    return 0


def validate_specs(args):
    from device_monitoring_prototype.services import (
        AGENT_DEVICE_TYPES,
        validate_detected_specifications,
    )

    data = json.loads(Path(args.file).read_text(encoding="utf-8"))
    if data.get("device_type") not in AGENT_DEVICE_TYPES:
        print(f"INVALID device_type {data.get('device_type')!r}")
        return 1
    validated = validate_detected_specifications(data["specifications"])
    for key, value in validated.items():
        print(f"  {key}: {value}")
    print("SPECIFICATIONS VALID")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve_parser = commands.add_parser("serve")
    serve_parser.add_argument("--db", required=True)
    serve_parser.add_argument("--port", type=int, default=5077)
    serve_parser.add_argument("--link-file", required=True)
    serve_parser.add_argument("--links", type=int, default=2)
    # "localhost" is covered by iOS App Transport Security's NSAllowsLocalNetworking.
    serve_parser.add_argument("--link-host", default="localhost")
    check_parser = commands.add_parser("check")
    check_parser.add_argument("--db", required=True)
    check_parser.add_argument("--expect-count", type=int, default=1)
    check_parser.add_argument("--expect-type", nargs="*")
    check_parser.add_argument("--expect-os")
    validate_parser = commands.add_parser("validate-specs")
    validate_parser.add_argument("file")
    args = parser.parse_args()
    if args.command == "serve":
        serve(args)
        return 0
    return check(args) if args.command == "check" else validate_specs(args)


if __name__ == "__main__":
    sys.exit(main())
