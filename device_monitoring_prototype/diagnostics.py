"""Validation and persistence for one-time, endpoint-collected diagnostics."""

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from device_monitoring_prototype.models import (
    ActivityLog,
    DiagnosticCheck,
    DiagnosticRun,
    Log,
    db,
)

DIAGNOSTIC_TOKEN_LIFETIME = timedelta(minutes=15)
REPORT_LIMIT_BYTES = 192_000
ALLOWED_CATEGORIES = {"hardware", "software", "driver"}
ALLOWED_STATUSES = {"passed", "warning", "failed", "skipped"}


class DiagnosticValidationError(ValueError):
    """Raised when an endpoint report is malformed or its run token is invalid."""


def create_diagnostic_run(device, user):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    run = DiagnosticRun(
        device=device,
        initiated_by=user,
        status="running",
        summary="Waiting for the Device Agent to submit its report.",
        recommendation=json.dumps({"token_hash": token_hash}),
        started_at=datetime.now(timezone.utc),
    )
    db.session.add(run)
    db.session.add(Log(device_id=device.id, event="Endpoint diagnostics started"))
    db.session.add(
        ActivityLog(
            actor_user_id=user.id,
            event_type="device.diagnostics_started",
            entity_type="device",
            entity_id=device.id,
            details={"device_name": device.device_name},
        )
    )
    db.session.commit()
    return run, token


def _validate_score(value, field):
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100
    ):
        raise DiagnosticValidationError(f"{field} must be a whole-number score from 0 to 100.")


def _validate_issue(issue):
    fields = {
        "title": 160,
        "severity": 16,
        "description": 1000,
        "root_cause": 1000,
        "impact": 1000,
        "recommendation": 1000,
    }
    if not isinstance(issue, dict) or set(issue) != set(fields) | {"steps"}:
        raise DiagnosticValidationError("A diagnostic issue has an invalid structure.")
    for field, maximum in fields.items():
        value = issue.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            raise DiagnosticValidationError(f"Diagnostic issue {field} is invalid.")
    if issue["severity"] not in {"critical", "attention", "warning", "info"}:
        raise DiagnosticValidationError("A diagnostic issue has an unsupported severity.")
    steps = issue.get("steps")
    if (
        not isinstance(steps, list)
        or len(steps) > 12
        or any(not isinstance(step, str) or not step.strip() or len(step) > 500 for step in steps)
    ):
        raise DiagnosticValidationError("Diagnostic troubleshooting steps are invalid.")


def validate_health_report(report):
    if not isinstance(report, dict) or set(report) != {
        "scores", "checks", "issues", "summary"
    }:
        raise DiagnosticValidationError("The diagnostic report is incomplete.")
    scores = report["scores"]
    if not isinstance(scores, dict) or set(scores) != {
        "overall", "hardware", "software", "drivers", "components"
    }:
        raise DiagnosticValidationError("The diagnostic scores are incomplete.")
    for key in ("overall", "hardware", "software", "drivers"):
        _validate_score(scores[key], key)
    components = scores["components"]
    component_keys = {
        "cpu", "ram", "storage", "gpu", "network", "operating_system"
    }
    if not isinstance(components, dict) or set(components) != component_keys:
        raise DiagnosticValidationError("The component health scores are incomplete.")
    for key, value in components.items():
        _validate_score(value, key)

    checks = report["checks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= 40:
        raise DiagnosticValidationError("A diagnostic report must contain 1-40 checks.")
    names = set()
    for check in checks:
        if not isinstance(check, dict) or set(check) != {
            "name", "category", "status", "summary", "details"
        }:
            raise DiagnosticValidationError("A diagnostic check has an invalid structure.")
        name = check["name"]
        if not isinstance(name, str) or not name.strip() or len(name) > 120 or name in names:
            raise DiagnosticValidationError("Diagnostic check names must be unique and valid.")
        names.add(name)
        if not isinstance(check["category"], str) or check["category"] not in ALLOWED_CATEGORIES:
            raise DiagnosticValidationError("A diagnostic check has an invalid category.")
        if not isinstance(check["status"], str) or check["status"] not in ALLOWED_STATUSES:
            raise DiagnosticValidationError("A diagnostic check has an invalid status.")
        if not isinstance(check["summary"], str) or len(check["summary"]) > 2000:
            raise DiagnosticValidationError("A diagnostic check summary is too long.")
        details = check["details"]
        if not isinstance(details, dict):
            raise DiagnosticValidationError("Diagnostic check details must be an object.")
        _validate_score(details.get("score"), f"{name} score")
        issue = details.get("issue")
        if issue is not None:
            _validate_issue(issue)
    issues = report["issues"]
    if not isinstance(issues, list) or len(issues) > 40:
        raise DiagnosticValidationError("Diagnostic issues must be a list of at most 40 items.")
    for issue in issues:
        _validate_issue(issue)
    summary = report["summary"]
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 2000:
        raise DiagnosticValidationError("The diagnostic report summary is invalid.")
    try:
        serialized = json.dumps(report, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError) as error:
        raise DiagnosticValidationError("The diagnostic report contains unsupported values.") from error
    if len(serialized.encode("utf-8")) > REPORT_LIMIT_BYTES:
        raise DiagnosticValidationError("The diagnostic report exceeds the size limit.")
    return report


def complete_diagnostic_run(run_id, token, report):
    report = validate_health_report(report)
    if not isinstance(token, str) or not token:
        raise DiagnosticValidationError("A diagnostic authorization token is required.")
    expected_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    run = db.session.get(DiagnosticRun, run_id)
    if run is None or run.status != "running":
        raise DiagnosticValidationError("This diagnostic run is invalid or already completed.")
    try:
        credential = json.loads(run.recommendation or "{}")
    except json.JSONDecodeError:
        credential = {}
    stored_hash = credential.get("token_hash", "") if isinstance(credential, dict) else ""
    if not isinstance(stored_hash, str) or not hmac.compare_digest(stored_hash, expected_hash):
        raise DiagnosticValidationError("The diagnostic authorization token is invalid.")
    started_at = run.started_at
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - started_at > DIAGNOSTIC_TOKEN_LIFETIME:
        run.status = "failed"
        run.summary = "The diagnostic report arrived after its authorization expired."
        run.recommendation = None
        db.session.commit()
        raise DiagnosticValidationError("This diagnostic authorization has expired.")

    issue_titles = [issue["title"] for issue in report["issues"]]
    recommendation = (
        report["issues"][0]["recommendation"]
        if report["issues"]
        else "No immediate action is recommended by the checks that ran."
    )
    claim = db.session.execute(
        update(DiagnosticRun)
        .where(
            DiagnosticRun.id == run_id,
            DiagnosticRun.status == "running",
            DiagnosticRun.recommendation == json.dumps({"token_hash": credential["token_hash"]}),
        )
        .values(
            status="completed",
            summary=report["summary"],
            detected_problem="; ".join(issue_titles) or None,
            recommendation=recommendation,
            finished_at=datetime.now(timezone.utc),
        )
        .execution_options(synchronize_session=False)
    )
    if claim.rowcount != 1:
        db.session.rollback()
        raise DiagnosticValidationError("This diagnostic run has already been submitted.")

    for check in report["checks"]:
        db.session.add(
            DiagnosticCheck(
                run_id=run_id,
                check_name=check["name"],
                category=check["category"],
                status=check["status"],
                result_summary=check["summary"],
                details=check["details"],
            )
        )
    record_health_report(run, report)
    db.session.add(Log(device_id=run.device_id, event="Endpoint diagnostics completed"))
    db.session.add(
        ActivityLog(
            actor_user_id=run.initiated_by_user_id,
            event_type="device.diagnostics_completed",
            entity_type="diagnostic_run",
            entity_id=run_id,
            details={
                "overall_score": report["scores"]["overall"],
                "issue_count": len(report["issues"]),
            },
        )
    )
    db.session.commit()
    db.session.refresh(run)
    return run


def diagnostic_run_payload(run):
    checks = [
        {
            "name": check.check_name,
            "category": check.category,
            "status": check.status,
            "summary": check.result_summary,
            "details": check.details if isinstance(check.details, dict) else {},
        }
        for check in run.checks
    ]
    scores = {
        "overall": None,
        "hardware": None,
        "software": None,
        "drivers": None,
        "components": {},
    }
    for check in checks:
        if check["name"] == "Overall scores" and isinstance(check["details"], dict):
            stored_scores = check["details"].get("scores")
            if isinstance(stored_scores, dict):
                stored_components = stored_scores.get("components")

                def valid_score(value):
                    return value if type(value) is int and 0 <= value <= 100 else None

                scores = {
                    **scores,
                    **{
                        key: valid_score(stored_scores.get(key))
                        for key in ("overall", "hardware", "software", "drivers")
                    },
                    "components": (
                        {
                            key: valid_score(value)
                            for key, value in stored_components.items()
                        }
                        if isinstance(stored_components, dict)
                        else {}
                    ),
                }
            break
    issues = [
        check["details"]["issue"]
        for check in checks
        if check["details"].get("issue")
    ]
    for check in checks:
        if check["name"] != "Overall scores":
            continue
        stored_issues = check["details"].get("issues")
        if isinstance(stored_issues, list) and stored_issues:
            issues = stored_issues
        break
    return {
        "id": run.id,
        "status": run.status,
        "summary": run.summary,
        "detected_problem": run.detected_problem,
        "recommendation": (
            "Waiting for the Device Agent to submit its report."
            if run.status == "running"
            else run.recommendation
        ),
        "scores": scores,
        "issues": issues,
        "checks": checks,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }


def record_health_report(run, report):
    """Persist scores and issue summaries in an existing check row for history views."""
    run.checks.append(
        DiagnosticCheck(
            check_name="Overall scores",
            category="hardware",
            status="passed",
            result_summary="Overall, hardware, software, and driver health scores.",
            details={
                "scores": report["scores"],
                "issues": report["issues"],
                "summary": report["summary"],
                "scanned_at": datetime.now(timezone.utc).isoformat(),
            },
        )
    )
