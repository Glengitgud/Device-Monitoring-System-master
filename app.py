"""Vercel entrypoint.

Vercel loads this file from the repository root. The real application lives in
the device_monitoring_prototype package, whose modules import each other as
"device_monitoring_prototype.<module>", so the package must be imported from
here rather than deploying that folder as the project root.
"""

from device_monitoring_prototype.app import app

__all__ = ["app"]
