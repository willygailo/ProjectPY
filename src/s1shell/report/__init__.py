"""Assessment report compiler combining CVE, profile, and fingerprint results."""

from s1shell.report.loader import load_artifacts
from s1shell.report.models import ReportBundle, ReportMetadata
from s1shell.report.service import ReportService

__all__ = ["ReportBundle", "ReportMetadata", "ReportService", "load_artifacts"]
