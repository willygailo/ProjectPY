"""CVE research module (NVD REST API 2.0 + CVE.org + SQLite TTL cache)."""

from s1shell.cve.models import CVERecord, CVESearchFilter, CVESearchResult, CVSSMetric
from s1shell.cve.service import CVEService

__all__ = ["CVERecord", "CVESearchFilter", "CVESearchResult", "CVSSMetric", "CVEService"]
