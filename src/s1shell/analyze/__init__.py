"""Deep offline & passive security analyzers: CSP3, Email Auth (SPF/DMARC/DKIM), Headers & CVSS."""

from s1shell.analyze.models import (
    CSPAnalysisResult,
    CSPFinding,
    CVSSAnalysisResult,
    CVSSMetricDetail,
    EmailAuthAnalysisResult,
    EmailAuthFinding,
    HeaderOfflineResult,
)
from s1shell.analyze.service import AnalyzeService

__all__ = [
    "AnalyzeService",
    "CSPAnalysisResult",
    "CSPFinding",
    "CVSSAnalysisResult",
    "CVSSMetricDetail",
    "EmailAuthAnalysisResult",
    "EmailAuthFinding",
    "HeaderOfflineResult",
]
