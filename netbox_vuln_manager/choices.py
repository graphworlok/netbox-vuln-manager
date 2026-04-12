from utilities.choices import ChoiceSet


class SeverityChoices(ChoiceSet):
    key = "Vulnerability.severity"

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"

    CHOICES = [
        (CRITICAL, "Critical", "danger"),
        (HIGH, "High", "warning"),
        (MEDIUM, "Medium", "yellow"),
        (LOW, "Low", "info"),
        (INFO, "Informational", "secondary"),
        (NONE, "None", "secondary"),
    ]

    # Numeric weight for ordering (higher = more severe)
    WEIGHTS = {
        CRITICAL: 5,
        HIGH: 4,
        MEDIUM: 3,
        LOW: 2,
        INFO: 1,
        NONE: 0,
    }

    @classmethod
    def from_cvss(cls, score):
        """Map a CVSS numeric score to a severity string."""
        if score is None:
            return cls.NONE
        score = float(score)
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.NONE


class FindingStatusChoices(ChoiceSet):
    key = "VulnerabilityFinding.status"

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted_risk"
    FALSE_POSITIVE = "false_positive"

    CHOICES = [
        (OPEN, "Open", "danger"),
        (IN_PROGRESS, "In Progress", "warning"),
        (RESOLVED, "Resolved", "success"),
        (ACCEPTED, "Accepted Risk", "info"),
        (FALSE_POSITIVE, "False Positive", "secondary"),
    ]


class SourceTypeChoices(ChoiceSet):
    key = "VulnerabilitySource.source_type"

    CROWDSTRIKE = "crowdstrike"
    SECURITYSCORECARD = "securityscorecard"
    CSV = "csv"

    CHOICES = [
        (CROWDSTRIKE, "CrowdStrike Falcon Spotlight"),
        (SECURITYSCORECARD, "SecurityScorecard"),
        (CSV, "Generic CSV (Nexpose, etc.)"),
    ]


class AssetMatchStrategyChoices(ChoiceSet):
    key = "VulnerabilitySource.asset_match_strategy"

    IP = "ip"
    HOSTNAME = "hostname"
    BOTH = "both"

    CHOICES = [
        (IP, "IP Address"),
        (HOSTNAME, "Hostname"),
        (BOTH, "IP Address and Hostname (either)"),
    ]


class SyncStatusChoices(ChoiceSet):
    key = "VulnerabilitySource.last_sync_status"

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"

    CHOICES = [
        (SUCCESS, "Success", "success"),
        (PARTIAL, "Partial", "warning"),
        (FAILED, "Failed", "danger"),
    ]
