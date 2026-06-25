from django.db import models


class ScamReport(models.Model):
    FRAUD_CATEGORIES = [
        ('PHISHING', 'Phishing'),
        ('PRIZE_FRAUD', 'Prize Fraud'),
        ('IMPERSONATION', 'Impersonation'),
        ('INVESTMENT_FRAUD', 'Investment Fraud'),
        ('ROMANCE_SCAM', 'Romance Scam'),
        ('NONE', 'None'),
    ]

    THREAT_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    SOURCE_TYPES = [
    ('TEXT', 'Text'),
    ('IMAGE', 'Image'),
    ('AUDIO', 'Audio'),
]

    fingerprint = models.CharField(max_length=64, unique=True, db_index=True)
    fraud_category = models.CharField(max_length=20, choices=FRAUD_CATEGORIES)
    threat_level = models.CharField(max_length=10, choices=THREAT_LEVELS)
    flagged_phrases = models.JSONField(default=list)
    explanation = models.TextField()
    recommended_action = models.TextField()
    report_count = models.PositiveIntegerField(default=1)
    source = models.CharField(max_length=10, choices=SOURCE_TYPES)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.fraud_category} | {self.threat_level} | {self.report_count} reports"


class ThreatActor(models.Model):
    CONTACT_TYPES = [
        ('PHONE', 'Phone'),
        ('WHATSAPP', 'WhatsApp'),
        ('BANK_ACCOUNT', 'Bank Account'),
        ('URL', 'URL'),
        ('EMAIL', 'Email'),
        ('ORG_NAME', 'Organisation Name'),
    ]

    contact_type = models.CharField(max_length=20, choices=CONTACT_TYPES)
    contact_value = models.CharField(max_length=255, db_index=True)
    label = models.CharField(max_length=255)
    report_count = models.PositiveIntegerField(default=1)
    fraud_categories = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('contact_type', 'contact_value')

    def __str__(self):
        return f"{self.contact_type}: {self.contact_value} | {self.report_count} reports"
    
class AuthorityReport(models.Model):
    AGENCIES = [
        ('EFCC', 'EFCC'),
        ('NITDA', 'NITDA'),
        ('CBN', 'CBN'),
        ('NPF', 'Nigeria Police Force'),
    ]

    scam_report = models.ForeignKey(ScamReport, on_delete=models.CASCADE, related_name='authority_reports')
    agency = models.CharField(max_length=20, choices=AGENCIES)
    reporter_note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Report to {self.agency} | {self.scam_report}"