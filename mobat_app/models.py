from django.db import models

class IPData(models.Model):
    SEMESTER_CHOICES = [
        ('PrimeiroSemestre', 'Primeiro Semestre'),
        ('SegundoSemestre', 'Segundo Semestre'),
        ('TerceiroSemestre', 'Terceiro Semestre'),
        ('Total', 'Total'),
    ]
    semester = models.CharField(max_length=50, choices=SEMESTER_CHOICES, db_index=True)
    IP = models.CharField(max_length=45, db_index=True)
    abuseipdb_is_whitelisted = models.BooleanField(null=True, blank=True)
    abuseipdb_confidence_score = models.IntegerField(null=True, blank=True)
    abuseipdb_country_code = models.CharField(max_length=2, null=True, blank=True)
    abuseipdb_isp = models.TextField(null=True, blank=True)
    abuseipdb_domain = models.TextField(null=True, blank=True)
    abuseipdb_total_reports = models.IntegerField(null=True, blank=True)
    abuseipdb_num_distinct_users = models.IntegerField(null=True, blank=True)
    abuseipdb_last_reported_at = models.DateTimeField(null=True, blank=True)
    virustotal_reputation = models.IntegerField(null=True, blank=True)
    virustotal_regional_internet_registry = models.CharField(max_length=100, null=True, blank=True)  # aumentado
    virustotal_as_owner = models.TextField(null=True, blank=True)
    harmless = models.IntegerField(null=True, blank=True)
    malicious = models.IntegerField(null=True, blank=True)
    suspicious = models.IntegerField(null=True, blank=True)
    undetected = models.IntegerField(null=True, blank=True)
    IBM_score = models.IntegerField(null=True, blank=True)
    IBM_average_history_Score = models.FloatField(null=True, blank=True)
    IBM_most_common_score = models.IntegerField(null=True, blank=True)
    virustotal_asn = models.CharField(max_length=100, null=True, blank=True)  
    SHODAN_asn = models.CharField(max_length=100, null=True, blank=True)      
    SHODAN_isp = models.TextField(null=True, blank=True)
    ALIENVAULT_reputation = models.IntegerField(null=True, blank=True)
    ALIENVAULT_asn = models.CharField(max_length=255, null=True, blank=True)  
    score_average_Mobat = models.FloatField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['semester', 'IP']),
            models.Index(fields=['abuseipdb_country_code']),
        ]

class Task(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title