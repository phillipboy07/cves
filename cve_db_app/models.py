from django.db import models



# Create your models here.

class Scan(models.Model):
    date = models.DateTimeField("scan date")

    
class Site(models.Model):
    name = models.CharField(max_length=200, blank=True)

class Device(models.Model):
    site = models.ForeignKey(Site, on_delete=models.PROTECT)
    dns_name = models.CharField(max_length=200, blank=True)
    ip = models.GenericIPAddressField()
    net_bios = models.CharField(max_length=200, blank=True)
    mac_address = models.CharField(max_length=200, blank=True)


# Potential Table for the processing the CVE scan data results
class Vulnerability(models.Model):
    device = models.ForeignKey(Device, on_delete=models.PROTECT)
    plugin = models.IntegerField()
    plugin_name = models.CharField(max_length=200)
    family = models.CharField(max_length=200)
    severity = models.CharField(max_length=200)
    protocol = models.CharField(max_length=200)
    port = models.CharField(max_length=200)
    exploit = models.CharField(max_length=50)
    repository = models.CharField(max_length=200)
    plugin_text = models.TextField(max_length=500, blank=True)
    cve = models.CharField(max_length=100,blank=True)
    first_discovered = models.DateTimeField(max_length=200)
    last_observed = models.DateTimeField(max_length=200)
    exploit_frameworks = models.CharField(max_length=200, blank=True)
    synopsis = models.CharField(max_length=200)
    description = models.TextField(max_length=500, blank=True)
    solution = models.CharField(max_length=200)
    see_also = models.URLField(max_length=200, blank=True)
    risk_factor = models.CharField(max_length=50)
    stig_severity = models.CharField(max_length=200, blank=True)
    cvss_base_score = models.DecimalField(blank=True)
    cvss_temporal_score = models.DecimalField(blank=True)
    cvss_vector = models.CharField(max_length=100,blank=True)
    cpe = models.CharField(max_length=100,blank=True)
    bid = models.BigIntegerField(blank=True)
    cross_references = models.CharField(max_length=200,blank=True)
    vuln_publication_date = models.CharField(max_length=200)
    patch_publication_date = models.CharField(max_length=200)
    plugin_publication_date = models.DateTimeField()
    plugin_modification_date = models.DateTimeField()
    exploit_ease = models.CharField(max_length=200,blank=True)
    check_type = models.CharField(max_length=100)
    version = models.CharField(max_length=100)
