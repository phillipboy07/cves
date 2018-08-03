from django.db import models
from django.contrib.postgres.fields import HStoreField




# Create your models here.

class Scan(models.Model):
    scan_date = models.DateTimeField("scan date")
    scan_results = HStoreField()

class Site(models.Model):
    site_name = models.CharField(max_length=200)

class Device(models.Model):
    site = models.ForeignKey(Site, on_delete=models.CASCADE)
    device_name = models.CharField(max_length=200)
    dns_name = models.CharField(max_length=200)
    device_ip = models.GenericIPAddressField()
    device_version = models.CharField(max_length=200)
    device_net_bios = models.CharField(max_length=200)



# Potential Table for the processing the CVE scan data results
# class Threat(models.Model)
