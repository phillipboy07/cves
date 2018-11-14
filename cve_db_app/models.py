from django.db import models
from datetime import datetime

# Create your models here.

#constants
STATUS_CHOICES = (
    ('On', 'Online'),
    ('Off', 'Offline'),
)

class Scan(models.Model):
    date = models.DateTimeField(blank=True)
    name = models.CharField(max_length=200, blank=True)
    
class Site(models.Model):
    name = models.CharField(max_length=200, blank=True)

class Contact(models.Model):
    first_name = models.CharField(max_length=200, blank=True)
    last_name = models.CharField(max_length=200, blank=True)
    gdit_group = models.CharField(max_length=200, blank=True)
    phone_number = models.CharField(max_length=200, blank=True)
    email_address = models.EmailField(max_length=200, blank=True) 

# Asset Mgmt from Dashboard View (broken up into Device and Device Location)
class Device(models.Model):
    site = models.ForeignKey(Site, on_delete=models.PROTECT)
    contact = models.ForeignKey(Contact, on_delete=models.PROTECT)
    dns_name = models.CharField(max_length=200, blank=True)
    ip = models.GenericIPAddressField()
    net_bios = models.CharField(max_length=200, blank=True)
    mac_address = models.CharField(max_length=200, blank=True)
    os_vendor = models.CharField(max_length=200, blank=True)
    os_type = models.CharField(max_length=200, blank=True)
    os_version = models.CharField(max_length=200, blank=True)
    os_revision = models.CharField(max_length=200, blank=True)
    switch = models.CharField(max_length=200, blank=True)
    port = models.CharField(max_length=200, blank=True)
    vlan = models.CharField(max_length=200, blank=True)
    make = models.CharField(max_length=200, null=True)
    model = models.CharField(max_length=200, null=True)
    serial_number = models.CharField(max_length=200, blank=True)
    asset_tag = models.CharField(max_length=200, blank=True)
    poc = models.CharField(max_length=200, blank=True)
    role = models.CharField(max_length=200, blank=True)
    function = models.CharField(max_length=200, blank=True)
    mission_criticality = models.CharField(max_length=200, blank=True)
    status = models.CharField(
        max_length=200, 
        choices=STATUS_CHOICES,
        default='On',
    )
# Asset Mgmt from Dashboard View (broken up into Device and Device Location) 
class Device_Location(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    building = models.CharField(max_length=200, blank=True)
    physical_location = models.CharField(max_length=200, blank=True)
    floor = models.CharField(max_length=200, blank=True)
    room = models.CharField(max_length=200, blank=True)
    rack_row = models.CharField(max_length=200, blank=True)
    rack_name = models.CharField(max_length=200, blank=True)
    rack_unit = models.CharField(max_length=200, blank=True)




# Potential Table for the processing the CVE scan data results
class Vulnerability(models.Model):
    scan = models.ForeignKey(Scan,on_delete=models.CASCADE)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    plugin = models.CharField(max_length=500,blank=True,null=True)
    plugin_name = models.CharField(max_length=200,blank=True,null=True)
    family = models.CharField(max_length=500,blank=True,null=True)
    severity = models.CharField(max_length=500,blank=True,null=True)
    protocol = models.CharField(max_length=500,blank=True,null=True)
    port = models.CharField(max_length=500,blank=True,null=True)
    exploit = models.CharField(max_length=50,blank=True,null=True)
    repository = models.CharField(max_length=500,blank=True,null=True)
    plugin_text = models.TextField(max_length=500, blank=True,null=True)
    cve = models.TextField(max_length=500,blank=True,null=True)
    first_discovered = models.DateTimeField(max_length=500,blank=True,null=True)
    last_observed = models.DateTimeField(max_length=500,blank=True,null=True)
    exploit_frameworks = models.CharField(max_length=500, blank=True,null=True)
    synopsis = models.CharField(max_length=500,blank=True,null=True)
    description = models.TextField(max_length=1000, blank=True,null=True)
    solution = models.CharField(max_length=500,blank=True,null=True)
    see_also = models.URLField(max_length=500, blank=True,null=True)
    risk_factor = models.CharField(max_length=50,blank=True,null=True)
    stig_severity = models.CharField(max_length=500, blank=True,null=True)
    cvss_base_score = models.DecimalField(blank=True, max_digits=5, decimal_places=2,null=True)
    cvss_temporal_score = models.DecimalField(blank=True, max_digits=5, decimal_places=2,null=True)
    cvss_vector = models.CharField(max_length=300,blank=True,null=True)
    cpe = models.TextField(max_length=500,blank=True,null=True)
    #bid = models.BigIntegerField(blank=True,null=True)
    bid = models.TextField(max_length=1000, blank=True,null=True)
    cross_references = models.CharField(max_length=500,blank=True,null=True)
    vuln_publication_date = models.CharField(max_length=500,blank=True,null=True)
    patch_publication_date = models.CharField(max_length=500,blank=True,null=True)
    plugin_publication_date = models.DateTimeField(blank=True,null=True)
    plugin_modification_date = models.DateTimeField(blank=True,null=True)
    exploit_ease = models.CharField(max_length=500,blank=True,null=True)
    check_type = models.CharField(max_length=300,blank=True,null=True)
    version = models.CharField(max_length=300,blank=True,null=True)

    class Meta:
        verbose_name_plural = "Vulnerabilities"
