from django.contrib import admin

# Register your models here.

from .models import Site,Device,Scan,Vulnerability as Vuln

admin.site.register(Site)
admin.site.register(Scan)
admin.site.register(Vuln)
admin.site.register(Device)