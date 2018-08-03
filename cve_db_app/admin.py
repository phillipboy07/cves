from django.contrib import admin

# Register your models here.

from .models import Site,Scan

admin.site.register(Site)
admin.site.register(Scan)
