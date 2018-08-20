from django.forms import ModelForm,forms
from django import forms
from cve_db_app.models import Scan

class ScanUploadForm(ModelForm,forms.Form):
    file = forms.FileField(required=False, label="Scan in CSV format")
    site = forms.CharField(required=True, label="Site Name that the Scan is based off of")
    class Meta:
        model = Scan
        fields = ['name']
        labels = {
            'name': ('Scan Name')
        }