from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.http import JsonResponse

from django.template import loader
from django.utils import timezone
from cve_db_app.forms import ScanUploadForm
from cve_db_app.models import Scan, Device, Vulnerability, Site
#from django.contrib.auth.models import Device
from django.utils.dateparse import parse_date
from datetime import datetime
import csv, requests, json


# Create your views here.

def index(request):
    template = loader.get_template('cve_db_app/index.html')
    #empty dict because no data is being passed.
    return HttpResponse(template.render({},request))

#TODO - place this in a helper class?!
def decode_utf8(input_iterator):
    for l in input_iterator:
        yield l.decode('utf-8')


def upload_scan(request):

    if request.method == 'POST':
        form = ScanUploadForm(request.POST)
        if form.is_valid():
            scan_entry = form.save(commit=False)
            scan_entry.date = timezone.now()
            scan_entry.save()
            #Save the Site Info
            site = Site(name=form.cleaned_data['site'])
            site.save()
            csv_file = request.FILES['file']
            #check if the file uploaded is a CSV file 
            if not csv_file.name.endswith('.csv'):
                return HttpResponse('<h1>No CSV file??</h1>')
            #if file is too large, return
            if csv_file.multiple_chunks():
                return HttpResponse("Uploaded file is too big (%.2f MB)." % (csv_file.size/(1000*1000),))
            
            #if we get this far lets process the CSV now.. 
            reader = csv.DictReader(decode_utf8(csv_file))
            for row in reader:
                lower_row = {k.lower(): v for k, v in row.items()}
                #TODO - replace with regex for the removal of all special chars
                minus_spec_row = {k.replace("?", ""): v for k, v in lower_row.items()}
                trimmed_row = {k.replace(" ", "_"): v for k, v in minus_spec_row.items()}
                #factor in foreign keys
                trimmed_row['scan_id'] = scan_entry.id
                device = Device(ip = trimmed_row['ip_address'], site_id = site.id)
                device.save()
                trimmed_row['device_id'] = device.id
                #pop out device specfic fields
                device_fields = ('dns_name', 'ip_address', 'netbios_name','mac_address')
                for key in device_fields:
                    if key in trimmed_row:
                        del trimmed_row[key]
                #remove all unecessary data like N/A, empty values, etc
                trimmed_row = {k:v for (k,v) in trimmed_row.items() if v != 'N/A' if v != 'n/a' if v != ''}
                #remove commas from integers (bid)
                for (k,v) in trimmed_row.items():
                    if (k=='bid'):
                        trimmed_row[k] = v.replace(',','')
                #convert datetime strings to valid formats
                datetime_fields = ('first_discovered','plugin_modification_date','last_observed','plugin_publication_date','vuln_publication_date','patch_publication_date')
                for key in datetime_fields:
                    if (key in trimmed_row):
                        trimmed_row[key] = parse_date(trimmed_row[key])
                #TODO - add Try Catch due to the data inconsistences 
                vuln = Vulnerability(**trimmed_row)
                vuln.save()
            #return render(request,'cve_db_app/detail.html',{'data':trimmed_row})
            return HttpResponse('<h1>Scan has been sucessfully uploaded.</h1>')
        else:
            return HttpResponse(form.errors)
            # template = loader.get_template('cve_db_app/index.html')
            # #empty dict because no data is being passed.
            # return HttpResponse(template.render({},request))
    else:
        form = ScanUploadForm()
        return render(request,'cve_db_app/upload_scan.html',{'form':form})


def process_csv(request):
    csv_file = request.FILES['file']
    #check if the file uploaded is a CSV file 
    if not csv_file.name.endswith('.csv'):
        return HttpResponse('<h1>No CSV file??</h1>')
    #if file is too large, return
    if csv_file.multiple_chunks():
        return HttpResponse("Uploaded file is too big (%.2f MB)." % (csv_file.size/(1000*1000),))
    
    #if we get this far lets process the CSV now.. 
    file_data = csv_file.read().decode("utf-8")

    lines = file_data.split("\n")
    return HttpResponse("Uploaded file is too big (%.2f MB)." % (lines))

        

def cve_search(request):

    if request.method == 'POST':
        #insert CVE API call
        CVE_SEARCHURL = "http://cve.circl.lu/api/cve/" + request.POST['cve-id']
        r = requests.get(CVE_SEARCHURL)
        if r.status_code != 200:
            return HttpResponse('Error %s.' % r.text)
        else:
            parsed_json = json.loads(r.text)
            data = {
                'cve_id' : parsed_json['id'],
                'cwe_id' : parsed_json['cwe'],
                'cvss_score': parsed_json['cvss'],
                'summary': parsed_json['summary']
            }
            return JsonResponse(data)
    else:
        return render(request,'cve_db_app/cve_search.html')


def ajax_get_cve_info(request):

        #insert CVE API call
        CVE_SEARCHURL = "http://cve.circl.lu/api/cve/" + request.GET['cve_id'];
        r = requests.get(CVE_SEARCHURL)
        if r.status_code != 200:
            return HttpResponse('Error %s.' % r.text)
        else:
            parsed_json = json.loads(r.text)
            data = {
                'cve_id' : parsed_json['id'],
                'cwe_id' : parsed_json['cwe'],
                'cvss_score': parsed_json['cvss'],
                'summary': parsed_json['summary']
            }
            return JsonResponse(data)



    

