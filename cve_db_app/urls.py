from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('upload_scan',views.upload_scan),
    path('cve_search', views.cve_search),
    path('ajax/get_cve_info/', views.ajax_get_cve_info),
]
