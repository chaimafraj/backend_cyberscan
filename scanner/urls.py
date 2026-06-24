from django.urls import path
from . import views

urlpatterns = [
    path('test/', views.test_api),
    path('scans/', views.scans_list),              # GET (list) + POST (create)
    path('scans/<int:pk>/', views.scan_detail),     # GET (one) + PUT (update) + DELETE
]