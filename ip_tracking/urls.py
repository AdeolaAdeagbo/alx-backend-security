# ip_tracking/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),  # main page
    # add other paths as needed, e.g.,
    # path('log/', views.log_ip, name='log_ip'),
]
