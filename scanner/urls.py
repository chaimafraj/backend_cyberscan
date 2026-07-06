from django.urls import path
from . import views
from . import auth_views
from . import client_views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from scanner.serializers import MyTokenObtainPairSerializer


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


urlpatterns = [
    # --- Auth Endpoints ---
    path('api/auth/register/', views.register_user, name='auth_register'),
    path('api/auth/login/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/change-password/', auth_views.change_password_view, name='change_password'),
    path('api/auth/logout/', auth_views.logout_view, name='logout'),

    # --- Scanner Endpoints ---
    path('api/test/', views.test_api),
    path('api/scans/', views.scans_list),
    path('api/scans/<int:pk>/', views.scan_detail),
    path('api/dashboard-stats/', views.dashboard_stats, name='dashboard_stats'),

    # --- Clients Endpoints (Admin) ---
    path('api/clients/', client_views.clients_list, name='clients_list'),
    path('api/clients/<int:pk>/', client_views.client_detail, name='client_detail'),

    # --- Sites Endpoints (Client) ---
    path('api/sites/', client_views.my_sites, name='my_sites'),
    path('api/sites/<int:pk>/', client_views.site_detail, name='site_detail'),
]