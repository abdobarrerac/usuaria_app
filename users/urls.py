from django.urls import path
from .views import RegisterView, UserDetailView, LoginView
from rest_framework.authtoken import views

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('profile/', UserDetailView.as_view(), name='profile'),
    path('login/', LoginView.as_view(), name='login'),
]
