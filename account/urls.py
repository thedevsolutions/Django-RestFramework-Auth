from django.urls import path, include
from .views import (
    UserRegistrationView,
    UserLoginView,
    UserChangePasswordView,
    SendPasswordResetEmailView,
    UserPasswordResetView,
)

app_name = 'account'

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='registeration'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
]