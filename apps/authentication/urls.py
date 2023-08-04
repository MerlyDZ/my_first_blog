# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path
from .views import reset_password, reset_password_confirm, login_view, register_user, change_password, logout, profil, change_email, edit_profile, activate_account, change_username
# from .views import CustomPasswordResetView, CustomPasswordResetDoneView, CustomPasswordResetConfirmView, CustomPasswordResetCompleteView
from django.contrib.auth.views import LogoutView
from django.contrib.auth import views as auth_views
from . import views
urlpatterns = [
    path('login/', login_view, name="login"),
    path('register/', register_user, name="register"),    
    path('profil/', profil, name="profil"),
    path('edit_profile/', edit_profile, name="edit_profile"),
    path('change_password/', change_password, name="change_password"),
    path('change_username/', change_username, name="change_username"),
    path('change_email/', change_email, name='change_email'),
    # path('update_email/', update_email, name="update_email"),
    path('logout/', logout, name="logout"),
    path('activate/<str:uidb64>/<str:token>/', activate_account, name='activate_account'),
    # path('forgot/', logout, name="logout"),
    # mot de passe oublié   
    path('reset_password/', reset_password, name='reset_password'),
    path('reset_password_confirm/', reset_password_confirm, name='reset_password_confirm'),

    # path('password_reset/done/', CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    # path('reset/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    # path('reset/done/', CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),
]