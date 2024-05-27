"""
URL configuration for usermanagement project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from rbac.views import *

urlpatterns = [
    # path("admin/", admin.site.urls),
    path('', home_view, name='home'),
    path('logout/', logout_view, name='logout'),
    path('404/', custom_404, name='404'),
    path('login/', login_view, name='login'),
    path('callback/', callback, name='callback'),
    path('backchannel-logout/', backchannel_logout, name='backchannel_logout'),

    path('users/', user_list_view, name='user_list'),

    path('roles/', role_list_view, name='role_list'),
    path('roles/create/', role_create_view, name='role_create'),
    path('roles/update/<int:role_id>/', role_update_view, name='role_update'),
    path('roles/delete/<int:role_id>/', role_delete_view, name='role_delete'),
]
