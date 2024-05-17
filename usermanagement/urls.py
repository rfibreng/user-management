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

    path('users/', user_list_view, name='user_list'),
    path('users/delete/<int:user_id>/', user_delete_view, name='user_delete'),
    path('users/update/<int:user_id>/', user_update_view, name='user_update'),
    path('users/create/', user_create_view, name='user_create'),
]
