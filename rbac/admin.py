from django.contrib import admin

from rbac import models

# Register your models here.
admin.site.register(models.CustomUser)
admin.site.register(models.Permission)
admin.site.register(models.Role)