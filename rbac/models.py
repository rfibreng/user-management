from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class CustomUser(AbstractUser):
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    role = models.ForeignKey('Role', on_delete=models.CASCADE)
    user_id = models.CharField(max_length=100, blank=True, null=True, unique=True)


class Permission(models.Model):
    CHOICES = [
        ('admin_apps', 'ADMIN APPS'),
        ('dashboard', 'Dashboard'),
        ('airflow', 'Airflow'),
        ('data_modeler', 'Data Modeler'),
        ('data_processor', 'Data Processor'),
        ('starrocks', 'Starrocks')
    ]
    name = models.CharField(max_length=255, choices=CHOICES, unique=True)

    def __str__(self):
        return self.name

class Role(models.Model):
    name = models.CharField(max_length=255, unique=True)
    permissions = models.ManyToManyField(Permission, related_name='roles')

    def __str__(self):
        return self.name