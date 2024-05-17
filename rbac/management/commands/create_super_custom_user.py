from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from rbac.models import Role

class Command(BaseCommand):
    help = 'Create a superuser with a specific role'

    def handle(self, *args, **kwargs):
        User = get_user_model()
        username = 'admin'
        email = 'admin@gmail.com'
        password = 'root1234'
        role_name = 'superadmin'

        # Check if the role exists
        try:
            role = Role.objects.get(name=role_name)
        except Role.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'Role "{role_name}" does not exist.'))
            return

        # Check if the user already exists
        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(f'User "{username}" already exists.'))
        else:
            # Create the user with the specified role
            user = User.objects.create_superuser(username=username, email=email, password=password, role=role)
            self.stdout.write(self.style.SUCCESS(f'Superuser "{username}" with role "{role_name}" created successfully.'))
