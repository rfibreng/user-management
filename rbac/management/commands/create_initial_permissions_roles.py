from django.core.management.base import BaseCommand
from rbac.models import Permission, Role

class Command(BaseCommand):
    help = 'Create initial permissions and roles'

    def handle(self, *args, **options):
        # Define the permissions
        permissions = [
            'admin_apps',
            'dashboard',
            'airflow',
            'data_modeler',
            'data_processor',
            'starrocks',
            'hdfs'
        ]

        # Create permissions
        for perm in permissions:
            Permission.objects.get_or_create(name=perm)
            self.stdout.write(self.style.SUCCESS(f'Permission "{perm}" created or already exists.'))

        # Define roles and their permissions
        roles_permissions = {
            'superadmin': permissions,
            'admin': [
                'dashboard',
                'airflow',
                'data_modeler',
                'data_processor',
                'starrocks',
                'hdfs'
            ],
            'viewer': [
                'dashboard'
            ]
        }

        # Create roles and assign permissions
        for role_name, perms in roles_permissions.items():
            role, created = Role.objects.get_or_create(name=role_name)
            for perm in perms:
                permission = Permission.objects.get(name=perm)
                role.permissions.add(permission)
            self.stdout.write(self.style.SUCCESS(f'Role "{role_name}" created or updated with permissions.'))
