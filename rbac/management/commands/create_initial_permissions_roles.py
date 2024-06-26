from django.core.management.base import BaseCommand
from rbac.models import Permission, Role

class Command(BaseCommand):
    help = 'Create initial permissions and roles'

    def handle(self, *args, **options):
        # Define the permissions
        permissions = [
            'admin_apps',
            'help_desk_apps',
            'dashboard',
            'airflow',
            'data_modeler',
            'data_processor',
            'data_management'
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
                'help_desk_apps',
                'airflow',
                'data_modeler',
                'data_processor',
                'data_management'
            ],
            'viewer': [
                'dashboard'
            ]
        }

        # Create roles and assign permissions
        for role_name, perms in roles_permissions.items():
            role, created = Role.objects.get_or_create(name=role_name)

            # Clear existing permissions and update with new ones
            role.permissions.clear()
            for perm in perms:
                permission = Permission.objects.get(name=perm)
                role.permissions.add(permission)
            self.stdout.write(self.style.SUCCESS(f'Role "{role_name}" created or updated with permissions.'))
        
         # Check and delete 'starrocks' and 'hdfs' permissions if they exist
        for perm_name in ['starrocks', 'hdfs']:
            try:
                permission = Permission.objects.get(name=perm_name)
                permission.delete()
                self.stdout.write(self.style.SUCCESS(f'Permission "{perm_name}" deleted.'))
            except Permission.DoesNotExist:
                self.stdout.write(self.style.WARNING(f'Permission "{perm_name}" does not exist.'))
