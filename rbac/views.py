import os
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from .models import CustomUser, Role
from .forms import CustomPasswordChangeForm, CustomUserCreationForm, CustomUserChangeForm, RoleForm, UserSettingsForm
from django.contrib.auth import get_user_model
from django.contrib.auth import logout, update_session_auth_hash
from django.contrib import messages
from django.core.paginator import Paginator
from urllib.parse import urlencode
from usermanagement import settings
import requests
import base64
from django.http import HttpResponse
import json

def logout_view(request):
    logout(request)
    
    logout_url = (
        f"{settings.SSO_BASE_URL}/realms/{settings.SSO_REALM}/protocol/openid-connect/logout"
        f"?client_id={settings.SSO_CLIENT_ID}"
        f"&post_logout_redirect_uri={settings.SSO_POST_LOGOUT_REDIRECT_URI}"
    )
    
    return redirect(logout_url)

def custom_404(request):
    return render(request, '404.html', status=404)

def callback(request):
    code = request.GET.get('code')
    if not code:
        return HttpResponse("Error: No code parameter found in the request.", status=400)

    token_url = f"{settings.SSO_BASE_URL}/realms/{settings.SSO_REALM}/protocol/openid-connect/token"
    data = {
        'grant_type': 'authorization_code',
        'client_id': settings.SSO_CLIENT_ID,
        'client_secret': settings.SSO_CLIENT_SECRET,
        'code': code,
        'redirect_uri': settings.SSO_REDIRECT_URI
    }

    response = requests.post(token_url, data=data)
    if response.status_code != 200:
        return HttpResponse("Error: Failed to retrieve token from SSO provider.", status=response.status_code)

    json_response = response.json()
    access_token = json_response.get('access_token')
    if not access_token:
        return HttpResponse("Error: No access token found in the response.", status=400)

    # Decode the JWT token
    exploded = access_token.split('.')
    if len(exploded) != 3:
        return HttpResponse("Error: Invalid access token format.", status=400)

    base64_payload = exploded[1]
    # Add padding if necessary
    base64_payload += '=' * (4 - len(base64_payload) % 4)
    try:
        decoded_payload = base64.b64decode(base64_payload)
    except (TypeError, ValueError):
        return HttpResponse("Error: Failed to decode access token.", status=400)

    json_token = json.loads(decoded_payload)

    # Extract user information from the token
    username = json_token.get('preferred_username') or json_token.get('sub')
    email = json_token.get('email')
    first_name = json_token.get('given_name')
    last_name = json_token.get('family_name')
    resource_access = json_token.get('resource_access', {})
    print(json_token)

    # Determine the user's role
    app_roles = resource_access.get(settings.SSO_CLIENT_ID, {}).get('roles', [])
    app_roles = 'viewer' if len(app_roles) == 0 else app_roles[0]

    if not username:
        return HttpResponse("Error: No username found in the token.", status=400)

    # Create or update the user in the Django database
    user, created = CustomUser.objects.get_or_create(username=username, defaults={
        'email': email if email is not None else f'{username}@gmail.com',
        'username':username,
        'first_name': first_name if first_name is not None else username,
        'last_name': last_name if last_name is not None else username,
        'role': Role.objects.get(name=app_roles),
    })

    if not created:
        # Update user details if they already exist
        user.email = email if email is not None else user.email
        user.first_name = first_name if first_name is not None else user.first_name
        user.last_name = last_name if last_name is not None else user.last_name
        user.role = app_roles
        user.save()

    # Log the user in
    login(request, user)

    # Redirect to home after successful authentication
    return redirect('home')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')  # Redirect to home if the user is already authenticated

    query_params = {
        'client_id': settings.SSO_CLIENT_ID,
        'redirect_uri': settings.SSO_REDIRECT_URI,
        'scope': 'openid',
        'response_type': 'code'
    }
    
    sso_url = f"{settings.SSO_BASE_URL}/realms/{settings.SSO_REALM}/protocol/openid-connect/auth?{urlencode(query_params)}"
    
    return redirect(sso_url)

# def login_view(request):
#     if request.user.is_authenticated:
#         return redirect('home')  # Redirect to home if the user is already authenticated

#     if request.method == 'POST':
#         form = AuthenticationForm(request, data=request.POST)
#         if form.is_valid():
#             username = form.cleaned_data.get('username')
#             password = form.cleaned_data.get('password')
#             user = authenticate(request, username=username, password=password)
#             if user is not None:
#                 login(request, user)
#                 return redirect('home')  # Redirect to home after successful login
#     else:
#         form = AuthenticationForm()

#     return render(request, 'login.html', {'form': form})

@login_required(login_url='/login/')
def home_view(request):
    user = request.user
    permissions = user.role.permissions.values_list('name', flat=True)
    context = {
        'show_admin_menu': 'admin_apps' in permissions,
        'permissions': permissions,
        'hdfs_url': os.getenv('HDFS_URL', '#'),
        'dashboard_url': os.getenv('DASHBOARD_URL', '#'),
        'data_modeler_url': os.getenv('DATA_MODELER_URL', '#'),
        'data_processor_url': os.getenv('DATA_PROCESSOR_URL', '#'),
        'starrocks_url': os.getenv('STARROCKS_URL', '#'),
        'airflow_url': os.getenv('AIRFLOW_URL', '#')
    }
    return render(request, 'home.html', context)

@login_required(login_url='/login/')
def user_list_view(request):
    user_self = request.user
    is_admin_apps = user_self.role.permissions.filter(name='admin_apps').exists()
    if not is_admin_apps:
        return redirect('404')
    
    query = request.GET.get('q', '')
    User = get_user_model()
    
    if query:
        users = User.objects.filter(username__icontains=query)
    else:
        users = User.objects.all()

    paginator = Paginator(users, 20)  # Show 10 users per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'show_admin_menu': is_admin_apps,
        'page_obj': page_obj,
        'query': query,
    }
    return render(request, 'users.html', context)

@login_required(login_url='/login/')
def user_delete_view(request, user_id):
    user_self = request.user
    is_admin_apps = user_self.role.permissions.filter(name='admin_apps').exists()
    
    if not is_admin_apps:
        return redirect('404')
    
    user_to_delete = get_object_or_404(CustomUser, id=user_id)
    
    if user_self == user_to_delete:
        messages.error(request, "You cannot delete yourself.")
        return redirect('user_list')
    
    user_to_delete.delete()
    messages.success(request, "User deleted successfully.")
    return redirect('user_list')

@login_required(login_url='/login/')
def user_update_view(request, user_id):
    user_self = request.user
    is_admin_apps = user_self.role.permissions.filter(name='admin_apps').exists()
    if not is_admin_apps:
        return redirect('404')
    user = get_object_or_404(CustomUser, id=user_id)
    if request.method == 'POST':
        form = CustomUserChangeForm(request.POST, instance=user)
        if form.is_valid():
            user = form.save(commit=False)
            password = form.cleaned_data.get('password')
            if password:
                user.set_password(password)
                update_session_auth_hash(request, user)  # Important to keep the user logged in after password change
            user.save()
            messages.success(request, "User updated successfully.")
            return redirect('user_list')
    else:
        form = CustomUserChangeForm(instance=user)
    context = {
        'show_admin_menu': is_admin_apps,
        'form': form
    }
    return render(request, 'user_form.html', context)

@login_required(login_url='/login/')
def user_create_view(request):
    user_self = request.user
    is_admin_apps = user_self.role.permissions.filter(name='admin_apps').exists()
    if not is_admin_apps:
        return redirect('404')
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('user_list')
    else:
        form = CustomUserCreationForm()
    context = {
        'show_admin_menu': is_admin_apps,
        'form': form
    }
    return render(request, 'user_form.html', context)

@login_required(login_url='/login/')
def role_list_view(request):
    user_self = request.user
    is_admin_apps = user_self.role.permissions.filter(name='admin_apps').exists()
    if not is_admin_apps:
        return redirect('404')
    
    roles = Role.objects.all()
    paginator = Paginator(roles, 20)  # Show 20 roles per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'show_admin_menu': is_admin_apps,
        'page_obj': page_obj,
    }
    return render(request, 'roles.html', context)

@login_required(login_url='/login/')
def role_create_view(request):
    user_self = request.user
    is_admin_apps = user_self.role.permissions.filter(name='admin_apps').exists()
    if not is_admin_apps:
        return redirect('404')
    if request.method == 'POST':
        form = RoleForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Role created successfully.")
            return redirect('role_list')
    else:
        form = RoleForm()
    return render(request, 'role_form.html', {'form': form, 'show_admin_menu': is_admin_apps})

@login_required(login_url='/login/')
def role_update_view(request, role_id):
    user_self = request.user
    is_admin_apps = user_self.role.permissions.filter(name='admin_apps').exists()
    if not is_admin_apps:
        return redirect('404')
    role = get_object_or_404(Role, id=role_id)
    if request.method == 'POST':
        form = RoleForm(request.POST, instance=role)
        if form.is_valid():
            form.save()
            messages.success(request, "Role updated successfully.")
            return redirect('role_list')
    else:
        form = RoleForm(instance=role)
    return render(request, 'role_form.html', {'form': form, 'show_admin_menu': is_admin_apps})

@login_required(login_url='/login/')
def role_delete_view(request, role_id):
    user_self = request.user
    is_admin_apps = user_self.role.permissions.filter(name='admin_apps').exists()
    if not is_admin_apps:
        return redirect('404')
    role = get_object_or_404(Role, id=role_id)
    role.delete()
    messages.success(request, "Role deleted successfully.")
    return redirect('role_list')

@login_required(login_url='/login/')
def user_settings_view(request):
    user = request.user
    is_admin_apps = user.role.permissions.filter(name='admin_apps').exists()
    if request.method == 'POST':
        user_form = UserSettingsForm(request.POST, instance=user)
        password_form = CustomPasswordChangeForm(user, request.POST)
        
        if user_form.is_valid():
            user_form.save()
            messages.success(request, 'Your profile was successfully updated!')
            return redirect('user_settings')
        
        if password_form.is_valid():
            user = password_form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Your password was successfully updated!')
            return redirect('user_settings')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        user_form = UserSettingsForm(instance=user)
        password_form = CustomPasswordChangeForm(user)

    return render(request, 'user_settings.html', {
        'user_form': user_form,
        'password_form': password_form, 
        'show_admin_menu': is_admin_apps
    })