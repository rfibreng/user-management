from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from .models import CustomUser
from .forms import CustomUserCreationForm, CustomUserChangeForm
from django.contrib.auth import get_user_model
from django.contrib.auth import logout, update_session_auth_hash
from django.contrib import messages

def logout_view(request):
    logout(request)
    return redirect('login')

def custom_404(request):
    return render(request, '404.html', status=404)

def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')  # Redirect to home if the user is already authenticated

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')  # Redirect to home after successful login
    else:
        form = AuthenticationForm()

    return render(request, 'login.html', {'form': form})

@login_required(login_url='/login/')
def home_view(request):
    user = request.user
    context = {
        'show_admin_menu': user.role.permissions.filter(name='admin_apps').exists()
    }
    return render(request, 'home.html', context)

@login_required(login_url='/login/')
def user_list_view(request):
    user_self = request.user
    is_admin_apps = user_self.role.permissions.filter(name='admin_apps').exists()
    if not is_admin_apps:
        return redirect('404')
    User = get_user_model()
    users = User.objects.all()
    context = {
        'show_admin_menu': is_admin_apps,
        'users': users
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

