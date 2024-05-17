from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required

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

