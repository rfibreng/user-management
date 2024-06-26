from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm, UserChangeForm, PasswordChangeForm
from .models import Role

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = get_user_model()
        fields = ('username', 'email', 'first_name', 'last_name', 'phone_number', 'role')

class CustomUserChangeForm(UserChangeForm):
    password = forms.CharField(required=False, widget=forms.PasswordInput, help_text="Leave blank if you don't want to change the password.")

    class Meta:
        model = get_user_model()
        fields = ('username', 'email', 'first_name', 'last_name', 'phone_number', 'role', 'password')

class RoleForm(forms.ModelForm):
    class Meta:
        model = Role
        fields = ['name', 'permissions']
        widgets = {
            'permissions': forms.CheckboxSelectMultiple,
        }

class UserSettingsForm(forms.ModelForm):
    class Meta:
        model = get_user_model()
        fields = ['username', 'first_name', 'last_name', 'email', 'phone_number']

class CustomPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    new_password1 = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    new_password2 = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))