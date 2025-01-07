from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib import messages
from django.shortcuts import render, redirect
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash, authenticate, login, logout
from django.contrib.auth.forms import PasswordChangeForm
from django.core.exceptions import ValidationError

def login_view(request):
    if request.method == 'POST':
        username_or_email = request.POST['username']
        password = request.POST['password']

        if not username_or_email or not password:
            messages.error(request, "Username and password are required.")
            return render(request, 'authentication/login.html')

        user = authenticate(username=username_or_email, password=password) or \
               authenticate(email=username_or_email, password=password)

        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid credentials. Please try again.")

    return render(request, 'authentication/login.html')

def signup_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Basic validation
        if not username or not email or not password:
            messages.error(request, "All fields are required.")
            return render(request, 'authentication/signup.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, 'authentication/signup.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return render(request, 'authentication/signup.html')

        if len(password) < 8:
            messages.error(request, "Password must be at least 8 characters long.")
            return render(request, 'authentication/signup.html')

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'authentication/signup.html')

        # Create user
        user = User.objects.create_user(username=username, email=email, password=password)
        messages.success(request, "Account created successfully! Please log in.")
        return redirect('login')
    
    return render(request, 'authentication/signup.html')

def forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()

        if not email:
            messages.error(request, "Please enter your email.")
            return render(request, 'authentication/forgot_password.html')

        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:  
            messages.error(request, "No user with this email exists.")
            return render(request, 'authentication/forgot_password.html')

        token = default_token_generator.make_token(user)
        reset_link = request.build_absolute_uri(f"/reset-password/{user.pk}/{token}/")

        subject = "Password Reset Request"
        message = render_to_string('authentication/reset_email.html', {'reset_link': reset_link})
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

        messages.success(request, "Password reset instructions have been sent to your email.")
        return redirect('login')

    return render(request, 'authentication/forgot_password.html')

@login_required
def change_password_view(request):
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Keep the user logged in
            messages.success(request, "Your password has been successfully updated.")
            return redirect('dashboard')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = PasswordChangeForm(user=request.user)

    return render(request, 'authentication/change_password.html', {'form': form})

@login_required
def dashboard_view(request):
    return render(request, 'authentication/dashboard.html')

@login_required
def profile_view(request):
    return render(request, 'authentication/profile.html', {'user': request.user})

def reset_password_view(request, user_id, token):
    try:
        user = User.objects.get(pk=user_id)
        if default_token_generator.check_token(user, token):
            if request.method == 'POST':
                new_password = request.POST['password1']
                confirm_password = request.POST['password2']

                if new_password != confirm_password:
                    messages.error(request, "Passwords do not match.")
                    return redirect(request.path)

                user.set_password(new_password)
                user.save()
                messages.success(request, "Password reset successful. Please log in.")
                return redirect('login')

            return render(request, 'authentication/reset_password.html')
        else:
            messages.error(request, "Invalid or expired token.")
    except ObjectDoesNotExist:
        messages.error(request, "Invalid user.")
    
    return redirect('forgot_password')

def logout_view(request):
    logout(request)
    return redirect('login')
