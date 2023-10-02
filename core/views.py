from django.shortcuts import redirect, render , get_object_or_404
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.decorators import login_required
from .utils import send_otp
from datetime import datetime
import pyotp
from django.contrib.auth.models import User


def login_view(request):
    error_message = None
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            send_otp(request)

            request.session['username'] = username
            return redirect('otp')
        else:
            error_message = "Invalid Username and Password "
    return render(request, 'login.html', {'error_message':error_message})

def otp_view(request):
    error_message = None
    if request.method == 'POST':
        otp = request.POST['otp']
        username = request.session['username']

        otp_secret_key = request.session['otp_secret_key']
        otp_valid_until = request.session['otp_valid_date']

        if otp_secret_key and otp_valid_until is not None:
            valid_until = datetime.fromisoformat(otp_valid_until)

            if valid_until > datetime.now():
                totp = pyotp.TOTP(otp_secret_key, interval=60)
                if totp.verify(otp):
                    user = get_object_or_404(User, username=username)
                    login(request, user)

                    del request.session['otp_secret_key']
                    del request.session['otp_valid_date']

                    return redirect('main')
                else:
                    error_message = 'Invalid One Time OTP !'
            else:
                error_message = 'One Time OTP has been Expired !'
        else:
            error_message = 'Oops Somethings went Wrong :('
    return render(request, 'otp.html', {'error_message':error_message})

@login_required
def main_view(request):
    return render(request, 'main.html', {})

def logout_view(request):
    logout(request)
    return redirect('login')
