# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

# Create your views here.
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
import email
# import django.core.mail.send_mail 
# import mailjet_rest
from mailjet_rest import Client
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, update_session_auth_hash
from .forms import LoginForm, SignUpForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm, PasswordResetForm
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic.edit import UpdateView
from django.urls import reverse_lazy
from django.contrib.auth.models import User
from .forms import ChangeUsernameForm, ChangeEmailForm
# from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
from .models import User
from django.urls import reverse

user = get_user_model()


def login_view(request):
    form = LoginForm(request.POST)

    msg = None

    if request.method == "POST":

        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect("/")
            else:
                msg = 'Invalid credentials'
        else:
            msg = 'Error validating the form'

    return render(request, "authentication/login.html", {"form": form, "msg": msg})


def register_user(request):
    form = SignUpForm(request.POST or None)
    if request.method=='POST':
        if form.is_valid():
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            user = form.save(commit=False)
            user.is_active = False  # Désactivez le compte jusqu'à activation
            user.save()

            # Générer le lien d'activation pour la vue de confirmation
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            activation_link = f"{request.scheme}://{request.get_host()}/activate/{uid}/{token}/"

            api_key ='c271420fc766e2f9bf76ba649e08b642'
            api_secret ='3c2d7b04ea5871619dbb6ee6c1482eb5'

            mailjet = Client(auth=(api_key, api_secret))
            data = {
	            'FromEmail': 'lougbegnona@gmail.com',
	            'FromName': 'Django DJ',
	            'Subject': 'Activate your account',
                'Text-part': 'Bienvenu sur votre page d\activation',
	            # 'Html-part': 'Veuillez cliquer <a href=\"authentication/activation_email.html/\">ICI</a>!<br />',
                'Html-part': f'Veuillez cliquer sur le lien <a href="{activation_link}">Activate my account</a> pour activer votre compte.',
	            # 'HTMLPart': render_to_string('activation_email.html', {
                #             'user': user,
                #             'activation_link': activation_link,
                #         }),
                'Recipients': [{'Email':user.email}]
            }
            result = mailjet.send.create(data=data)
            # print(result.status_code)
            # print (result.json())
           

            try:
                response = mailjet.send.create(data=data)
                if response.status_code == 200:
                    return render(request,'authentication/login.html')
                else:
                    print(result.status_code)
                    # En cas d'échec de l'envoi de l'e-mail, journalisez l'erreur ou affichez un message d'erreur convivial.
                    print("Erreur lors de l'envoi de l'e-mail de confirmation :", response.content)
                    # Afficher un message d'erreur convivial pour l'utilisateur
                    form.add_error(None, "Désolé, une erreur s'est produite lors de l'envoi de l'e-mail de confirmation. Veuillez réessayer plus tard.")
            except Exception as e:
                # Gérer les autres erreurs éventuelles ici
                print("Erreur lors de l'envoi de l'e-mail de confirmation :",str(e))
                # Afficher un message d'erreur convivial pour l'utilisateur
                form.add_error(None, "Désolé, une erreur s'est produite lors de l'envoi de l'e-mail de confirmation. Veuillez réessayer plus tard.")
        else:
            print(form.errors)

    return render(request, 'authentication/register.html', {'form': form})

@login_required

def profil(request):
    username = request.POST.get('username')
    email = request.POST.get('email')
    password = request.POST.get('password')
    return render(request, 'authentication/profil.html')

def edit_profile(request):
    username = request.POST.get('username')
    email = request.POST.get('email')
    password = request.POST.get('password')
    return render(request, 'authentication/edit_profile.html')

def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():

            if request.user.check_password(form.cleaned_data['old_password']):
                if form.cleaned_data['new_password1'] == form.cleaned_data['new_password2']:
                    user = form.save()

                    update_session_auth_hash(request, user)
                    messages.success(request, 'Mot de passe changé avec succès.')
                    return redirect('/authentication/profil.html')
                else:
                    messages.error(request, "Le nouveau mot de passe et la confirmation sont différents.")
            else:
                messages.error(request, "Ancien mot de passe incorrect.")
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'authentication/change_password.html', {'form': form})

@login_required
def change_username(request):
    if request.method == 'POST':
        form = ChangeUsernameForm(request.POST)
        if form.is_valid():
            new_username = form.cleaned_data['new_username']
            user = request.user
            user.new_username = new_username
            user.save()
            return redirect('authentication/profil.html')  
    else:
        form = ChangeUsernameForm()
    return render(request, 'authentication/change_username.html', {'form': form})


def change_email(request):
    if request.method == 'POST':
        form = ChangeEmailForm(request.POST)
        if form.is_valid():
            new_email = form.cleaned_data['new_email']
            # Sauvegarder la nouvelle adresse e-mail dans la base de données ou dans le modèle personnalisé si vous l'avez créé
            # Par exemple :
            # request.user.email = new_email
            # request.user.save()
            return redirect('authentication/profil.html')  # Rediriger vers la page de profil ou une autre page
    else:
        form = ChangeEmailForm()

    return render(request, 'authentication/change_email.html', {'form': form})

def activate_account(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return render(request, 'authentication/activation_success.html')
        else:
            return render(request, 'authentication/activation_failed.html')
    except User.DoesNotExist:
        return render(request, 'authentication/activation_failed.html')


def reset_password(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.user, request.POST)
        if form.is_valid():
            try:
                user = User.objects.get(email=email)
                if request.user.check_email(form.cleaned_data['old_email']):

                    token = default_token_generator.make_token(user)
                    reset_password_url = reverse('password_reset_confirm', kwargs={'uidb64': user.pk, 'token': token})
                    reset_password_url = request.build_absolute_uri(reset_password_url)

                    api_key ='c271420fc766e2f9bf76ba649e08b642'
                    api_secret ='3c2d7b04ea5871619dbb6ee6c1482eb5'

                    mailjet = Client(auth=(api_key, api_secret))
                    data = {
	                    'FromEmail': 'lougbegnona@gmail.com',
	                    'FromName': 'Django DJ',
	                    'Subject': 'Réinitiliser votre mot de passe',
                        'Text-part': 'Bienvenu sur la page de réinitialisation',
	                    # 'Html-part': 'Veuillez cliquer <a href=\"authentication/activation_email.html/\">ICI</a>!<br />',
                        'Html-part': f'Veuillez cliquer sur le lien suivant :<a href="{reset_password_url}">REINITIALISER</a> pour continuer.',
	                    # 'HTMLPart': render_to_string('activation_email.html', {
                        #             'user': user,
                        #             'activation_link': activation_link,
                        #         }),
                        'Recipients': [{'Email':user.email}]
                    }
                    result = mailjet.send.create(data=data)
                else:
                    messages.error(request, "Ancienne adresse mail est incorrecte.")
                try:
                    response = mailjet.send.create(data=data)
                    if response.status_code == 200:
                        return render(request,'authentication/password_reset_confirm1.html')
                    else:
                        print(result.status_code)
                        # En cas d'échec de l'envoi de l'e-mail, journalisez l'erreur ou affichez un message d'erreur convivial.
                        print("Erreur lors de l'envoi de l'e-mail de confirmation :", response.content)
                        # Afficher un message d'erreur convivial pour l'utilisateur
                        form.add_error(None, "Désolé, une erreur s'est produite lors de l'envoi de l'e-mail de confirmation. Veuillez réessayer plus tard.")
                except Exception as e:
                    # Gérer les autres erreurs éventuelles ici
                    print("Erreur lors de l'envoi de l'e-mail de confirmation :",str(e))
                    # Afficher un message d'erreur convivial pour l'utilisateur
                    form.add_error(None, "Désolé, une erreur s'est produite lors de l'envoi de l'e-mail de confirmation. Veuillez réessayer plus tard.")
            except User.DoesNotExist:
                print("l'utilisateur n'existe pas")

        else:
            print(form.errors)
    else:
        form = PasswordResetForm(request.user)
    return render(request, 'authentication/password_reset_form.html', {'form': form})
                
def reset_password_confirm(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():

            if request.user.check_password(form.cleaned_data['old_password']):
                if form.cleaned_data['new_password1'] == form.cleaned_data['new_password2']:
                    user = form.save()

                    update_session_auth_hash(request, user)
                    messages.success(request, 'Mot de passe réinitialisé avec succès.')
                    return redirect('/authentication/login.html')
                else:
                    messages.error(request, "Le nouveau mot de passe et la confirmation sont différents.")
            else:
                messages.error(request, "Ancien mot de passe incorrect.")
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'authentication/reset_password_confirm1.html', {'form': form})       
       
       
       


#  if form.cleaned_data['new_password1'] == form.cleaned_data['new_password2']:
#                     user = form.save()

#                     update_session_auth_hash(request, user)
#                     messages.success(request, 'Mot de passe changé avec succès.')
#                     return redirect('/authentication/profil.html')
#                 else:
#                     messages.error(request, "Le nouveau mot de passe et la confirmation sont différents.")

# class CustomPasswordResetView(PasswordResetView):
#     template_name = 'authentication/password_reset_form.html'
#     email_template_name = 'authentication/update_email.html'

# class CustomPasswordResetDoneView(PasswordResetDoneView):
#     template_name = 'authentication/password_reset_done.html'

# class CustomPasswordResetConfirmView(PasswordResetConfirmView):
#     template_name = 'authentication/password_reset_confirm.html'

# class CustomPasswordResetCompleteView(PasswordResetCompleteView):
#     template_name = 'authentication/password_reset_complete.html'

def logout(request):
    return render(request, 'authentication/logout.html')   

#  @login_required
# class UpdateEmailView(LoginRequiredMixin, UpdateView):
#     template_name = 'update_email.html'
#     model = User
#     fields = ['email']
#     success_url = reverse_lazy('update_email')

#     def form_valid(self, form):
#         messages.success(self.request, 'Votre adresse e-mail a été mise à jour avec succès.')
#         return super().form_valid(form)

# def update_email(request):
#     return UpdateEmailView.as_view()(request, pk=request.user.id)
