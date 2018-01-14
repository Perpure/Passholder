"""
Copyright (C) 2017-2018 Pavel Dyachek GPL 3.0+

This file is part of PassHolder.

    PassHolder is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    PassHolder is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with PassHolder.  If not, see <http://www.gnu.org/licenses/>.
"""
from django.shortcuts import render, redirect
from Crypto.Cipher import AES
from .models import Pass_info, Crypto
from .forms import PassForm, RegForm, AuthForm, FindForm, ChangePassForm
from django.db import IntegrityError
from django.utils import timezone
from django.conf import settings
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, logout, login
from django.contrib.auth.hashers import check_password
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import activation_token
from django.contrib.auth.models import User
from django.core.mail import EmailMessage


class Cred():
    def __init__(self, s, l, i, si):
        self.source = s
        self.login = l
        self.id = i
        self.showid = si


def index(request):
    return render(request, 'passes/index.html', {'title': 'PassHolder'})


def get_json(request):
    credid = request.GET['id']
    try:
        cred = Pass_info.objects.get(id=credid)
        if request.user.id == cred.userid:
            c = Crypto.objects.get(id=cred.crypto_id)
            cipher = AES.new(settings.AES_KEY, AES.MODE_EAX, nonce=c.nonce_p)
            password = cipher.decrypt(cred.password_text)
            try:
                cipher.verify(c.tag_p)
                password_r = password
            except ValueError:
                password_r = 'error'
        else:
            password_r = "error"
        if request.GET['cont'] == "Скрыть":
            return JsonResponse({"password": "",
                                 "id": str(credid),
                                 "show": "Показать"})
        else:
            return JsonResponse({"password": password_r.decode("utf-8"),
                                 "id": str(credid),
                                 "show": "Скрыть"})
    except:
        return JsonResponse({"password": "",
                             "id": str(credid),
                             "show": "Показать", })


@login_required(login_url='/auth/')
def add_info(request):
    if request.method == 'POST':
        form = PassForm(request.POST)
        if form.is_valid():
            sourceb = bytes(form.cleaned_data['source_text'], 'utf-8')
            cipher = AES.new(settings.AES_KEY, AES.MODE_EAX)
            s_nonce = cipher.nonce
            source, s_tag = cipher.encrypt_and_digest(sourceb)

            loginb = bytes(form.cleaned_data['login_text'], 'utf-8')
            cipher = AES.new(settings.AES_KEY, AES.MODE_EAX)
            l_nonce = cipher.nonce
            login, l_tag = cipher.encrypt_and_digest(loginb)

            passwordb = bytes(form.cleaned_data['password_text'], 'utf-8')
            cipher = AES.new(settings.AES_KEY, AES.MODE_EAX)
            p_nonce = cipher.nonce
            password, p_tag = cipher.encrypt_and_digest(passwordb)

            cr = Crypto(
                tag_s=s_tag,
                nonce_s=s_nonce,
                tag_l=l_tag,
                nonce_l=l_nonce,
                tag_p=p_tag,
                nonce_p=p_nonce,
                cr_date=timezone.now())
            cr.save()

            us = Pass_info(
                source_text=source,
                login_text=login,
                password_text=password,
                crypto=Crypto.objects.latest("cr_date"),
                userid=request.user.id)
            us.save()
            return render(request, 'passes/add_info.html', {'form': PassForm(),
                                                            'title': 'Добавление записи',
                                                            'msg': "Успешно добавлено"})
    else:
        form = PassForm()
    return render(request, 'passes/add_info.html', {'form': form,
                                                    'title': 'Добавление записи'})


@login_required(login_url='/auth/')
def get_info(request):
    cred = Pass_info.objects.filter(userid=request.user.id)
    out = []
    for q in cred:
        c = Crypto.objects.get(id=q.crypto_id)
        cipher = AES.new(settings.AES_KEY, AES.MODE_EAX, nonce=c.nonce_s)
        source = cipher.decrypt(q.source_text)
        try:
            cipher.verify(c.tag_s)
            source_r = source
        except ValueError:
            source_r = 'error'

        cipher = AES.new(settings.AES_KEY, AES.MODE_EAX, nonce=c.nonce_l)
        login = cipher.decrypt(q.login_text)
        try:
            cipher.verify(c.tag_l)
            login_r = login
        except ValueError:
            login_r = 'error'

        out.append(Cred(source_r, login_r, q.id, "showid" + str(q.id)))
    sortedout = out
    l = ""
    s = ""
    if request.method == 'POST':
        form = FindForm(request.POST)
        if form.is_valid():
            sortedout = []
            l = form.cleaned_data['login']
            s = form.cleaned_data['source']
            if l and s:
                for cr in out:
                    if str(cr.login).find(l) + 1 and str(cr.source).find(s) + 1:
                        sortedout.append(cr)
            elif l:
                for cr in out:
                    if str(cr.login).find(l) + 1:
                        sortedout.append(cr)
            elif s:
                for cr in out:
                    if str(cr.source).find(s) + 1:
                        sortedout.append(cr)
            else:
                sortedout = out
    else:
        form = FindForm()

    pagin = Paginator(sortedout, 10, orphans=3)
    page = request.GET.get('page')
    try:
        sortedout = pagin.page(page)
    except PageNotAnInteger:
        sortedout = pagin.page(1)
        page = 1
    except EmptyPage:
        sortedoutt = pagin.page(pagin.num_pages)
        page = pagin.num_pages
    return render(request, 'passes/get_info.html', {'curpage': page,
                                                    'form': form,
                                                    'out': sortedout,
                                                    's': s,
                                                    'l': l,
                                                    'title': 'Просмотр записей'})


@login_required(login_url='/auth/')
def delete_info(request):
    credid = request.GET['id']
    try:
        cred = Pass_info.objects.get(id=credid)
        if request.user.id == cred.userid:
            c = Crypto.objects.get(id=cred.crypto_id)
            cipher = AES.new(settings.AES_KEY, AES.MODE_EAX, nonce=c.nonce_s)
            source = cipher.decrypt(cred.source_text)
            try:
                cipher.verify(c.tag_s)
                source_r = source
            except ValueError:
                source_r = 'error'

            cipher = AES.new(settings.AES_KEY, AES.MODE_EAX, nonce=c.nonce_l)
            login = cipher.decrypt(cred.login_text)
            try:
                cipher.verify(c.tag_l)
                login_r = login
            except ValueError:
                login_r = 'error'
            if request.GET['del'] == 'no':
                return render(request, 'passes/delete_info.html', {'source': source_r,
                                                                   'login': login_r,
                                                                   'id': credid,
                                                                   'del': 0,
                                                                   'title': 'Удаление записи'})
            elif request.GET['del'] == 'yes':
                c.delete()
                cred.delete()
                return render(request, 'passes/delete_info.html', {'source': source_r,
                                                                   'login': login_r,
                                                                   'del': 1,
                                                                   'title': 'Удаление записи'})
        return render(request, 'passes/delete_info.html', {'del': 2,
                                                           'title': 'Удаление записи'})
    except:
        return render(request, 'passes/delete_info.html', {'del': 2,
                                                           'title': 'Удаление записи'})


@login_required(login_url='/auth/')
def download_info(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="%s.csv"' % request.user.username
    response.write('Ресурс;Логин;Пароль\n')
    cred = Pass_info.objects.filter(userid=request.user.id)
    out = []
    for q in cred:
        c = Crypto.objects.get(id=q.crypto_id)
        cipher = AES.new(settings.AES_KEY, AES.MODE_EAX, nonce=c.nonce_s)
        source = cipher.decrypt(q.source_text)
        try:
            cipher.verify(c.tag_s)
            source_r = source
        except ValueError:
            source_r = 'error'

        cipher = AES.new(settings.AES_KEY, AES.MODE_EAX, nonce=c.nonce_l)
        login = cipher.decrypt(q.login_text)
        try:
            cipher.verify(c.tag_l)
            login_r = login
        except ValueError:
            login_r = 'error'

        out.append(Cred(source_r, login_r, q.id, "showid" + str(q.id)))
    sortedout = []
    l = request.GET['login']
    s = request.GET['source']
    if l and s:
        for cr in out:
            if str(cr.login).find(l) + 1 and str(cr.source).find(s) + 1:
                cred = Pass_info.objects.get(id=cr.id)
                c = Crypto.objects.get(id=cred.crypto_id)
                cipher = AES.new(settings.AES_KEY, AES.MODE_EAX, nonce=c.nonce_p)
                password = cipher.decrypt(cred.password_text)
                try:
                    cipher.verify(c.tag_p)
                    password_r = password
                except ValueError:
                    password_r = 'error'
                response.write(cr.source.decode("utf-8") + ';' + cr.login.decode("utf-8") + ';' + password_r.decode(
                    "utf-8") + '\n')
    elif l:
        for cr in out:
            if str(cr.login).find(l) + 1:
                cred = Pass_info.objects.get(id=cr.id)
                c = Crypto.objects.get(id=cred.crypto_id)
                cipher = AES.new(settings.AES_KEY, AES.MODE_EAX, nonce=c.nonce_p)
                password = cipher.decrypt(cred.password_text)
                try:
                    cipher.verify(c.tag_p)
                    password_r = password
                except ValueError:
                    password_r = 'error'
                response.write(cr.source.decode("utf-8") + ';' + cr.login.decode("utf-8") + ';' + password_r.decode(
                    "utf-8") + '\n')
    elif s:
        for cr in out:
            if str(cr.source).find(s) + 1:
                cred = Pass_info.objects.get(id=cr.id)
                c = Crypto.objects.get(id=cred.crypto_id)
                cipher = AES.new(settings.AES_KEY, AES.MODE_EAX, nonce=c.nonce_p)
                password = cipher.decrypt(cred.password_text)
                try:
                    cipher.verify(c.tag_p)
                    password_r = password
                except ValueError:
                    password_r = 'error'
                response.write(cr.source.decode("utf-8") + ';' + cr.login.decode("utf-8") + ';' + password_r.decode(
                    "utf-8") + '\n')
    else:
        for cr in out:
            cred = Pass_info.objects.get(id=cr.id)
            c = Crypto.objects.get(id=cred.crypto_id)
            cipher = AES.new(settings.AES_KEY, AES.MODE_EAX, nonce=c.nonce_p)
            password = cipher.decrypt(cred.password_text)
            try:
                cipher.verify(c.tag_p)
                password_r = password
            except ValueError:
                password_r = 'error'
            response.write(
                cr.source.decode("utf-8") + ';' + cr.login.decode("utf-8") + ';' + password_r.decode("utf-8") + '\n')
    return response


def reg(request):
    if request.method == 'POST':
        form = RegForm(request.POST)
        if form.is_valid():
            login = form.cleaned_data['login']
            password = form.cleaned_data['password']
            password2 = form.cleaned_data['password2']
            email = form.cleaned_data['email']
            if User.objects.filter(email=email):
                return render(request, 'passes/reg.html', {'form': form,
                                                           'errormsg': "Такая почта уже зарегистрирована",
                                                           'title': 'Регистрация'})
            else:
                if password == password2:
                    try:
                        user = User.objects.create_user(login, email, password)
                        user.is_active = False
                        user.save()
                        mail_subject = 'Активируйте ваш аккаунт PassHolder.'
                        message = render_to_string('activate_email.html', {
                            'user': user,
                            'domain': get_current_site(request).domain,
                            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                            'token':activation_token.make_token(user),
                        })
                        email = EmailMessage(mail_subject, message, to=[email])
                        email.send()
                        return render(request, 'passes/email_confirm.html', {'msg':'Чтобы подтвердить ваш email, на почту '+user.email+' было отправлено письмо с инструкциями по активации. Если вы не получили письмо, проверьте папку спам, а также убедитесь, что указанная почта действительно ваша.'})
                    except IntegrityError:
                        return render(request, 'passes/reg.html', {'form': form,
                                                                   'errormsg': "Указанный пользователь уже существует!",
                                                                   'title': 'Регистрация'})
                    return render(request, 'passes/auth.html', {'title': 'Вход',
                                                                'form': AuthForm()})
                else:
                    return render(request, 'passes/reg.html', {'form': form,
                                                               'errormsg': "Пароли не совпадают! Попробуйте еще раз",
                                                               'title': 'Регистрация'})
    else:
        form = RegForm()
    return render(request, 'passes/reg.html', {'form': form,
                                               'errormsg': "",
                                               'title': 'Регистрация'})


def auth(request):
    if request.method == 'POST':
        form = AuthForm(request.POST)
        if form.is_valid():
            ulogin = form.cleaned_data['login']
            upassword = form.cleaned_data['password']
            user = authenticate(username=ulogin, password=upassword)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    next_url = request.GET.get('next')
                    if next_url:
                        return redirect(next_url)
                    else:
                        return redirect('/')
                else:
                    return render(request, 'passes/auth.html', {'form': form,
                                                                'errormsg': "Введенные данные верны, но пользователь не активен на данный момент",
                                                                'title': 'Вход'})
            else:
                return render(request, 'passes/auth.html', {'form': form,
                                                            'errormsg': "Введенные данные неверные",
                                                            'title': 'Вход'})
    else:
        form = AuthForm()
    return render(request, 'passes/auth.html', {'form': form,
                                                'errormsg': "",
                                                'title': 'Вход'})

def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        return render(request, 'passes/email_confirm.html', {'msg':'Вы успешно подтвердили почту, теперь вы можете начать работать с сайтом.'})
    else:
        return render(request, 'passes/email_confirm.html', {'msg':'Неверная ссылка активации'})

@login_required(login_url='/auth/')
def userpage(request):
    if request.method == 'POST':
        form = ChangePassForm(request.POST)
        if form.is_valid():
            passwordold = form.cleaned_data['passwordold']
            password = form.cleaned_data['password']
            password2 = form.cleaned_data['password2']
            if check_password(passwordold, request.user.password):
                if password == password2:
                    request.user.set_password(password)
                    ulogin = request.user.username
                    request.user.save()
                    user = authenticate(username=ulogin, password=password)
                    login(request, user)
                    return render(request, 'passes/userpage.html', {'form': ChangePassForm(),
                                                                    'msg': 'Ваш пароль успешно сменен',
                                                                    'title': request.user.username})
                else:
                    return render(request, 'passes/userpage.html', {'form': ChangePassForm(),
                                                                    'msg': 'Пароли не совпадают',
                                                                    'title': request.user.username})
            else:
                return render(request, 'passes/userpage.html', {'form': ChangePassForm(),
                                                                'msg': 'Неверный пароль',
                                                                'title': request.user.username})
    else:
        form = ChangePassForm()
    return render(request, 'passes/userpage.html', {'form': ChangePassForm(),
                                                    'title': request.user.username})

def email_confirm(request):
    return render(request, 'passes/email_confirm.html')

def logoutview(request):
    logout(request)
    return redirect('/')
