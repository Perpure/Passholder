from django import forms


class PassForm(forms.Form):
    source_text = forms.CharField(label='Ресурс', max_length=100)
    login_text = forms.CharField(label='Логин', max_length=100)
    password_text = forms.CharField(label='Пароль', max_length=100, widget=forms.PasswordInput())


class RegForm(forms.Form):
    login = forms.CharField(label='Логин', max_length=100)
    password = forms.CharField(label='Пароль', max_length=100, widget=forms.PasswordInput())
    password2 = forms.CharField(label='Повторите пароль', max_length=100, widget=forms.PasswordInput())
    email = forms.EmailField(label='Электронная почта')


class AuthForm(forms.Form):
    login = forms.CharField(label='Логин', max_length=100)
    password = forms.CharField(label='Пароль', max_length=100, widget=forms.PasswordInput())

class FindForm(forms.Form):
    source = forms.CharField(label='Ресурс', max_length=100, required=False)
    login = forms.CharField(label='Логин', max_length=100, required=False)

class DeleteForm(forms.Form):
    credid = forms.IntegerField(widget=forms.HiddenInput())
    
