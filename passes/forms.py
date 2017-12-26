from django import forms


class PassForm(forms.Form):
    source_text = forms.CharField(max_length=100,  widget=forms.TextInput(attrs={'placeholder': 'Ресурс'}))
    login_text = forms.CharField(max_length=100,  widget=forms.TextInput(attrs={'placeholder': 'Логин'}))
    password_text = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Пароль'}))


class RegForm(forms.Form):
    login = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Логин'}),  min_length=5)
    password = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Пароль'}),  min_length=8)
    password2 = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Повторите пароль'}),  min_length=8)
    email = forms.EmailField(widget=forms.TextInput(attrs={'placeholder': 'Эл. почта'}))


class AuthForm(forms.Form):
    login = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Логин'}))
    password = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Пароль'}))

class FindForm(forms.Form):
    source = forms.CharField(max_length=100, required=False, widget=forms.TextInput(attrs={'placeholder': 'Поиск по ресурсу'}))
    login = forms.CharField(max_length=100, required=False, widget=forms.TextInput(attrs={'placeholder': 'Поиск по логину'}))

class ChangePassForm(forms.Form):
    passwordold = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Прежний пароль'}))
    password = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Новый пароль'}),  min_length=8)
    password2 = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Повторите новый пароль'}),  min_length=8)
    
    
