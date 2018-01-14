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
from django import forms


class PassForm(forms.Form):
    source_text = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Ресурс'}))
    login_text = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Логин'}))
    password_text = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Пароль'}))


class RegForm(forms.Form):
    login = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Логин'}), min_length=5)
    password = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Пароль'}),
                               min_length=8)
    password2 = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Повторите пароль'}),
                                min_length=8)
    email = forms.EmailField(widget=forms.TextInput(attrs={'placeholder': 'Эл. почта'}))


class AuthForm(forms.Form):
    login = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Логин'}))
    password = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Пароль'}))


class FindForm(forms.Form):
    source = forms.CharField(max_length=100, required=False,
                             widget=forms.TextInput(attrs={'placeholder': 'Поиск по ресурсу'}))
    login = forms.CharField(max_length=100, required=False,
                            widget=forms.TextInput(attrs={'placeholder': 'Поиск по логину'}))


class ChangePassForm(forms.Form):
    passwordold = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Прежний пароль'}))
    password = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Новый пароль'}),
                               min_length=8)
    password2 = forms.CharField(max_length=100,
                                widget=forms.PasswordInput(attrs={'placeholder': 'Повторите новый пароль'}),
                                min_length=8)
