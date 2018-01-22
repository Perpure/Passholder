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
    source_text = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Ресурс', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}))
    login_text = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Логин', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}))
    password_text = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Пароль', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}))


class RegForm(forms.Form):
    login = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Логин', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}), min_length=5)
    password = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Пароль', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}),
                               min_length=8)
    password2 = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Повторите пароль', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}),
                                min_length=8)
    email = forms.EmailField(widget=forms.TextInput(attrs={'placeholder': 'Эл. почта', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}))


class AuthForm(forms.Form):
    login = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Логин', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}))
    password = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Пароль', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}))


class FindForm(forms.Form):
    source = forms.CharField(max_length=100, required=False,
                             widget=forms.TextInput(attrs={'placeholder': 'Поиск по ресурсу', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}))
    login = forms.CharField(max_length=100, required=False,
                            widget=forms.TextInput(attrs={'placeholder': 'Поиск по логину', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}))


class ChangePassForm(forms.Form):
    passwordold = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Прежний пароль', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}))
    password = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'placeholder': 'Новый пароль', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}),
                               min_length=8)
    password2 = forms.CharField(max_length=100,
                                widget=forms.PasswordInput(attrs={'placeholder': 'Повторите новый пароль', 'style':'-webkit-appearance: none; height: 27px; border-radius:2px; border: 1px solid #aaaaaa; padding: 0px 10px;'}),
                                min_length=8)

