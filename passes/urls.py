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
from django.conf.urls import url, include
import django
from django.contrib.auth import views
from . import views

app_name = 'passes'
urlpatterns = [
    url(r'^password_reset/$', 
        django.contrib.auth.views.password_reset, 
        {'post_reset_redirect' : '/password_reset/done/',
         'template_name': 'registration/password_reset.html'},
        name='password_reset'),
    url(r'^password_reset/done/$',
        django.contrib.auth.views.password_reset_done,
        {'template_name': 'registration/password_reset_done.html'},
        name='password_reset_done'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', 
        django.contrib.auth.views.password_reset_confirm, 
        {'post_reset_redirect' : '/reset/done/',
         'template_name': 'registration/password_reset_confirm.html'},
        name='password_reset_confirm'),
    url(r'^reset/done/$', 
        django.contrib.auth.views.password_reset_complete,
        {'template_name': 'registration/password_reset_complete.html'},
        name='password_reset_complete'),
    url(r'^$', views.index, name='index'),
    url(r'^add_info/$', views.add_info, name='add_info'),
    url(r'^get_info/$', views.get_info, name='get_info'),
    url(r'^reg/$', views.reg, name='reg'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.activate, name='activate'),
    url(r'^auth/$', views.auth, name='auth'),
    url(r'^logout/$', views.logoutview, name='logout'),
    url(r'^confirmation/$', views.confirmation, name='confirmation'),
    url(r'^ajax/json/$', views.get_json),
    url(r'^delete_info/$', views.delete_info, name='delete_info'),
    url(r'^download_info/&', views.download_info, name='download_info'),
    url(r'^userpage/$', views.userpage, name='userpage'),
    url(r'^email_confirm/$', views.email_confirm, name='email_confirm'),
]
