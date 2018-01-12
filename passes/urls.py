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
    url(r'^ajax/json/$', views.get_json),
    url(r'^delete_info/$', views.delete_info, name='delete_info'),
    url(r'^download_info/&', views.download_info, name='download_info'),
    url(r'^userpage/$', views.userpage, name='userpage'),
    url(r'^email_confirm/$', views.email_confirm, name='email_confirm'),
]
