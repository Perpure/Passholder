from django.conf.urls import url
from django.contrib.auth import views as auth_views
from . import views

app_name = 'passes'
urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^add_info/$', views.add_info, name='add_info'),
    url(r'^get_info/$', views.get_info, name='get_info'),
    url(r'^reg/$', views.reg, name='reg'),
    url(r'^auth/$', views.auth, name='auth'),
    url(r'^logout/$', views.logoutview, name='logout'),
    url(r'^ajax/json/$', views.get_json),
    url(r'^delete_info/$', views.delete_info, name='delete_info'),
    url(r'^download_info/&', views.download_info, name='download_info'),
    url(r'^userpage/$', views.userpage, name='userpage'),
    url(r'^password_reset/$', auth_views.password_reset, name='password_reset'),
    url(r'^password_reset/done/$', auth_views.password_reset_done, name='password_reset_done'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',auth_views.password_reset_confirm, name='password_reset_confirm'),
    url(r'^reset/done/$', auth_views.password_reset_complete, name='password_reset_complete'),
]
