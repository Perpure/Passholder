from django.conf.urls import url

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
]
