from django.conf.urls import url

from . import views

app_name = 'passes'
urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^add_info/$', views.add_info, name='add_info'),
    url(r'^get_info/$', views.get_info, name='get_info'),
    url(r'^reg/$', views.reg, name='reg'),
    url(r'^success/$', views.success, name='success'),
    url(r'^auth/$', views.auth, name='auth'),
    
]
