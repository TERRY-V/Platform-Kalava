from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    # Examples:
    # url(r'^$', 'pynxl.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^', include('homepage.urls')),
    url(r'^captcha/', include('captcha.urls')),
    url(r'^grappelli/', include('grappelli.urls')),
    url(r'^usercenter/', include('usercenter.urls')),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^djadmin/', include('djadmin.urls')),
]

