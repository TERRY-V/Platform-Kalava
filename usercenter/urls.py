from django.conf.urls import url
from usercenter.views import UserCenter

from . import views

urlpatterns = [
        url(r'^login$', views.login, name="login"),
        url(r'^register$', views.register, name="register"),
        url(r'^main$', views.main, name="main"),
        url(r'^api$', views.api, name="api"),
        url(r'^api/(?P<api_id>[0-9]+)$', views.showAPI, name='showAPI'),
        url(r'^applyapi$', views.applyAPI, name="applyAPI"),
        url(r'^myapi$', views.myAPI, name="myAPI"),
        url(r'^forgetpassword$', views.forgetPassword, name="forgetPassword"),
        url(r'^changeprofile$', views.changeProfile, name="changeProfile"),
        url(r'^changepassword$', views.changePassword, name="changePassword"),
        url(r'^resetpassword/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>.+)/$', views.resetPassword, name="resetPassword"),
        url(r'^refreshcaptcha$', views.refreshCaptcha, name="refreshCaptcha"),
        url(r'^(?P<slug>\w+)check$', UserCenter.as_view()),
        ]
