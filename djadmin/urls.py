from django.conf.urls import url
from djadmin.views import DjadminCenter

from . import views

urlpatterns = [
        url(r'^$', views.login, name="login"),
        url(r'^login$', views.login, name="login"),
        url(r'^main$', views.main, name="main"),
        url(r'^setting$', views.setting, name="setting"),
        url(r'^api$', views.api, name="api"),
        url(r'^api/add$', views.addAPI, name="addAPI"),
        url(r'^api/(?P<api_id>[0-9]+)$', views.showAPI, name='showAPI'),
        url(r'^api/(?P<api_id>[0-9]+)/change$', views.changeAPI, name='changeAPI'),
        url(r'^api/(?P<api_id>[0-9]+)/delete$', views.deleteAPI, name='deleteAPI'),
        url(r'^api/(?P<api_id>[0-9]+)/param$', views.param, name='param'),
        url(r'^api/(?P<api_id>[0-9]+)/param/add$', views.addParam, name='addParam'),
        url(r'^api/(?P<api_id>[0-9]+)/param/(?P<param_id>[0-9]+)/change$', views.changeParam, name='changeParam'),
        url(r'^api/(?P<api_id>[0-9]+)/param/(?P<param_id>[0-9]+)/delete$', views.deleteParam, name='deleteParam'),
        url(r'^api/(?P<api_id>[0-9]+)/errno$', views.errno, name='errno'),
        url(r'^api/(?P<api_id>[0-9]+)/errno/add$', views.addErrno, name='addErrno'),
        url(r'^api/(?P<api_id>[0-9]+)/errno/(?P<errno_id>[0-9]+)/change$', views.changeErrno, name='changeErrno'),
        url(r'^api/(?P<api_id>[0-9]+)/errno/(?P<errno_id>[0-9]+)/delete$', views.deleteErrno, name='deleteErrno'),
        url(r'^menu$', views.menu, name="menu"),
        url(r'^menu/add$', views.addMenu, name="addMenu"),
        url(r'^menu/(?P<menu_id>[0-9]+)/change$', views.changeMenu, name='changeMenu'),
        url(r'^menu/(?P<menu_id>[0-9]+)/delete$', views.deleteMenu, name='deleteMenu'),
        url(r'^permission$', views.permission, name="permission"),
        url(r'^permission/add$', views.addPermission, name="addpermission"),
        url(r'^permission/(?P<permission_id>[0-9]+)/change$', views.changePermission, name='changePermission'),
        url(r'^permission/(?P<permission_id>[0-9]+)/delete$', views.deletePermission, name='deletePermission'),
        url(r'^log$', views.log, name="log"),
        url(r'^log/statistics$', views.logStatistics, name="logStatistics"),
        url(r'^user$', views.user, name="user"),
        url(r'^user/add$', views.addUser, name="addUser"),
        url(r'^user/(?P<user_id>[0-9]+)/changepassword$', views.changeUserPassword, name='changeUserPassword'),
        url(r'^user/(?P<user_id>[0-9]+)/changeprofile$', views.changeUserProfile, name='changeUserProfile'),
        url(r'^(?P<slug>\w+)check$', DjadminCenter.as_view()),
        ]

