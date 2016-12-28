# -*- coding: utf-8 -*-

import os
import json
import uuid
import datetime

from datetime import datetime, timedelta

from django.contrib import auth
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site

from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

from django.db import connection
from django.http import HttpResponse, Http404

from django.shortcuts import get_object_or_404
from django.shortcuts import redirect
from django.shortcuts import render

from django.template.defaulttags import register
from django.utils.http import (base36_to_int, is_safe_url, urlsafe_base64_decode, urlsafe_base64_encode)
from django.views.generic import View

from djadmin.models import SiteInfo, MenuInfo

from apiworks.models import ApiInfo, ApiPermission, ApiLog
from usercenter.forms import UserCreationForm
from usercenter.models import User

class DjadminCenter(View):

    def post(self, request, *args, **kwargs):
        slug = self.kwargs.get('slug')

        if slug == 'login':
            return self.login(request)
        elif slug == 'logout':
            return self.logout(request)
        raise PermissionDenied

    def login(self, request):
        username = request.POST.get("username")
        password = request.POST.get("password")

        context = {"status": 0}
        user = auth.authenticate(username=username, password=password)
        if user is not None and user.is_staff:
            auth.login(request, user)
        elif user is not None:
            context["status"] = -1
            context["errors"] = []
            context["errors"].append('用户名权限不够！')
        else:
            context["status"] = -1
            context["errors"] = []
            context["errors"].append(u'用户名或密码错误！')
        return HttpResponse(json.dumps(context), content_type="application/json")

    def logout(self, request):
        auth.logout(request)
        return HttpResponse({"status": 0})

def login(request):
    site_info = SiteInfo.objects.first()
    context = {'site_info': site_info}
    return render(request, 'djadmin/login.html', context)

@staff_member_required(login_url='/djadmin/login')
def main(request):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')

    api_list = ApiInfo.objects.all()

    stats = {}
    stats['api_num'] = ApiInfo.objects.count()
    stats['user_num'] = get_user_model().objects.count()
    stats['audit_num'] = ApiPermission.objects.filter(api_status=0).count()
    stats['request_num'] = ApiLog.objects.filter(created_time__gte=datetime.now().date()).count()

    context = {'site_info': site_info, 
        'menu_list': menu_list,
        'api_list': api_list,
        'time_now': datetime.now(),
        'stats': stats}
    return render(request, 'djadmin/main.html', context)

@staff_member_required(login_url='/djadmin/login')
def setting(request):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/setting')

    if request.method == 'POST':
        site_info.site_name = request.POST.get('name')
        site_info.site_slogan = request.POST.get('slogan')
        site_info.site_athor = request.POST.get('author')
        site_info.site_keywords = request.POST.get('keywords')
        site_info.site_description = request.POST.get('description')
        site_info.site_copyright = request.POST.get('copyright')
        site_info.site_license = request.POST.get('license')
        site_info.site_email = request.POST.get('email')
        site_info.site_phone = request.POST.get('phone')
        site_info.save()
        messages.add_message(request, messages.INFO, u'系统设置信息保存成功！')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now}
    return render(request, 'djadmin/setting.html', context)

@staff_member_required(login_url='/djadmin/login')
def menu(request):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/menu')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now}
    return render(request, 'djadmin/menu.html', context)

@staff_member_required(login_url='/djadmin/login')
def addMenu(request):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/menu')

    if request.method == 'POST':
        name = request.POST.get('name')
        pid = request.POST.get('pid')
        link = request.POST.get('link')
        order = request.POST.get("order")
        visible = request.POST.get("visible")
        menu = MenuInfo(menu_name=name, menu_pid=pid, menu_link=link, menu_order=order, menu_visible=visible)
        menu.save()
        messages.add_message(request, messages.INFO, u'菜单信息添加成功！')
        return redirect('/djadmin/menu')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now}
    return render(request, 'djadmin/addmenu.html', context)

@staff_member_required(login_url='/djadmin/login')
def changeMenu(request, menu_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/menu')

    menu = get_object_or_404(MenuInfo, id=menu_id)
    if request.method == 'POST':
        menu.menu_name = request.POST.get('name')
        menu.menu_pid = request.POST.get('pid')
        menu.menu_link = request.POST.get('link')
        menu.menu_order = request.POST.get("order")
        menu.menu_visible = request.POST.get("visible")
        menu.save()
        messages.add_message(request, messages.INFO, u'菜单信息保存成功！')
        return redirect('/djadmin/menu')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu': menu,
            'menu_now': menu_now}
    return render(request, 'djadmin/changemenu.html', context)

@staff_member_required(login_url='/djadmin/login')
def deleteMenu(request, menu_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/menu')

    menu = get_object_or_404(MenuInfo, id=menu_id)
    menu.delete()
    messages.add_message(request, messages.INFO, u'菜单信息删除成功！')
    return redirect('/djadmin/menu')

''' user '''
@staff_member_required(login_url='/djadmin/login')
def user(request):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/user')

    user_list = get_user_model().objects.all()
    keyword = request.GET.get('q')
    if keyword and len(keyword):
        user_list = user_list.filter(username=keyword.encode('utf-8'))

    page = request.GET.get('page', 1)
    paginator = Paginator(user_list, 20)
    try:
        page = int(page)
        users = paginator.page(page)
    except PageNotAnInteger:
        users = paginator.page(1)
    except EmptyPage:
        users = []

    if page >= 5:
        page_range = list(paginator.page_range)[page-5: page+4]
    else:
        page_range = list(paginator.page_range)[0: page+4]

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'page_range': page_range,
            'users': users,
            'query_num': len(user_list)}
    return render(request, 'djadmin/user.html', context)

@staff_member_required(login_url='/djadmin/login')
def addUser(request):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/user')

    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            new_user = form.save()
            messages.add_message(request, messages.INFO, u'添加用户成功！')
            return redirect('/djadmin/user')
        else:
            for k, v in form.errors.items():
                messages.add_message(request, messages.INFO, v.as_text())

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now}
    return render(request, 'djadmin/adduser.html', context)

@staff_member_required(login_url='/djadmin/login')
def changeUserPassword(request, user_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/user')

    user = get_object_or_404(get_user_model(), id=user_id)
    if request.method == 'POST':
        form = SetPasswordForm(user, request.POST)
        if form.is_valid():
            user = form.save()
            messages.add_message(request, messages.INFO, u'用户信息编辑成功！')
            return redirect('/djadmin/user')
        else:
            for k, v in form.errors.items():
                messages.add_message(request, messages.INFO, k + ' ' + v.as_text())

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'user': user,
            'menu_now': menu_now}
    return render(request, 'djadmin/changepassword.html', context)

@staff_member_required(login_url='/djadmin/login')
def changeUserProfile(request, user_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/user')

    user = get_object_or_404(get_user_model(), id=user_id)
    if request.method == 'POST':
        user.email = request.POST.get('email')
        user.address = request.POST.get('address')
        user.phone = request.POST.get('phone')
        user.intro = request.POST.get('intro')
        if len(request.FILES):
            avatar_blob = request.FILES['upload-avatar']
            avatar_path = 'static/avatar/%s.jpg' % user_id
            with open(avatar_path, 'wb+') as destination:
                for chunk in avatar_blob.chunks():
                    destination.write(chunk)
            user.img = '/' + avatar_path
        user.save()
        user.save()
        messages.add_message(request, messages.INFO, u'用户信息保存成功！')
        return redirect('/djadmin/user')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'user': user,
            'menu_now': menu_now}
    return render(request, 'djadmin/changeprofile.html', context)

''' API '''
@staff_member_required(login_url='/djadmin/login')
def api(request):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    api_list = ApiInfo.objects.all()
    keyword = request.GET.get('q')
    if keyword and len(keyword):
        api_list = api_list.filter(api_name__contains=keyword.encode('utf-8'))

    page = request.GET.get('page', 1)
    paginator = Paginator(api_list, 20)
    try:
        page = int(page)
        apis = paginator.page(page)
    except PageNotAnInteger:
        apis = paginator.page(1)
    except EmptyPage:
        apis = []

    if page >= 5:
        page_range = list(paginator.page_range)[page-5: page+4]
    else:
        page_range = list(paginator.page_range)[0: page+4]

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'page_range': page_range,
            'apis': apis,
            'query_num': len(api_list)}
    return render(request, 'djadmin/api.html', context)

def showAPI(request, api_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    api = get_object_or_404(ApiInfo, id=api_id)
    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'api': api,}
    return render(request, 'djadmin/showapi.html', context)

@staff_member_required(login_url='/djadmin/login')
def addAPI(request):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    if request.method == 'POST':
        name = request.POST.get('name')
        provider = request.POST.get('provider')
        keywords = request.POST.get('keywords')
        description = request.POST.get('description')
        url = request.POST.get("url")
        method = request.POST.get("method")
        request_sample = request.POST.get("request_sample")
        reply_sample = request.POST.get("reply_sample")
        api = ApiInfo(api_name=name, 
            api_provider=provider,
            api_keywords=keywords,
            api_description=description,
            api_url=url,
            api_method=method,
            request_sample=request_sample,
            reply_sample=reply_sample)
        api.save()
        messages.add_message(request, messages.INFO, u'服务API添加成功！')
        return redirect('/djadmin/api')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now}
    return render(request, 'djadmin/addapi.html', context)

@staff_member_required(login_url='/djadmin/login')
def changeAPI(request, api_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    api = get_object_or_404(ApiInfo, id=api_id)
    if request.method == 'POST':
        api.api_name = request.POST.get('name')
        api.api_provider = request.POST.get('provider')
        api.api_keywords = request.POST.get('keywords')
        api.api_description = request.POST.get('description')
        api.api_url = request.POST.get("url")
        api.api_method = request.POST.get("method")
        api.request_sample = request.POST.get("request_sample")
        api.reply_sample = request.POST.get("reply_sample")
        api.save()
        messages.add_message(request, messages.INFO, u'服务信息保存成功！')
        return redirect('/djadmin/api')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'api': api,
            'menu_now': menu_now}
    return render(request, 'djadmin/changeapi.html', context)

@staff_member_required(login_url='/djadmin/login')
def deleteAPI(request, api_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    api = get_object_or_404(ApiInfo, id=api_id)
    api.delete()
    messages.add_message(request, messages.INFO, u'服务信息删除成功！')
    return redirect('/djadmin/api')

@staff_member_required(login_url='/djadmin/login')
def param(request, api_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    api = get_object_or_404(ApiInfo, id=api_id)
    param_list = api.apiparam_set.all().order_by('param_order')

    page = request.GET.get('page', 1)
    paginator = Paginator(param_list, 20)
    try:
        page = int(page)
        params = paginator.page(page)
    except PageNotAnInteger:
        params = paginator.page(1)
    except EmptyPage:
        params = []

    if page >= 5:
        page_range = list(paginator.page_range)[page-5: page+4]
    else:
        page_range = list(paginator.page_range)[0: page+4]

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'page_range': page_range,
            'api': api,
            'params': params,
            'query_num': len(param_list)}
    return render(request, 'djadmin/param.html', context)

@staff_member_required(login_url='/djadmin/login')
def addParam(request, api_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    api = get_object_or_404(ApiInfo, id=api_id)
    if request.method == 'POST':
        name = request.POST.get('name')
        param_type = request.POST.get('type')
        requested = request.POST.get('requested')
        location = request.POST.get('location')
        default = request.POST.get('default')
        order = request.POST.get('order')
        description = request.POST.get('description')
        api.apiparam_set.create(param_name=name, 
            param_type=param_type, 
            param_requested=requested, 
            param_location=location, 
            param_default=default, 
            param_order=order, 
            param_description=description)
        messages.add_message(request, messages.INFO, u'服务添加参数成功！')
        return redirect('/djadmin/api/' + api_id + '/param')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'api': api}
    return render(request, 'djadmin/addparam.html', context)

@staff_member_required(login_url='/djadmin/login')
def changeParam(request, api_id, param_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    api = get_object_or_404(ApiInfo, id=api_id)
    param = api.apiparam_set.get(id=param_id)
    if request.method == 'POST':
        param.param_name = request.POST.get('name')
        param.param_type = request.POST.get('type')
        param.param_requested = request.POST.get('requested')
        param.param_location = request.POST.get('location')
        param.param_default = request.POST.get('default')
        param.param_order = request.POST.get('order')
        param.param_description = request.POST.get('description')
        param.save()
        messages.add_message(request, messages.INFO, u'参数信息编辑成功！')
        return redirect('/djadmin/api/' + api_id + '/param')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'api': api,
            'param': param}
    return render(request, 'djadmin/changeparam.html', context)

@staff_member_required(login_url='/djadmin/login')
def deleteParam(request, api_id, param_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    api = get_object_or_404(ApiInfo, id=api_id)
    param = api.apiparam_set.filter(id=param_id)
    param.delete()
    messages.add_message(request, messages.INFO, u'参数信息删除成功！')
    return redirect('/djadmin/api/' + api_id + '/param')

@staff_member_required(login_url='/djadmin/login')
def errno(request, api_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    api = get_object_or_404(ApiInfo, id=api_id)
    errno_list = api.apierrno_set.all().order_by('-errno')

    page = request.GET.get('page', 1)
    paginator = Paginator(errno_list, 20)
    try:
        page = int(page)
        errnos = paginator.page(page)
    except PageNotAnInteger:
        errnos = paginator.page(1)
    except EmptyPage:
        errnos = []

    if page >= 5:
        page_range = list(paginator.page_range)[page-5: page+4]
    else:
        page_range = list(paginator.page_range)[0: page+4]

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'page_range': page_range,
            'api': api,
            'errnos': errnos,
            'query_num': len(errno_list)}
    return render(request, 'djadmin/errno.html', context)

@staff_member_required(login_url='/djadmin/login')
def addErrno(request, api_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    api = get_object_or_404(ApiInfo, id=api_id)
    if request.method == 'POST':
        errno = request.POST.get('errno')
        errno_message = request.POST.get('errno_message')
        errno_intro = request.POST.get('errno_intro')
        api.apierrno_set.create(errno=errno, errno_message=errno_message, errno_intro=errno_intro)
        messages.add_message(request, messages.INFO, u'添加错误码成功！')
        return redirect('/djadmin/api/' + api_id + '/errno')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'api': api}
    return render(request, 'djadmin/adderrno.html', context)

@staff_member_required(login_url='/djadmin/login')
def changeErrno(request, api_id, errno_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    api = get_object_or_404(ApiInfo, id=api_id)
    errno = api.apierrno_set.get(id=errno_id)
    if request.method == 'POST':
        errno.errno = request.POST.get('errno')
        errno.errno_message = request.POST.get('errno_message')
        errno.errno_intro = request.POST.get('errno_intro')
        errno.save()
        messages.add_message(request, messages.INFO, u'错误码信息编辑成功！')
        return redirect('/djadmin/api/' + api_id + '/errno')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'api': api,
            'errno': errno}
    return render(request, 'djadmin/changeerrno.html', context)

@staff_member_required(login_url='/djadmin/login')
def deleteErrno(request, api_id, errno_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/api')

    api = get_object_or_404(ApiInfo, id=api_id)
    errno = api.apierrno_set.filter(id=errno_id)
    errno.delete()
    messages.add_message(request, messages.INFO, u'错误码删除成功！')
    return redirect('/djadmin/api/' + api_id + '/errno')

@staff_member_required(login_url='/djadmin/login')
def permission(request):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/permission')

    permission_list = ApiPermission.objects.all().order_by('-created_time')

    username = request.GET.get('username')
    if username and len(username):
    	user = get_object_or_404(get_user_model(), username=username)
        permission_list = permission_list.filter(user_id=user.id)

    page = request.GET.get('page', 1)
    paginator = Paginator(permission_list, 20)
    try:
        page = int(page)
        permissions = paginator.page(page)
    except PageNotAnInteger:
        permissions = paginator.page(1)
    except EmptyPage:
        permissions = []

    if page >= 5:
        page_range = list(paginator.page_range)[page-5: page+4]
    else:
        page_range = list(paginator.page_range)[0: page+4]

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'page_range': page_range,
            'permissions': permissions,
            'query_num': len(permission_list)}
    return render(request, 'djadmin/permission.html', context)

@staff_member_required(login_url='/djadmin/login')
def addPermission(request):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/permission')

    api_list = ApiInfo.objects.all()
    if request.method == 'POST':
        username = request.POST.get('username')
        api_id = request.POST.get('api_id')
        expired_time = request.POST.get('expired_time')
        status = request.POST.get('status')
        permission = ApiPermission()
        permission.api = ApiInfo.objects.get(id=api_id)
        permission.user = get_object_or_404(get_user_model(), username=username)
        permission.api_key = uuid.uuid4()
        permission.expired_time = datetime.strptime(expired_time, '%m/%d/%Y')
        permission.api_status = status
        permission.save()
        messages.add_message(request, messages.INFO, u'权限添加成功！')
        return redirect('/djadmin/permission')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'api_list': api_list,}
    return render(request, 'djadmin/addpermission.html', context)

@staff_member_required(login_url='/djadmin/login')
def changePermission(request, permission_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/permission')

    api_list = ApiInfo.objects.all()
    permission = get_object_or_404(ApiPermission, id=permission_id)
    if request.method == 'POST':
        username = request.POST.get('username')
        api_id = request.POST.get('api_id')
        expired_time = request.POST.get('expired_time')
        status = request.POST.get('status')
        permission.api = ApiInfo.objects.get(id=api_id)
        permission.api_status = status
        permission.expired_time = datetime.strptime(expired_time, '%m/%d/%Y')
        print(permission.expired_time)
        permission.save()
        messages.add_message(request, messages.INFO, u'权限信息编辑成功！')
        return redirect('/djadmin/permission')

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'permission': permission,
            'api_list': api_list,}
    return render(request, 'djadmin/changepermission.html', context)

@staff_member_required(login_url='/djadmin/login')
def deletePermission(request, permission_id):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/permission')

    permission = get_object_or_404(ApiPermission, id=permission_id)
    permission.delete()
    messages.add_message(request, messages.INFO, u'API权限删除成功！')
    return redirect('/djadmin/permission')

@staff_member_required(login_url='/djadmin/login')
def log(request):
    site_info = SiteInfo.objects.first()
    menu_list = MenuInfo.objects.order_by('menu_order')
    menu_now = get_object_or_404(MenuInfo, menu_link='/djadmin/log')

    api_list = ApiInfo.objects.all()
    log_list = ApiLog.objects.all().order_by('-created_time')

    apikey = request.GET.get('q')
    if apikey and len(apikey)==36 and apikey[8]=='-':
        log_list = log_list.filter(api_key=apikey)
    else:
        apikey = ''

    apiid = request.GET.get('apiid')
    if apiid and len(apiid) and int(apiid) <> 0:
        log_list = log_list.filter(api_id=int(apiid))
    else:
        apiid = 0

    page = request.GET.get('page', 1)
    paginator = Paginator(log_list, 20)
    try:
        page = int(page)
        logs = paginator.page(page)
    except PageNotAnInteger:
        logs = paginator.page(1)
    except EmptyPage:
        logs = []

    if page >= 5:
        page_range = list(paginator.page_range)[page-5: page+4]
    else:
        page_range = list(paginator.page_range)[0: page+4]

    context = {'site_info': site_info, 
            'menu_list': menu_list,
            'menu_now': menu_now,
            'page_range': page_range,
            'api_list': api_list,
            'apiid': int(apiid),
            'apikey': apikey,
            'logs': logs,
            'query_num': len(log_list)}
    return render(request, 'djadmin/log.html', context)

@staff_member_required(login_url='/djadmin/login')
def logStatistics(request):
    apiid = request.GET.get("apiid")
    query = 'select date(created_time) as created_date, count(*) FROM platformAPI.api_log where api_id = ' \
        + apiid + ' AND TO_DAYS(NOW()) - TO_DAYS(created_time) <= 20 GROUP BY created_date'

    context = {'status': 0}
    context['data'] = {}
    context['data']['stats'] = []

    items = {}
    with connection.cursor() as cursor:
        cursor.execute(query)
        for record in cursor.fetchall():
            items[str(record[0])] = record[1]

    now = datetime.now()
    for n in range(0, 20):
        record = {}
        record['date'] = (now - timedelta(days=n)).strftime('%Y-%m-%d')
        record['count'] = items.get(record['date'], 0)
        context['data']['stats'].append(record)
    return HttpResponse(json.dumps(context), content_type="application/json")

