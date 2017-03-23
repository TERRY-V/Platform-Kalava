# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.db import models

from django.conf import settings

class ApiInfo(models.Model):
    api_name = models.CharField(u'服务名称', max_length=30)
    api_provider = models.CharField(u'服务商', max_length=50)
    api_description = models.TextField(u'服务描述')
    api_url = models.CharField(u'接口地址', max_length=200, blank=True)
    api_method = models.IntegerField(u'请求方法', default=1, blank=True)
    api_keywords = models.CharField(u'关键字', max_length=200, blank=True)
    api_status = models.IntegerField(u'API状态', default=0)
    request_sample = models.TextField(u'请求示例', null=True)
    reply_sample = models.TextField(u'JSON返回示例', null=True)
    created_time = models.DateTimeField(u'创建时间', auto_now_add=True, null=True)

    class Meta:
        db_table = 'api_info'
        verbose_name = u'API管理'
        verbose_name_plural = u'API管理'

    def __str__(self):
        return self.api_name.encode('utf-8')

    def labels_as_list(self):
        return self.api_keywords.split(',')

class ApiParam(models.Model):
    api = models.ForeignKey(ApiInfo, verbose_name=u'所属服务', on_delete=models.CASCADE)
    param_name = models.CharField(u'参数名', max_length=200, blank=True)
    param_type = models.CharField(u'类型', max_length=200, blank=True)
    param_requested = models.IntegerField(u'必填', default=1)
    param_location = models.IntegerField(u'参数位置', default=1)
    param_default = models.CharField(u'默认值', max_length=200, blank=True)
    param_order = models.IntegerField(u'排序', default=1)
    param_description = models.TextField(u'描述', blank=True)
    created_time = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'api_param'
        verbose_name = u'参数管理'
        verbose_name_plural = u'参数管理'

class ApiErrno(models.Model):
    api = models.ForeignKey(ApiInfo, verbose_name=u'所属服务', on_delete=models.CASCADE)
    errno = models.IntegerField(u'错误码', default=0)
    errno_message = models.CharField(u'类型', max_length=200, blank=True)
    errno_intro = models.TextField(u'描述', blank=True)
    created_time = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'api_errno'
        verbose_name = u'错误码管理'
        verbose_name_plural = u'错误码管理'

class ApiPermission(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name=u'用户')
    api = models.ForeignKey(ApiInfo, verbose_name=u'所属服务', on_delete=models.CASCADE)
    api_key = models.CharField('API Key', max_length=200, blank=True)
    api_status = models.IntegerField(u'API状态', default=1)
    expired_time = models.DateTimeField(u'失效时间', blank=True, null=True)
    created_time = models.DateTimeField(u'创建时间', auto_now_add=True)
    
    class Meta:
        db_table = 'api_permission'
        verbose_name = u'API权限管理'
        verbose_name_plural = u'API权限管理'

class ApiLog(models.Model):
    api = models.ForeignKey(ApiInfo, verbose_name=u'所属服务', on_delete=models.CASCADE)
    api_key = models.CharField('API Key', max_length=200, blank=True)
    image_url = models.CharField(u'图片链接', max_length=200, blank=True)
    request_id = models.CharField(u'请求ID', max_length=50, null=True)
    request = models.TextField(u'请求信息', blank=True)
    status = models.IntegerField(u'状态码', default=0)
    result = models.TextField(u'返回结果', blank=True)
    error_report = models.IntegerField(u'报错', default=0)
    consumed_time = models.IntegerField(u'消耗时间', default=0)
    created_time = models.DateTimeField(u'创建时间', auto_now_add=True)

    class Meta:
        db_table = 'api_log'
        verbose_name = u'日志管理'
        verbose_name_plural = u'日志管理'

class ApiImage(models.Model):
    api = models.ForeignKey(ApiInfo, verbose_name=u'所属服务', on_delete=models.CASCADE)
    image_path = models.CharField(u'图片路径', max_length=200, blank=True)
    created_time = models.DateTimeField(u'创建时间', auto_now_add=True)
    
    class Meta:
        db_table = 'api_image'
        verbose_name = u'示例图片管理'
        verbose_name_plural = u'示例图片管理'

