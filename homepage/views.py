# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import json
import urllib2

from django.http import HttpResponse
from django.template import loader

from django.shortcuts import get_object_or_404
from django.shortcuts import redirect
from django.shortcuts import render

from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.template.defaulttags import register

from django import template
from django.views.generic import View, TemplateView, ListView, DetailView

from .models import Website, Column, News
from apiworks.models import ApiInfo

def index(request):
    return redirect('/usercenter/main')

def introduce(request):
    site_info = Website.objects.first()
    column_now = Column.objects.get(pk=1)
    column_list = Column.objects.order_by('column_order')

    context = {'site_info': site_info, 
            'column_now': column_now,
            'column_list': column_list,}
    return render(request, 'homepage/introduce.html', context)

def trends(request):
    site_info = Website.objects.first()
    column_now = Column.objects.get(pk=1)
    column_list = Column.objects.order_by('column_order')
    news_list = News.objects.order_by('-createtime')

    context = {'site_info': site_info, 
            'column_now': column_now,
            'column_list': column_list,
            'news_list': news_list}
    return render(request, 'homepage/trends.html', context)

def contactus(request):
    site_info = Website.objects.first()
    column_now = Column.objects.get(pk=1)
    column_list = Column.objects.order_by('column_order')

    context = {'site_info': site_info, 
            'column_now': column_now,
            'column_list': column_list,}
    return render(request, 'homepage/contactus.html', context)

def declaration(request):
    site_info = Website.objects.first()
    column_now = Column.objects.get(pk=1)
    column_list = Column.objects.order_by('column_order')

    context = {'site_info': site_info, 
            'column_now': column_now,
            'column_list': column_list,}
    return render(request, 'homepage/declaration.html', context)

def links(request):
    site_info = Website.objects.first()
    column_now = Column.objects.get(pk=1)
    column_list = Column.objects.order_by('column_order')

    context = {'site_info': site_info, 
            'column_now': column_now,
            'column_list': column_list,}
    return render(request, 'homepage/links.html', context)

def mobile(request):
    site_info = Website.objects.first()
    column_now = Column.objects.get(pk=1)
    column_list = Column.objects.order_by('column_order')

    context = {'site_info': site_info, 
            'column_now': column_now,
            'column_list': column_list,}
    return render(request, 'homepage/mobile.html', context)

