"""frankensteinWebUI URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url,include
from django.conf.urls.static import static
from frankensteinWebUI import views
from django.conf import settings

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^newProject$', views.newProject, name='newProject'),
    url(r'^project$', views.project, name='project'),
    url(r'^emulate$', views.emulate, name='emulate'),


    url(r'^getProjectCfg$', views.getProjectCfg, name='getProjectCfg'),
    url(r'^projectSanityCheck$', views.projectSanityCheck, name='getProjectCfg'),

    url(r'^editConfig$', views.editConfig, name='editConfig'),
    url(r'^editGroup$', views.editGroup, name='editGroup'),
    url(r'^editSegment$', views.editSegment, name='editSegment'),
    url(r'^editSymbol$', views.editSymbol, name='editSymbol'),

    url(r'^loadELF$', views.loadELF, name='loadELF'),
    url(r'^loadIdb$', views.loadIdb, name='loadIdb'),
    url(r'^loadSegment$', views.loadSegment, name='loadSegment'),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
