"""jcmc URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include

from django.conf import settings
from django.conf.urls.static import static

from fixit.views import home_view
from fixit.views import view_status,UploadFile, download_report,add_wf, view_jobs,API_db_update
from fixit.views import view_adhoc, view_advSearch, view_jcadmin,dashboard,dashboard_view,graph_test, view_patchreport
from rest_framework import routers
from fixit.views import HostListViewSet
from fixit.views import shutdown

routers = routers.DefaultRouter()
routers.register(r'hostdata', HostListViewSet)

urlpatterns = [
    #path('', shutdown, name='home'),
    path('', home_view, name='home'),
    path('fixit/', home_view, name='home'),
    path('Jobs', view_jobs),
    path('reports/', view_status),

    path('reports/<int:pid>/', view_status),
    path('reports/<str:job_state>', view_status),
    path('reports/<int:pid>/<str:job_state>/', view_status),

    # path('dashboard', dashboard),
    # path('dashboard/<str:WF>', dashboard_view),
    # path('dashboard/<str:WF>/<str:State>/', dashboard_view),

    path('api_db_update/', API_db_update, name='urlname'),

    # path('api_db_update/', API_db_update),
    path('addwf', add_wf),
    path('admin', admin.site.urls),

    path('downloadreport/None',download_report),
    path('downloadreport/<int:pid>',download_report),

    path('adhoc', view_adhoc),
    path('advSearch', view_advSearch),
    path('jcadmin', view_adhoc),

    path('patchreport', view_patchreport),
    path('patchreport/<str:job_state>', view_patchreport),
    # path('patchinfo', view_patchData),

    # path('graph_test',graph_test),

    # path('',include(routers.urls)),
    path('api-auth/',include('rest_framework.urls',
                             namespace='rest_framework'))

]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
