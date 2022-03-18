from django.contrib import admin

from .models import HostList, Scripts
from fixit.models import Analytics, ScheduledJobs, patch_report

admin.site.register(HostList)
admin.site.register(Scripts)
admin.site.register(Analytics)
admin.site.register(ScheduledJobs)
admin.site.register(patch_report)
