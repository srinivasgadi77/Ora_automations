from django.db import models
from datetime import datetime
from django.utils import timezone

class HostList(models.Model):
    Pid             = models.IntegerField()
    State          = models.CharField(max_length=50,default='Running')
    SubmittedBy = models.CharField(max_length=50,default=' ')
    DateTime   = models.DateTimeField(default=timezone.now, blank=True)
    Hostname = models.CharField(max_length=50)
    Result        = models.CharField(max_length=500)
    JobState    =  models.CharField(max_length=50,default='Running')
	
    class Meta:
        verbose_name = 'Report'

    def __str__(self):
        return '%s %s' %(self.Pid,self.Hostname)

class Scripts(models.Model):
    script_name   = models.CharField(max_length=300,blank=True)
    script             = models.CharField(max_length=1000, blank=True)
    owner            = models.CharField(max_length=100,blank=True)
    DateTime       = models.DateTimeField(default=timezone.now, blank=True)

    class Meta:
        verbose_name = 'Scripts'

    def __str__(self):
        return self.script_name
        
class Analytics(models.Model):
    Pid               = models.IntegerField()
    sript_name   = models.CharField(max_length=500,blank=True)

    class Meta:
        verbose_name = 'Analytic'

    def __str__(self):
        return self.script_name

class ScheduledJobs(models.Model):
    Pid               = models.IntegerField()
    Owner          = models.CharField(max_length=50,default=' ')
    WF               =  models.CharField(max_length=500,blank=True)
    DateTime     = models.DateTimeField(default=timezone.now, blank=True)
    HostCount   = models.IntegerField(blank=True)
    State            = models.CharField(max_length=50,default=' ')
    JobState = models.CharField(max_length=50, default='Running')
    running_count = models.IntegerField(default=0)
    success_count = models.IntegerField(default=0)
    NonSuccess_count = models.IntegerField(default=0)
    InValidHosts = models.IntegerField(default=0)

    class Meta:
        verbose_name = 'ScheduledJob'

    def __str__(self):
        return self.Pid


class patch_report(models.Model):
    Pid = models.IntegerField()
    host_name = models.CharField(max_length=100, default=' ')
    State = models.CharField(max_length=50, default=' ')
    DateTime = models.DateTimeField(default=timezone.now, blank=True)
    pre_cves_important = models.CharField(max_length=100, default=' ')
    pre_cves_critical = models.CharField(max_length=100, default=' ')
    post_cves_critical = models.CharField(max_length=100, default=' ')
    owner_email = models.CharField(max_length=100, default=' ')
    pre_cves_low = models.CharField(max_length=100, default=' ')
    pre_kernel = models.CharField(max_length=100, default=' ')
    pre_os_version = models.CharField(max_length=100, default=' ')
    cves_pending = models.CharField(max_length=100, default=' ')
    cves_status = models.CharField(max_length=100, default=' ')
    snapshot_date = models.CharField(max_length=100, default=' ')
    uptrack_status = models.CharField(max_length=100, default=' ')
    upgraded_kernel = models.CharField(max_length=100, default=' ')
    pre_cves_moderate = models.CharField(max_length=100, default=' ')
    date_patched = models.CharField(max_length=100, default=' ')
    non_uek_status = models.CharField(max_length=100, default=' ')
    kernel_status = models.CharField(max_length=100, default=' ')
    reboot_status = models.CharField(max_length=100, default=' ')
    post_cves_moderate = models.CharField(max_length=100, default=' ')
    updated_os_version = models.CharField(max_length=100, default=' ')
    post_cves_important = models.CharField(max_length=100, default=' ')
    post_cves_low = models.CharField(max_length=100, default=' ')


    class Meta:
        verbose_name = 'CpuPatchData'

    def __str__(self):
        return self.Pid