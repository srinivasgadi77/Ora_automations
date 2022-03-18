# # -*- coding: utf-8 -*-
# from __future__ import unicode_literals

from django.http import HttpResponse
from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.db.models import Q
from excel_response import ExcelResponse
from django.db.models import Count

from .models import patch_report
from .models import HostList
from .models import Scripts
from .models import Analytics
from .models import ScheduledJobs
from .forms import FixitCreateForm
from .forms import AddWfForm
import pathlib

from itertools import islice
import json
import subprocess
import os
import time
import threading
import pdb
import sys
import re
import pandas as pd

import base64

from rest_framework import viewsets
from .serializers import HostListSerializers


class HostListViewSet(viewsets.ModelViewSet):
    queryset = HostList.objects.all()
    serializer_class = HostListSerializers


def db_stats_update(JobId):
    while True:
        time.sleep(60)
        job_stats = HostList.objects.filter(Pid=JobId)
        my_data_dict = {
            'running_count': job_stats.filter(State__icontains='Running').count(),
            'success_count': job_stats.filter(State__icontains='Success').count(),
            'NonSuccess_count': job_stats.exclude(Q(State__icontains='Success')).exclude(
                Q(State__icontains='Running')).exclude(Q(State__icontains='InvalidHost')).count(),
            'InValidHosts': job_stats.filter(State__icontains='InvalidHost').count(),
            'JobState': 'Running' if 'Running' in HostList.objects.filter(Pid=JobId).values_list('State',
                                                                                                 flat=True) else 'Done',
        }
        ScheduledJobs.objects.filter(Pid=JobId).update(**my_data_dict)

def shutdown(request):
    return render(request, 'fixit/shutdown.html')



def execute(username, JobId, scriptnames, hosts_file):
    # print('4.username = %s' % username)
    global monitor_fie
    CURRENT_TIME = time.strftime('%d%m%Y_%H%m%S')
    LogFile = f'/tmp/JC_FIX_Log_{CURRENT_TIME}'
    monitor_fie = f'{LogFile}_monitor'

    PARALLEL_EXECUTOR = os.path.join(os.getcwd(), 'scan_hosts_adoc_16.py')

    cmd = f'{PARALLEL_EXECUTOR} --file {hosts_file} --Pid {JobId} --enable --ldap {username} --parse_passwd {USER_PASSWD} --logfile {LogFile}  --cmd "{scriptnames.strip()}" --timeout {int(TIMEOUT) * 60} --regex_item "{DROPDM_REGEX}" --regex_value "{REGEX_VALUE}" --last_lines {LASTLOGTOSHOW} &'
    print('Executing the command\n', cmd)
    os.system(cmd)
    time.sleep(2)
    db_stats_update(JobId)

    '''
    It will update the status of issued command to Database as and when the logfile have the new data, copying the original log file to two duplicate copies and erasing the data from original
    one for reference and other for updating the DB which have only latest information from log.
    '''
    # while True:
    #     if os.path.exists(monitor_fie):
    #         print('=> 1.Processing\n')
    #         db_stats_update(JobId)
    #
    #         print('\n=============DONE ====================\n')
    #     else:
    #         break
    #
    #     # Wating for 5s to update the next set of recods
    #     time.sleep(5)


def writeToFile(hostnames, hosts_file):
    with open(hosts_file, 'w') as fw:
        for host in hostnames:
            fw.write(host + '\n')
    return hosts_file


def validate_host(JobId, hostname, username):
    # ''' VALIDTING THE WHETHER GIVEN HOST IS RESOLVED'''
    if not hostname:
        return

    cmd = 'host %s >/dev/null' % hostname
    # proc = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
    return_status = os.system(cmd)
    # Result, error = proc.communicate()
    # Result = str(Result, 'utf-8')

    # if 'not' in Result or 'NXDOMAIN' in Result:
    #     HostList.objects.create(Pid=JobId, Hostname=hostname, SubmittedBy=username, State='InvalidHost')
    #     return False
    # else:
    #     return True

    if return_status:
        HostList.objects.create(Pid=JobId, Hostname=hostname, SubmittedBy=username, State='InvalidHost')
        return False
    else:
        return True


# def run_background(JobId, scriptnames, hosts_file):
#     job = threading.Thread(target=execute, args=(JobId, scriptnames, hosts_file,))
#     job.start()

'''It divide the list into given equal part of sub lists and return'''


def chunk(it, size):
    '''if size value 0, then it will not split the list'''
    it1 = iter(it)
    if size:
        divisions = iter(lambda: tuple(islice(it1, size)), ())
        return divisions
    else:
        return [it]


def Analysis(JobId, hostnames, username, scriptnames, hosts_file, SPLIT_SIZE):
    '''Dividing the hosts list to max 999 and repeaat the process till end of all hosts'''

    for turn, division_hosts in enumerate(list(chunk(set(hostnames), SPLIT_SIZE))):
        validated_hosts = []
        '''Data analysis'''
        print(f'Working on {turn + 1} : {len(division_hosts)}/{len(hostnames)}')

        for hostname in division_hosts:
            if validate_host(JobId, hostname, username):
                print('Updating db with %s' % hostname)

                HostList.objects.create(Pid=JobId, Hostname=hostname, SubmittedBy=username)
                validated_hosts.append(hostname)

        # print('\n==> validated_hosts = %s' %validated_hosts)

        hosts_file = writeToFile(validated_hosts, hosts_file)
        print(f'=>{turn} : {open(hosts_file).read()}')
        time.sleep(5)
        job = threading.Thread(target=execute, args=(username, JobId, scriptnames, hosts_file,))
        job.start()

       # print(f'==>Sleeping for {int(turn) * 30} min to start a turn batch')
        print(f'==>Sleeping for 10  min to start another batch')
#        time.sleep(int(turn) * 30)
        time.sleep(600)

    # while True:
    #     if os.path.exists(monitor_fie):
    #         time.sleep(3)
    #     else:
    #         print('Update file state')
    #         JobState = 'Completed'
    #         HostList.objects.filter(Pid=JobId).update(JobState=JobState)
    #         HostList.objects.filter(Pid=JobId).filter(State__icontains='Running').update(State='TimeOut')
    #         ScheduledJobs.objects.filter(Pid=JobId).update(JobState=JobState)
    #         db_stats_update(JobId)
    #         break


def udpate_db(JobId, hostnames, username, scriptnames, SELECTED_WF):
    # print('2.username = %s' %username)
    # hosts_file=f'/tmp/host_file_{CURRENT_TIME}'
    hosts_file = '/tmp/host_file'

    if not hostnames:
        return
    print('In udpate_db ')

    if ',' in hostnames:
        hostnames = hostnames.split(',')

    elif isinstance(hostnames, str):
        hostnames = [hostnames]

    # pdb.set_trace()

    df = pd.DataFrame({'hosts': list(set(hostnames))})
    df = df.replace(r'\n', '', regex=True)

    # DATA CLEANING
    # find and replace if there are any hosts ends with "."

    not_endwith_dot = df[~df['hosts'].str.endswith('.')]
    endwith_dot_replace = df[df['hosts'].str.endswith('.')]['hosts'].str[:-1]

    # convert above statement to dataframe
    endwith_dot_replace = pd.DataFrame({'hosts': endwith_dot_replace})

    df = not_endwith_dot.append(endwith_dot_replace)

    df = df[df['hosts'].str.endswith('.com') & ~df['hosts'].str.contains('-c')].reset_index(drop=True)
    # df = df[~df['hosts'].str.contains('-c')].reset_index(drop=True)

    '''If there are more than 999 hosts rather display requested hosts on screen  will simply display JOBID and that can be monitored.'''
    hostnames = df.iloc[:, 0].values.tolist()
    HOST_CNT = df.count()[0]

    '''Update the DB with below details as soon as clean up the data with invalied hosts'''
    ScheduledJobs.objects.create(Pid=JobId, Owner=username, WF=SELECTED_WF, HostCount=HOST_CNT)
    SPLIT_SIZE = 0

    if not THREADS:
        if HOST_CNT >= 50000:
            SPLIT_SIZE = 4000

        elif HOST_CNT >= 30000:
            SPLIT_SIZE = 3500

        elif HOST_CNT >= 20000:
            SPLIT_SIZE = 3000

        elif HOST_CNT >= 5000:
            SPLIT_SIZE = 2000

        else:
            SPLIT_SIZE = int(HOST_CNT)
    else:
        SPLIT_SIZE = int(THREADS)

    print(f'=>SPLIT_SIZE = {SPLIT_SIZE}')

    threading.Thread(target=Analysis, args=(JobId, hostnames, username, scriptnames, hosts_file, SPLIT_SIZE)).start()
    validated_hosts = (df, True)
    return validated_hosts


def home_view(request, pid=None):
    global hostnames
    evaludated_hosts = (pd.DataFrame(), False)
    hostnames = ''
    JobId = ''

    # print(f'1.hosts_file',hosts_file)

    query_results = []
    if request.method == "POST":
        print('\n======>I am in post')
        scriptnames = ''
        global USER_PASSWD, TIMEOUT, DROPDM_REGEX, REGEX_VALUE, LASTLOGTOSHOW, THREADS
        FormData = request.POST
        username = FormData.get('username')

        USER_PASSWD = FormData.get("Passwd")
        if not USER_PASSWD:
            USER_PASSWD = 'None'

        TIMEOUT = FormData.get("timeout")
        THREADS = FormData.get("threads")
        DROPDM_REGEX = FormData.get("dropdown_regex")
        REGEX_VALUE = FormData.get("regex")
        LASTLOGTOSHOW = FormData.get("LastLogToShow")

        if not DROPDM_REGEX:
            DROPDM_REGEX = 'None'
            REGEX_VALUE = 'None'
        # print('1.I am in post')

        ''' Getting the Pid from DB and increment and assign this JOB ID per task for identity '''

        if HostList.objects.values():
            JobId = HostList.objects.values().last()['Pid'] + 1
        else:
            JobId = 1
        SELECTED_WF = FormData.get("scriptname")  # '''selected WF name'''
        scriptnames = request.POST.get('script')  # ''' selected WF value'''
        Analytics.objects.create(Pid=JobId, sript_name=scriptnames)

        if request.POST.get('hostname'):

            hostnames = request.POST['hostname'].strip()

            hostnames = re.sub('[  \r\n]+', ',', hostnames)

            # print(f'\n=>hostnames = {hostnames}')

            '''Check if there are more than one host with , deliminate, which means there are more than one host in hostname field'''
            # print('1.username = %s' %username)
            evaludated_hosts = udpate_db(JobId, hostnames, username, scriptnames, SELECTED_WF)
            print('==> Executuon done')

        elif request.FILES:
            hosts_file, hostnames = UploadFile(request)
            evaludated_hosts = udpate_db(JobId, hostnames, username, scriptnames, SELECTED_WF)

    else:
        hostnames = request.GET.get('hostname', '')
        scriptnames = dict(Scripts.objects.values_list('script_name', 'script'))

    if evaludated_hosts[1]:  ### True mean : data commig from Pandas table
        pandas_data = True
        query_results = evaludated_hosts[0].to_html()
        hosts_count = evaludated_hosts[0].count()[0]
        # print(f'=> query_results : {query_results}')
    else:
        pandas_data = False
        query_results = [HostList.objects.filter(Hostname__contains=hostname.strip()).values().last() for hostname in
                         evaludated_hosts[0]]
        hosts_count = len(query_results)

    ''' this part will display the hostname which are submitted for execution'''
    form = FixitCreateForm()
    data = {
        'pandas_data': pandas_data,
        'JobId': JobId,
        'query_results': query_results,
        'hosts_count': hosts_count,
        'form': form,
        'scriptnames': scriptnames,
    }
    return render(request, 'fixit/fixit_create_page.html', data)


def UploadFile(request):
    print('I am on upload')
    if request.method == 'POST' and request.FILES['JC_hosts_File']:
        JC_hosts_File = request.FILES['JC_hosts_File']
        fs = FileSystemStorage()
        filename = fs.save(JC_hosts_File.name, JC_hosts_File)
        uploaded_file = os.path.join(settings.MEDIA_ROOT, filename)

        with open(uploaded_file, 'r') as fileData:
            uploaded_hosts = [host for host in fileData]
        return (uploaded_file, uploaded_hosts)


def API_db_update(request):
    import pytz
    import datetime

    data_api = request.GET['data']
    try:
        JobId = patch_report.objects.values().last()['Pid'] + 1
    except:
        JobId = 1

    patchData = {}
    print(f'==>APIdata = {data_api}')

    try:
        for e in data_api.split('|')[2].split(','):
            patchData[e.split(':')[0].strip()] = e.split(':')[1].strip()
    except:
        return 'No Proper data for JCMATE'

    if 'SUCCESSFUL' in patchData['cves_status'] and 'SUCCESSFUL' in patchData['kernel_status']:
        State = 'Success'

    elif not 'SUCCESSFUL' in patchData['cves_status'] and 'SUCCESSFUL' in patchData['kernel_status']:
        State = 'CvesFailed'

    elif 'SUCCESSFUL' in patchData['cves_status'] and not 'SUCCESSFUL' in patchData['kernel_status']:
        State = 'kernelPatchFailed'

    else:
        State = 'Failed'

    '''Finding for dup'''

    data = {
        'Pid': JobId,
        'State': State,
        'DateTime': datetime.datetime.now(tz=pytz.utc),
        'pre_cves_important': patchData['{pre_cves_important'],
        'pre_cves_critical': patchData['pre_cves_critical'],
        'post_cves_critical': patchData['post_cves_critical'],
        'owner_email': patchData['owner_email'],
        'pre_cves_low': patchData['pre_cves_low'],
        'pre_kernel': patchData['pre_kernel'],
        'pre_os_version': patchData['pre_os_version'],
        'cves_pending': patchData['cves_pending'],
        'cves_status': patchData['cves_status'],
        'snapshot_date': patchData['snapshot_date'],
        'uptrack_status': patchData['uptrack_status'],
        'upgraded_kernel': patchData['upgraded_kernel'],
        'pre_cves_moderate': patchData['pre_cves_moderate'],
        'date_patched': patchData['date_patched'],
        'non_uek_status': patchData['non_uek_status'],
        'kernel_status': patchData['kernel_status'],
        'reboot_status': patchData['reboot_status'],
        'host_name': patchData['host_name'],
        'post_cves_moderate': patchData['post_cves_moderate'],
        'updated_os_version': patchData['updated_os_version'],
        'post_cves_important': patchData['post_cves_important'],
        'post_cves_low': patchData['post_cves_low'][:-1]
    }

    try:
        patch_report.objects.update_or_create(
            host_name__icontains=patchData['host_name'], defaults=data
        )

    except Exception as e:
        print(f'ERROR: Details mismatch : %s' % e)

    return HttpResponse('SUCCESS: Record has been updated with JCMate with PID: %s' % JobId)


def view_status(request, pid=None, job_state=None):
    # print(f'==> pid = {pid}\n job_state={job_state}')
    # print(f'URL ==> pid = {type(pid)}\n job_state={type(job_state)}')

    '''FIXIT: TO HAVE A PROPER TYPES'''
    '''BUG: WORKAROUND : by default django send the values as string hence type casting to string by evaludating it'''
    try:
        if job_state and isinstance(eval(job_state), int):
            pid = eval(job_state)
            job_state = None
    except NameError:
        pass

    # print(f'2URL ==> pid = {type(pid)}\n job_state={type(job_state)}')
    statsByState = {}

    if pid and job_state:
        if job_state == 'NotSuccess':
            query_results = HostList.objects.filter(Pid=pid).exclude(Q(State__icontains='Success')).exclude(
                Q(State__icontains='Running')).exclude(Q(State__icontains='InvalidHost')).order_by('-id')
            # job_stats.exclude(Q(State__icontains='Success')).exclude(Q(State__icontains='Running')).exclude(Q(State__icontains='InvalidHost')).count(
        else:
            query_results = HostList.objects.filter(Pid=pid).filter(State__icontains=job_state.strip()).order_by('-id')
            if not query_results:
                return HttpResponseRedirect('/reports/%s/' % pid)

    elif pid and isinstance(pid, int):
        query_results = HostList.objects.filter(Pid=pid).order_by('-id')


    elif job_state and isinstance(job_state, str):
        if job_state == 'NotSuccess':
            query_results = HostList.objects.filter(Pid=pid).exclude(Q(State__icontains='Success')).order_by('-id')
        else:
            query_results = HostList.objects.filter(State__icontains=job_state.strip()).order_by('-id')

    else:
        query_results = HostList.objects.all().order_by('-id')

    '''if there is invalid PID '''
    if not query_results:
        return HttpResponseRedirect('/reports/')

    '''Get the distinct state columns'''
    states = list(query_results.order_by().values_list('State', flat=True).distinct())

    for state in states:
        statsByState[state.strip()] = query_results.filter(State__icontains=state.strip()).count()

    try:
        active_hosts = query_results.count()
        total_hosts = ScheduledJobs.objects.filter(Pid=pid).values_list('HostCount', flat=True)[0]
        Queued = int(total_hosts) - int(active_hosts)

        print('>>Queued %s' % Queued)

        print('update the complete job state')
        # Complete_job_state = HostList.objects.filter(Pid=pid).values().last()['JobState']
        Complete_job_state = 'Running' if 'Running' in HostList.objects.filter(Pid=pid).values_list('State',
                                                                                                    flat=True) else 'Completed'

        '''Get the script name and WF'''
        script_name = Analytics.objects.filter(Pid=pid).values_list('sript_name')[0][0]
        WF = Scripts.objects.filter(script=script_name).values().last()['script_name']

    except Exception as e:
        print('==> Excetion %s' % str(e))
        Complete_job_state = ''
        total_hosts = query_results.count()
        Queued = 0
        WF = ''
        script_name = ''

    data = {'query_results': query_results[:500],
            'Pid': pid,
            'statsByState': statsByState,
            'total_hosts': total_hosts,
            'Queued': Queued,
            'ExecutionDate': query_results[0].DateTime,
            'script_name': script_name,
            'WF': WF,
            'Complete_job_state': Complete_job_state
            }

    # print("\n====================")
    # print('\n=> data = %s' %data)
    # print("====================\n")
    return render(request, 'fixit/report.html', data)


def view_patchreport(request, pid=None, job_state=None):
    # print(f'==> pid = {pid}\n job_state={job_state}')
    # print(f'URL ==> pid = {type(pid)}\n job_state={type(job_state)}')

    '''FIXIT: TO HAVE A PROPER TYPES'''
    '''BUG: WORKAROUND : by default django send the values as string hence type casting to string by evaludating it'''
    try:
        if job_state and isinstance(eval(job_state), int):
            pid = eval(job_state)
            job_state = None
    except NameError:
        pass

    statsByState = {}

    if job_state and isinstance(job_state, str):
        query_results = patch_report.objects.filter(State__icontains=job_state.strip()).order_by('-id')

    else:
        query_results = patch_report.objects.all().order_by('-id')

    count = patch_report.objects.all().count()

    '''Get the distinct state columns'''
    states = list(query_results.order_by().values_list('State', flat=True).distinct())

    for state in states:
        statsByState[state.strip()] = query_results.filter(State__icontains=state.strip()).count()

    # Generate Graph=============================
    WF = 'Ol_patching '

    getPlot(WF, statsByState.keys(), statsByState.values())

    Graph = image_as_base64(os.getcwd() + "/static/images/%s.png" % WF)
    # =============================
    if count:
        success_ration = round(statsByState.get('Success', 1) * 100 / count, 2)
    else:
        success_ration = 0

    data = {'query_results': query_results[:500],
            'statsByState': statsByState,
            'Count': count,
            'Graph': Graph,
            'success_ration': success_ration,
            }

    return render(request, 'fixit/patchreport.html', data)


def dashboard_view(request, WF=None, State=None):
    if State:
        WfPids = [id['Pid'] for id in list(ScheduledJobs.objects.filter(WF=WF).values('Pid'))]
        GroupByState = HostList.objects.filter(Pid__in=WfPids).values('State').annotate(Count('State')).filter(
            State__icontains=State)

    else:
        WfPids = [id['Pid'] for id in list(ScheduledJobs.objects.filter(WF=WF).values('Pid'))]
        GroupByState = HostList.objects.filter(Pid__in=WfPids).values('State').annotate(Count('State'))

    data = {'query_results': GroupByState.values()[:500],
            'Pid': 0,
            'statsByState': GroupByState,
            'total_hosts': GroupByState.values().count(),
            'Queued': 0,
            'ExecutionDate': None,
            'script_name': None,
            'WF': WF,
            'Complete_job_state': None,
            }
    # 'DashBoard': True,
    # }

    return render(request, 'fixit/report.html', data)


def view_jobs(request):
    Jobs = ScheduledJobs.objects.order_by('-id').values()

    data = {'Jobs': Jobs}
    return render(request, 'fixit/jobs.html', data)


def download_report(requeste, pid=None):
    CURRENT_TIME = time.strftime('%d%m%Y_%H%m%S')
    # print(f'PID = {pid} \n {type(pid)}')
    if pid and pid == 9000000000:
        print('I am here')
        query_results = patch_report.objects.all().order_by('-id')
    elif pid:
        query_results = HostList.objects.filter(Pid=pid).order_by('id')
    else:
        query_results = HostList.objects.all()

    # import pdb;pdb.set_trace()
    q = query_results.values('State', 'Hostname', 'Result')
    df = pd.DataFrame.from_records(q)

    from io import BytesIO
    import xlsxwriter

    with BytesIO() as b:
        writer = pd.ExcelWriter(b, engine='xlsxwriter')

        df.to_excel(writer, sheet_name='Sheet1', index=False)

        writer.save()
        return HttpResponse(b.getvalue(), content_type='application/vnd.ms-excel')
    # return HttpResponse(df,content_type='application/csv')

    # print(f'query_results = > {query_results}')
    # print(type(query_results))
    # df.to_csv('/tmp/test_d.csv')
    # # return ExcelResponse(df, f'JcMate_report_{CURRENT_TIME}')
    # return ExcelResponse(df.values, f'JcMate_report_{CURRENT_TIME}')
    # # return  ExcelResponse(df.to_csv('/tmp/test_d.csv'))


def add_wf(request):
    from django.http import JsonResponse
    from django.core import serializers

    if request.method == 'POST':
        WfName = request.POST['WfName'].strip()
        Command = request.POST['Command'].strip()

        Scripts.objects.create(script_name=WfName, script=Command)
    else:
        form = AddWfForm()

    query_results = Scripts.objects.all().order_by('-id').values()
    script_count = len(query_results)

    form = FixitCreateForm()
    data = {
        'query_results': list(query_results),
        'script_count': script_count,
        'form': form,
    }

    return render(request, 'fixit/add_wf.html', data)


def contact_view(*args, **kwargs):
    return HttpResponse("<h1>Contact Srini</h1>")


def view_adhoc(request):
    return render(request, 'fixit/inprogress.html')


def view_advSearch(request):
    data = {}
    # pdb.set_trace()
    if request.POST:
        # pdb.set_trace()
        SearchkeyWord = '*'

        if request.POST['Keyword']:
            SearchkeyWord = request.POST['Keyword'].strip()
            SearchkeyWord = re.sub('[  \r\n]+', ',', SearchkeyWord)

        print(f'\n=>hostnames = {SearchkeyWord}')
        print(f'=> type = {type(SearchkeyWord)}')

        if ',' in SearchkeyWord:
            SearchkeyWord = SearchkeyWord.split(',')

        elif isinstance(SearchkeyWord, str):
            SearchkeyWord = [SearchkeyWord]

        print('==================')
        print(f'\n=>hostnames = {SearchkeyWord}')
        print(f'=> type = {type(SearchkeyWord)}')

        found_search_results = patch_report.objects.filter(Q(host_name__in=SearchkeyWord)).order_by(
            '-DateTime').values()
        found_count = found_search_results.count()

        if int(found_count) > 500:
            found_search_results = found_search_results[:100]

        found_host_list = [query['host_name'] for query in found_search_results]
        dono_hosts = set(SearchkeyWord) - set(found_host_list)

        dono_hosts_count = len(dono_hosts)

        data = {
            'search_results': found_search_results,
            'results_count': found_count,
            'dono_hosts': dono_hosts,
            'donot_host_count': dono_hosts_count,
        }

    return render(request, 'fixit/advancedSearch.html', data)


def view_jcadmin(request):
    return render(request, 'fixit/inprogress.html')


def image_as_base64(image_file, format='png'):
    """
    :param image_file for the complete path of image.
    :param format is format for image, eg: png or jpg.
    """
    if not os.path.isfile(image_file):
        return None
    encoded_string = ''
    with open(image_file, 'rb') as img_f:
        encoded_string = str(base64.b64encode(img_f.read()), 'utf-8')
    return encoded_string


def getPlot(WF, x, y):
    # pdb.set_trace()

    import matplotlib.pyplot as plt
    x_pos = [i for i, _ in enumerate(x)]
    fig, ax = plt.subplots(figsize=(7, 3))

    colors = ['#AF7AC5', '#00CC00', '#64B5F6', '#81C784', '#D4E157', '#6D4C41', '#663399', 'SILVER', 'red']

    rects1 = ax.bar(x_pos, y, color=colors, width=0.5)

    '''make lable names to 6 characters to fit in the grapth'''
    x = [i[:6] for i in x]

    plt.xticks(x_pos, x)

    def autolabel(rects):
        """
        Attach a text label above each bar displaying its height
        """
        for rect in rects:
            height = rect.get_height()
            ax.text(rect.get_x() + rect.get_width() / 2., 1.05 * height, '%d' % (height), ha='right', va='bottom')

    autolabel(rects1)

    image_path = os.path.join(settings.BASE_DIR, 'static/images/', WF)
    plt.savefig(image_path, transparent=True, dpi=100)
    return


def dashboard(request):
    groupByWf = {}
    WfGraphData = {}

    states = []
    s_count = []
    WFs = [wf['script_name'] for wf in Scripts.objects.values('script_name').distinct()]

    for WF in WFs:
        Pids = [id['Pid'] for id in list(ScheduledJobs.objects.filter(WF=WF).values('Pid'))]
        QData = HostList.objects.filter(Pid__in=Pids).values('State').annotate(Count('State'))

        GraphData = {}
        for data in QData:
            GraphData[data['State']] = data['State__count']

        getPlot(WF, GraphData.keys(), GraphData.values())

        groupByWf[WF] = [QData, image_as_base64(os.getcwd() + "/static/images/%s.png" % WF)]

    data = {
        'groupByWf': groupByWf,
    }
    return render(request, 'fixit/dashboard.html', data)


def graph_test(request):
    # Construct the graph
    x = arange(0, 2 * pi, 0.01)
    s = cos(x) ** 2
    plot(x, s)

    xlabel('xlabel(X)')
    ylabel('ylabel(Y)')
    title('Simple Graph!')
    grid(True)

    # Store image in a string buffer
    buffer = StringIO()

    canvas = pylab.get_current_fig_manager().canvas
    canvas.draw()
    pilImage = PIL.Image.fromstring("RGB", canvas.get_width_height(), canvas.tostring_rgb())
    pilImage.save(buffer, "PNG")
    pylab.close()

    # Send buffer in a http response the the browser with the mime type image/png set
    return HttpResponse(buffer.getvalue(), mimetype="image/png")
