from rest_framework import  serializers
from .models import patch_report, HostList

class HostListSerializers(serializers.ModelSerializer):
    class Meta:
        model = HostList
        fields = [ 'Pid', 'State', 'SubmittedBy', 'DateTime', 'Hostname', 'Result', 'JobState' ]



