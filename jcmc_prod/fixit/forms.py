from django import forms
from .models import HostList
from .models import Scripts

class FixitCreateForm(forms.ModelForm):
    hostname = forms.CharField(
        widget=forms.Textarea(attrs={'placeholder': 'FQDN'}),
        max_length=10000
                               )

    class Meta:
        model = HostList
        fields = [
            'hostname'
        ]

class AddWfForm(forms.ModelForm):
    class Meta:
        model = Scripts
        fields = [
            'script_name',
            'script'
        ]

    class DateForm(forms.Form):
        date = forms.DateTimeField(input_formats=['%d/%m/%Y %H:%M'])

    # def clean_script_name(self):
    #     if not self.cleaned_data['script_name']:
    #             raise forms.ValidationError('script_nam is  mandatory')
    #
    # def clean_script(self):
    #     if not self.cleaned_data['script']:
    #         raise forms.ValidationError('script field  mandatory')