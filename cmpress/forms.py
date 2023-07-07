# forms.py
from django import forms

class MyFileUploadForm(forms.Form):
    file = forms.FileField(label='Select a file')
