# models.py
from django.db import models

class MyFileModel(models.Model):
    file = models.FileField(upload_to='uploads/')
