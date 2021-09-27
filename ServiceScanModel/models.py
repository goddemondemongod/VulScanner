from django.db import models
from vulscan_Project import requestUtil

class ServiceScan(models.Model):
    taskid = models.IntegerField(default=1)
    ip = models.CharField(max_length=50)
    port = models.IntegerField(default=0)
    isShown = models.BooleanField(default=False)
    speciality = models.CharField(max_length=100, default="")
    type = models.CharField(max_length=50, default="low")
    title = models.CharField(max_length=100, default="")
    server = models.CharField(max_length=100, default="")
    url = models.CharField(max_length=200, default="")
    note = models.CharField(max_length=100, default="")
    vulnerable = models.BooleanField(default=False)
    isVpn = models.BooleanField(max_length=100, default=False)
    cookies = models.CharField(max_length=500, default="")


# Create your models here.
