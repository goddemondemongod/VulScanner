from django.db import models

# Create your models here.

class Group(models.Model):
    name = models.CharField(max_length=100, default="")
    webvpn = models.CharField(max_length=100, default="")
    cookies = models.CharField(max_length=500, default="")