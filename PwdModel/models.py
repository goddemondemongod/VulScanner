from django.db import models

# Create your models here.

class Pwd(models.Model):
    system = models.CharField(max_length=100, default="")
    username = models.CharField(max_length=100, default="")
    password = models.CharField(max_length=100, default="")