# Generated by Django 3.2.1 on 2021-07-20 13:37

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('UserModel', '0001_initial'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='VulnScan',
            new_name='User',
        ),
    ]
