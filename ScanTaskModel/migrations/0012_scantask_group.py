# Generated by Django 3.2.1 on 2021-07-27 03:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ScanTaskModel', '0011_alter_scantask_ip_range'),
    ]

    operations = [
        migrations.AddField(
            model_name='scantask',
            name='group',
            field=models.CharField(default='测试', max_length=100),
        ),
    ]
