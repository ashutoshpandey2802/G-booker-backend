# Generated by Django 5.0.6 on 2024-09-26 06:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('booker', '0009_therapistschedule_title'),
    ]

    operations = [
        migrations.AddField(
            model_name='therapistschedule',
            name='color',
            field=models.CharField(blank=True, max_length=7, null=True),
        ),
    ]
