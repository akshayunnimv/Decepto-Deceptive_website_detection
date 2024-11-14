from django.db import models
from django.utils import timezone

class User(models.Model):
    name=models.CharField(max_length=100)
    contact_number=models.IntegerField()
    email=models.EmailField()
    password=models.CharField(max_length=100)
    def __str__(self):
        return self.name

  
class Admin(models.Model):
    email=models.EmailField()
    password=models.CharField(max_length=100)

class Review(models.Model):
    url=models.CharField(max_length=100)
    current_date=models.DateTimeField(default=timezone.now) 
    review=models.CharField(max_length=100)
    login_id=models.ForeignKey(User,on_delete=models.CASCADE)
class Complaint(models.Model):
    complaint=models.CharField(max_length=100)
    date=models.DateTimeField(default=timezone.now) 
    reply=models.CharField(max_length=100,null=True,blank=True)
    status=models.CharField(max_length=100,default='open')
    login_id=models.ForeignKey(User,on_delete=models.CASCADE)

class Category(models.Model):
    category=models.CharField(max_length=100)
    url=models.CharField(max_length=100)
    login_id=models.ForeignKey(User,on_delete=models.CASCADE)
