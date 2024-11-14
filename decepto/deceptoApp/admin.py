from django.contrib import admin
from .models import User,Admin,Complaint,Review,Category

admin.site.register(User)
admin.site.register(Admin)
admin.site.register(Complaint)
admin.site.register(Category)
admin.site.register(Review)