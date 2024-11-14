from django.urls import path,include
from . import views
urlpatterns = [   
    path('',views.index,name='home'),
    path('about/',views.about,name='about'),
    path('contact/',views.contact,name='contact'),
    path('register/',views.register,name='register'),
    path('userlogin/',views.userlogin,name='userlogin'),
    path('adminlogin/',views.adminlogin,name='adminlogin'),
    #user_module
    path('userhome/',views.userhome,name='userhome'),
    path('usercheckurl/',views.checkuser,name='checkuser'),
    path('complaintuser/',views.complaintuser,name='complaintuser'),
    path('reviewuser/',views.reviewuser,name='reviewuser'),
    path('userprofile/',views.profile,name='profile'),
    path('logout/', views.userlogout, name='logout'),
    path('user_viewreviews/', views.user_viewreviews, name='user_viewreviews'),
    path('user_viewcomplaints/', views.user_viewcomplaints, name='user_viewcomplaints'),
    #admin_module
    path('admin_home/',views.admin_home,name='admin_home'),
    path('admin_viewreviews/',views.admin_viewreviews,name='admin_viewreviews'),
    path('admin_complaints/',views.admin_complaints,name='admin_complaints'),
    path('admin_report/',views.admin_report,name='admin_report'),
    path('admin_checkurl/',views.admin_checkurl,name='admin_checkurl'),
    path('admin_logout/',views.admin_logout,name='admin_logout'),
    path('download_category_data/<str:category>/', views.download_category_data, name='download_category_data'),
    


]