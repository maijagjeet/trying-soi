from django.contrib import admin
from django.urls import path, include
from cmpress import views

urlpatterns = [
    path('', views.begin, name='begin'),
    path('new/', views.new, name='home'),
    path('login/', views.login_, name="login"),
    path('signup/', views.signup, name="signup"),
    path('logout/', views.logout_, name="logout"),
    path('otp/', views.otp, name="otp"),
    path('loginnext/', views.file_upload_view,name="afterlogin"),
    path('success/', views.success, name="success"),
    path('downloadfile/', views.downloadfile, name='downloadfile'),
]
