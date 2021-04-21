# urls.py
from django.urls import path
from .views import (
    ProfileListApiView,
    ProfileUpdateApiView,
    FileListView,
    FileUpdateApiView,
    UserListApiView,
    UserUpdateApiView,
    UserLoginView,
    UserLogoutView,
    UserSignupView,
    ChangePasswordView,
    FileDownloadView,
    BatchFileCreateView,
    BatchListApiView,
    # FileDownloadView2,
)


urlpatterns = [
    path("signup/", UserSignupView.as_view(), name="user-signup"),
    path("login/", UserLoginView.as_view(), name="user-login"),
    path("logout/", UserLogoutView.as_view(), name="user-logout"),
    path("changepasswd/", ChangePasswordView.as_view(), name="chnage-password"),
    path("user/", UserListApiView.as_view(), name="user-list"),
    path("user/<int:pk>/", UserUpdateApiView.as_view(), name="user-update"),
    path("profile/", ProfileListApiView.as_view(), name="profile-list"),
    path("profile/<int:pk>/", ProfileUpdateApiView.as_view(), name="profile-update"),
    path("batch-upload/", BatchFileCreateView.as_view(), name="bulk-file-upload"),
    path("batch/", BatchListApiView.as_view(), name="batch-list"),
    path("file/", FileListView.as_view(), name="file-list"),
    path("file/<int:pk>/", FileUpdateApiView.as_view(), name="file-update"),
    path("file-download/<int:pk>/", FileDownloadView.as_view(), name="file-download"),
    # path("dfile2/<int:pk>/", FileDownloadView2.as_view(), name="file-download2"),
]
