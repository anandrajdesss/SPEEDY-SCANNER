import os
from django.conf import settings
from django.http import HttpResponse, Http404
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model, login, logout, authenticate
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_204_NO_CONTENT,
    HTTP_200_OK,
    HTTP_400_BAD_REQUEST,
    HTTP_403_FORBIDDEN,
)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework import exceptions
from rest_framework.authtoken.models import Token
from wsgiref.util import FileWrapper
from azure.storage.blob import BlockBlobService
from decouple import config
from rest_framework.generics import (
    ListCreateAPIView,
    RetrieveUpdateDestroyAPIView,
    CreateAPIView,
    ListAPIView,
    UpdateAPIView,
    RetrieveAPIView,
)
from .serializers import (
    ProfileSerializer,
    FileSerializer,
    BatchSerializer,
    BatchFileSerializer,
    GetUserSerilaizer,
    LoginSerializer,
    SignUpSerializer,
    UserUpdateSerilaizer,
    ChangePasswordSerializer,
)
from .models import Profile, File, Batch

User = get_user_model()


class UserSignupView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignUpSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = SignUpSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"status": "success"})
        return Response({"status": "failure", "data": serializer.errors})


class UserLoginView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("phone", None)
        password = request.data.get("password", None)
        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                login(request, user)
                token, created = Token.objects.get_or_create(user=user)
                data = {
                    "id": user.id,
                    "token": token.key,
                    "username": user.phone,
                    "is_admin": user.is_admin,
                    "profile_id": user.profile.id,
                }
                return Response({"status": "success", "data": data}, status=HTTP_200_OK)
            return Response(
                {"status": "failure", "data": "Unable to login with given credidential"}
            )
        return Response(
            {
                "status": "failure",
                "data": "You need to provide both username and password",
            }
        )


class ChangePasswordView(CreateAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"status": "success"})
        return Response({"status": "failure",})


class UserLogoutView(APIView):
    premission_classes = [IsAuthenticated]

    def post(self, request):
        print("logout")
        logout(request)
        return Response(status=HTTP_204_NO_CONTENT)


class UserListApiView(ListAPIView):
    queryset = User.objects.all()
    serializer_class = GetUserSerilaizer
    permission_classes = [IsAuthenticated]

    def list(self, request):
        queryset = User.objects.all()
        serializer = GetUserSerilaizer(queryset, many=True)
        return Response({"status": "success", "data": serializer.data})


class UserUpdateApiView(RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserUpdateSerilaizer
    permission_classes = [IsAuthenticated]

    def retrieve(self, request, pk=None):
        queryset = User.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserUpdateSerilaizer(user)
        return Response({"status": "success", "data": serializer.data})

    def update(self, request, pk=None):
        queryset = User.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserUpdateSerilaizer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"status": "success", "data": serializer.data})
        return Response({"status": "failure", "data": serializer.errors})


class ProfileListApiView(ListAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    def list(self, request):
        queryset = Profile.objects.all()
        serializer = ProfileSerializer(queryset, many=True)
        return Response({"status": "success", "data": serializer.data})


class ProfileUpdateApiView(RetrieveUpdateDestroyAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    def retrieve(self, request, pk=None):
        queryset = Profile.objects.all()
        profile = get_object_or_404(queryset, pk=pk)
        serializer = ProfileSerializer(profile)
        return Response({"status": "success", "data": serializer.data})

    def update(self, request, pk=None):
        queryset = Profile.objects.all()
        profile = get_object_or_404(queryset, pk=pk)
        serializer = ProfileSerializer(profile, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"status": "success", "data": serializer.data})
        return Response({"status": "failure", "data": serializer.errors})


class FileListView(ListCreateAPIView):
    queryset = File.objects.all()
    serializer_class = FileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        batch_queryset = Batch.objects.all()
        batch_no = self.request.query_params.get("batch_no", None)
        user = self.request.user
        if user.is_admin:
            return File.objects.all()
        if batch_no is not None:
            batch = get_object_or_404(batch_queryset, pk=batch_no)
            if batch.user == user:
                return File.objects.filter(batch=batch_no)
            else:
                raise exceptions.PermissionDenied(
                    detail="Your not a owner of this resource", code=HTTP_403_FORBIDDEN,
                )
        else:
            raise exceptions.NotAcceptable(
                detail="Provide valid Params", code=HTTP_400_BAD_REQUEST
            )

    def list(self, request):
        queryset = self.get_queryset()
        serializer = FileSerializer(queryset, many=True)
        return Response({"status": "success", "data": serializer.data})

    def create(self, request):
        serializer = FileSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"status": "success", "data": serializer.data})
        return Response({"status": "failure", "data": serializer.errors})


class FileUpdateApiView(RetrieveUpdateDestroyAPIView):
    queryset = File.objects.all()
    serializer_class = FileSerializer
    permission_classes = [IsAuthenticated]

    def retrieve(self, request, pk=None):
        queryset = File.objects.all()
        file = get_object_or_404(queryset, pk=pk)
        serializer = FileSerializer(file)
        return Response({"status": "success", "data": serializer.data})

    def update(self, request, pk=None):
        queryset = File.objects.all()
        file = get_object_or_404(queryset, pk=pk)
        serializer = FileSerializer(file, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"status": "success", "data": serializer.data})
        return Response({"status": "failure", "data": serializer.errors})


class FileDownloadView(RetrieveAPIView):
    queryset = File.objects.all()
    # serializer_class = FileSerializer
    permission_classes = [IsAuthenticated]

    def retrieve(self, request, *args, **kwargs):
        container_name = "media"
        account_name = config("AZURE_ACCOUNT_NAME")
        account_key = config("AZURE_ACCOUNT_ACCESS_KEY")
        queryset = File.objects.all()
        obj = get_object_or_404(queryset, pk=kwargs.get("pk"))
        file_name = os.path.basename(str(obj.file_path))
        block_blob_service = BlockBlobService(
            account_name=account_name, account_key=account_key,
        )
        generator = block_blob_service.list_blobs(container_name)
        for blob in generator:
            # print("\t Blob name: " + blob.name)
            if obj.file_path.name == blob.name:
                block_blob_service.get_blob_to_path(
                    container_name, blob.name, file_name
                )
                with open(file_name, "rb") as fh:
                    response = HttpResponse(fh.read(), content_type="image/jpeg")
                    response["Content-Disposition"] = "attachment; filename={}".format(
                        file_name
                    )
                os.remove(file_name)
                return response
        return Response(status=HTTP_400_BAD_REQUEST)


class BatchFileCreateView(CreateAPIView):
    serializer_class = BatchFileSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request):
        serializer = BatchFileSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"status": "success"})
        return Response({"status": "failure"})


class BatchListApiView(ListAPIView):
    queryset = Batch.objects.all()
    serializer_class = BatchSerializer
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = BatchSerializer(queryset, many=True)
        return Response(serializer.data)

    def get_queryset(self):
        user = self.request.user
        if user.is_admin:
            return Batch.objects.all()
        return Batch.objects.filter(user=user)


# class FileDownloadView2(RetrieveAPIView):
#     def retrieve(self, request, pk=None):
#         connection_string = "DefaultEndpointsProtocol=https;AccountName=speedyscannerdesss;AccountKey=89jO8IN3zhBB5jZz2k9v7n6n9St3ueprOoHX6uP28nb4QR4MS9K/k+fcw93q5SEA9ycHUuEgifhEM7u2ov9XOQ==;EndpointSuffix=core.windows.net"
#         queryset = File.objects.all()
#         file = get_object_or_404(queryset, pk=pk)
#         serializer = FileSerializer(file)
#         blob = BlobClient.from_connection_string(
#             conn_str=connection_string, container_name="media", blob_name=str(file.file)
#         )
#         with open("./BlockDestination.txt", "wb") as my_blob:
#             blob_data = blob.download_blob()
#             blob_data.readinto(my_blob)
#             response = HttpResponse(my_blob.read(), content_type="image/jpeg")
#             response["Content-Disposition"] = "attachment; filename={}".format(filename)
#             return response
#         return Response(status=HTTP_400_BAD_REQUEST)
