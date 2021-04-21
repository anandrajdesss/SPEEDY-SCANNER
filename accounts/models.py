from datetime import date
from django.db import models
from django.utils.timezone import now
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager


class MyUserManager(BaseUserManager):
    def normalize_phone(self, name):
        return name.lower().strip()

    def __create(self, phone, email, password):
        if not email:
            raise ValueError("Users must have an email address")
        if not phone:
            raise ValueError("Users must have an phone number")
        user = self.model(
            email=self.normalize_email(email), phone=self.normalize_phone(phone),
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, phone, email, password=None):
        user = self.__create(phone, email, password)
        user.save()
        return user

    def create_superuser(self, phone, email, password=None):
        user = self.__create(phone, email, password)
        user.is_admin = True
        user.save()
        return user


class MyUser(AbstractBaseUser):
    phone = models.CharField(max_length=16, unique=True)
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True)

    objects = MyUserManager()

    USERNAME_FIELD = "phone"
    REQUIRED_FIELDS = ["email"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin


def upload_image(instance, filename):
    return "accounts/{user}/{filename}".format(
        user=instance.batch.user.id, filename=filename
    )


class Profile(models.Model):
    first_name = models.CharField(max_length=200)
    last_name = models.CharField(max_length=200)
    user = models.OneToOneField(MyUser, on_delete=models.CASCADE)

    def __str__(self):
        return self.first_name


class Batch(models.Model):
    created_date = models.CharField(max_length=20, blank=True, editable=False)
    description = models.CharField(max_length=200)
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE)

    def save(self, *args, **kwargs):
        self.created_date = str(date.today())
        super(Batch, self).save(*args, **kwargs)

    def __str__(self):
        return self.description


class File(models.Model):
    file_path = models.FileField(upload_to=upload_image)
    batch = models.ForeignKey(Batch, on_delete=models.CASCADE)

    def __str__(self):
        return "%s - %s" % (self.batch.user, self.batch)

