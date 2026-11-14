from django.contrib.auth.backends import ModelBackend

from .models import Auditor


class AuditorBackend(ModelBackend):

    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            username = kwargs.get(Auditor.USERNAME_FIELD)
        if username is None or password is None:
            return None
        try:
            auditor = Auditor.objects.get(username=username)
        except Auditor.DoesNotExist:
            return None
        if auditor.check_password(password) and auditor.is_active:
            return auditor
        return None

    def get_user(self, user_id):
        try:
            return Auditor.objects.get(pk=user_id)
        except Auditor.DoesNotExist:
            return None