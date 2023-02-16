import base64

from django.http import HttpResponse
from django.utils.timezone import now

from .models import Key


class KeyAuthMixin:
    def get_user_data(self, request):
        if "authorization" in request.headers:
            auth = request.headers["authorization"].split()
            if len(auth) == 2 and auth[0].lower() == "basic":
                return base64.b64decode(auth[1]).split(":")
        if "user" in request.GET and "password" in request.GET:
            return (request.GET["user"], request.GET["password"])
        return None

    def dispatch(self, request, *args, **kwargs):
        auth = self.get_user_data(request)
        if auth:
            uname, passwd = auth
            try:
                key = Key.objects.filter(user__username=uname, password=passwd).get()
                key.used_on = now()
                key.save()
                user = key.user
            except (Key.MultipleObjectsReturned, Key.DoesNotExist):
                user = None
            if user is not None and user.is_active:
                request.user = user
                return super().dispatch(request, *args, **kwargs)
        return HttpResponse("Unauthorized", status=401)
