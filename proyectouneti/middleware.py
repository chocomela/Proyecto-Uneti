from django.core.exceptions import PermissionDenied
from django.http import JsonResponse

from .models import Auditor, BitacoraAuditoria


class AuditorSoloLecturaMiddleware:


    EXEMPT_PATHS = ("/logout/", "/auditor/logout/", "/admin/logout/")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path in self.EXEMPT_PATHS:
            return self.get_response(request)

        es_auditor = (
            request.user.is_authenticated
            and isinstance(request.user, Auditor)
        )

        if es_auditor and request.method not in ("GET", "HEAD", "OPTIONS"):
            try:
                BitacoraAuditoria.objects.create(
                    usuario=None,
                    accion="ESCRITURA_BLOQUEADA",
                    recurso=request.path[:100],
                    detalle={
                        "auditor_username": request.user.username,
                        "metodo": request.method,
                        "path": request.path,
                    },
                    direccion_ip=request.META.get("REMOTE_ADDR"),
                    agente_usuario=request.META.get("HTTP_USER_AGENT", ""),
                    exitoso=False,
                )
            except Exception:
                pass

            mensaje = "Los auditores solo tienen acceso de lectura al sistema."

            if request.headers.get("HX-Request"):
                return JsonResponse({"error": mensaje}, status=403)

            raise PermissionDenied(mensaje)

        return self.get_response(request)