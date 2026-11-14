# core/decorators.py
from functools import wraps

from django.contrib import messages
from django.shortcuts import redirect

from .models import BitacoraAuditoria, RolUsuario


def rol_requerido(roles_permitidos):
    """Restringe la vista a los roles indicados (RF-06).
    Registra en bitácora todo acceso denegado para trazabilidad."""
    permitidos = {r for r in roles_permitidos}

    def deco(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            u = request.user
            if not u.is_authenticated:
                return redirect("login")
            if u.rol not in permitidos:
                BitacoraAuditoria.objects.create(
                    usuario=u,
                    accion="ACCESO_DENEGADO",
                    recurso=view.__name__,
                    detalle={
                        "rol_actual": u.rol,
                        "roles_requeridos": sorted(permitidos),
                    },
                    direccion_ip=request.META.get("REMOTE_ADDR"),
                    agente_usuario=request.META.get("HTTP_USER_AGENT", ""),
                    exitoso=False,
                )
                messages.error(request, "No tiene permisos para realizar esta acción.")
                return redirect("dashboard")
            return view(request, *args, **kwargs)
        return wrapper
    return deco