from django.views.decorators.cache import never_cache
from django.contrib.auth import login as auth_login
from datetime import timezone as dt_timezone
from functools import wraps
from io import BytesIO
import csv
from django.utils.decorators import method_decorator
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from django.contrib.auth.views import LoginView
from django.http import HttpResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login as auth_login

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .form import (
    AuditoriaFilterForm,
    ConjuntoDatosForm,
    ModeloIAForm,
    TransicionEstadoForm,
    VersionConjuntoDatosForm,
    VersionModeloForm,
    LoginForm,
    SignupForm,
    
)

from .models import (
    Organizacion,
    ConjuntoDatos,
    VersionConjuntoDatos,
    ModeloIA,
    VersionModelo,
    EntradaLibroMayor,
    TipoEntradaLibroMayor,
    RolUsuario,
    TransicionEstado,
    BitacoraAuditoria,
    Auditor,
    Contacto,
    Usuario,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _marca_tiempo_canonica():
    """UTC sin microsegundos para mantener hashes reproducibles."""
    return timezone.now().astimezone(dt_timezone.utc).replace(microsecond=0)


def _append_ledger_entry(
    *,
    organizacion,
    tipo,
    version_modelo=None,
    version_conjunto_datos=None,
    carga_util,
    actor,
):
    """
    Añade una entrada encadenada al Libro Mayor de una organización.

    El llamador debe estar dentro de transaction.atomic() y haber bloqueado
    previamente la organización mediante _lock_organizacion().
    """

    ultima = (
        EntradaLibroMayor.objects
        .filter(organizacion=organizacion)
        .order_by("-secuencia")
        .first()
    )

    secuencia = (ultima.secuencia + 1) if ultima else 1
    hash_anterior = ultima.hash_actual if ultima else None
    fecha_registro = _marca_tiempo_canonica()

    hash_actual = EntradaLibroMayor.calcular_hash(
        organizacion_id=organizacion.id,
        secuencia=secuencia,
        tipo=tipo,
        carga_util=carga_util,
        hash_anterior=hash_anterior,
        fecha_registro=fecha_registro,
        actor_id=actor.id,
    )

    return EntradaLibroMayor.objects.create(
        organizacion=organizacion,
        secuencia=secuencia,
        tipo=tipo,
        version_modelo=version_modelo,
        version_conjunto_datos=version_conjunto_datos,
        carga_util=carga_util,
        hash_anterior=hash_anterior,
        hash_actual=hash_actual,
        actor=actor,
        firmado_por=actor if actor.clave_publica else None,
        huella_clave_firmante=actor.huella_clave_publica,
        # TODO: sustituir por una firma criptográfica real.
        firma_institucional=(
            actor.clave_publica[:100] if actor.clave_publica else ""
        ),
        fecha_registro=fecha_registro,
    )


def _lock_organizacion(organizacion):
    """Bloquea la organización para serializar las escrituras del ledger."""
    return Organizacion.objects.select_for_update().get(pk=organizacion.pk)


def _registrar_bitacora(
    request,
    usuario,
    accion,
    recurso,
    identificador="",
    detalle=None,
    exitoso=True,
):
    BitacoraAuditoria.objects.create(
        usuario=usuario,
        accion=accion,
        recurso=recurso,
        identificador_recurso=identificador or "",
        detalle=detalle or {},
        direccion_ip=request.META.get("REMOTE_ADDR"),
        agente_usuario=request.META.get("HTTP_USER_AGENT", ""),
        exitoso=exitoso,
    )


def _es_auditor_activo(user):
    """True solo si el usuario es un Auditor vigente (tabla independiente)."""
    return isinstance(user, Auditor) and user.vigente


def auditor_requerido(view):
    """Restringe la vista a un Auditor autenticado y vigente."""
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("login")
        if not _es_auditor_activo(request.user):
            messages.error(request, "No tiene perfil de auditor vigente.")
            return redirect("login")
        return view(request, *args, **kwargs)
    return wrapper

@method_decorator(never_cache, name="dispatch")
class StyledLoginView(LoginView):
    """LoginView que pinta de rosa los campos cuando hay error de credenciales."""
    template_name = "core/login.html"
    authentication_form = LoginForm

    def form_invalid(self, form):
        if hasattr(form, "apply_error_classes"):
            form.apply_error_classes()
        return super().form_invalid(form)

@never_cache
@transaction.atomic
def signup_view(request):
    """Autorregistro: crea un Usuario (REGISTRADOR) + su Contacto."""
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            usuario = form.save(commit=False)
            usuario.rol = RolUsuario.REGISTRADOR
            usuario.email = form.cleaned_data["email"]

            organizacion = form.cleaned_data.get("organizacion")
            if not organizacion:
                organizacion = Organizacion.objects.create(
                    nombre=form.cleaned_data["organizacion_nombre"].strip(),
                    rif=form.cleaned_data["organizacion_rif"].strip().upper(),
                    siglas=(form.cleaned_data.get("organizacion_siglas") or "").strip(),
                    activo=True,
                )

            usuario.organizacion = organizacion
            usuario.save()

            Contacto.objects.create(
                usuario=usuario,
                email=form.cleaned_data["email"],
                telefono=form.cleaned_data["telefono"],
                principal=True,
            )

            auth_login(
                request,
                usuario,
                backend="django.contrib.auth.backends.ModelBackend",
            )
            return redirect("dashboard")
    else:
        form = SignupForm()

    return render(request, "core/signup.html", {"form": form})

@never_cache
def recuperar_view(request):
    """Recuperación: username + método (email o teléfono)."""
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        metodo = request.POST.get("metodo", "email")

        usuario = Usuario.objects.filter(username=username).first()
        auditor = Auditor.objects.filter(username=username).first()

        contacto = None
        if usuario:
            contacto = Contacto.objects.filter(
                usuario=usuario, principal=True
            ).first()
        elif auditor:
            contacto = Contacto.objects.filter(
                auditor=auditor, principal=True
            ).first()

        if contacto:
            if metodo == "email" and contacto.email:
                BitacoraAuditoria.objects.create(
                    usuario=usuario if usuario else None,
                    accion="RECUPERACION_SOLICITADA",
                    recurso="Usuario" if usuario else "Auditor",
                    detalle={
                        "auditor_username": auditor.username if auditor else "",
                        "metodo": "email",
                        "email": contacto.email[:3] + "***",
                    },
                    direccion_ip=request.META.get("REMOTE_ADDR"),
                    exitoso=True,
                )
                # TODO: enviar correo con token real aquí.
            elif metodo == "telefono" and contacto.telefono:
                BitacoraAuditoria.objects.create(
                    usuario=usuario if usuario else None,
                    accion="RECUPERACION_SOLICITADA",
                    recurso="Usuario" if usuario else "Auditor",
                    detalle={
                        "auditor_username": auditor.username if auditor else "",
                        "metodo": "telefono",
                        "telefono": contacto.telefono[:3] + "***",
                    },
                    direccion_ip=request.META.get("REMOTE_ADDR"),
                    exitoso=True,
                )
                # TODO: enviar SMS o generar token aquí.

        messages.info(
            request,
            "Si los datos coinciden con una cuenta registrada, recibirá "
            "instrucciones para restablecer su contraseña.",
        )
        return redirect("login")

    return render(request, "core/recuperacion.html")


# ---------------------------------------------------------------------------
# Vistas
# ---------------------------------------------------------------------------

@login_required
def dashboard_view(request):
    """Panel principal del ente: modelos y estado reciente del ledger."""

    # Auditor → su panel propio (tabla independiente, solo lectura)
    if _es_auditor_activo(request.user):
        return redirect("auditor_home")

    usuario = request.user
    organizacion = usuario.organizacion

    if not organizacion:
        es_admin = (
            usuario.rol == RolUsuario.ADMINISTRADOR
            or usuario.is_staff
        )

        if es_admin:
            modelos_globales = (
                ModeloIA.objects
                .select_related("organizacion", "version_actual")
                .order_by("-creado_en")
            )
            usuarios_globales = (
                Usuario.objects
                .select_related("organizacion")
                .order_by("-date_joined")
            )
            total_orgs = Organizacion.objects.count()
        else:
            modelos_globales = ModeloIA.objects.none()
            usuarios_globales = Usuario.objects.none()
            total_orgs = 0

        return render(request, "core/sin_organizacion.html", {
            "es_admin": es_admin,
            "modelos": modelos_globales,
            "usuarios": usuarios_globales,
            "total_orgs": total_orgs,
        })


    modelos = (
        ModeloIA.objects
        .filter(organizacion=organizacion)
        .select_related("version_actual")
        .order_by("-creado_en")
    )

    entradas_ledger = (
        EntradaLibroMayor.objects
        .filter(organizacion=organizacion)
        .select_related(
            "version_modelo__modelo",
            "version_conjunto_datos__conjunto_datos",
        )
        .order_by("-secuencia")[:10]
    )

    es_integra, _, motivo = EntradaLibroMayor.verificar_integridad(
        organizacion.id
    )

    return render(request, "core/dashboard.html", {
        "organizacion": organizacion,
        "modelos": modelos,
        "entradas_ledger": entradas_ledger,
        "es_integra": es_integra,
        "motivo_integridad": motivo,
    })


# ---------------------------------------------------------------------------
# Registro de modelos de IA
# ---------------------------------------------------------------------------

@login_required
@transaction.atomic
def registrar_modelo_view(request):
    """Registra un Modelo de IA, su primera versión y la entrada en el ledger."""

    usuario = request.user
    organizacion = usuario.organizacion

    if not organizacion:
        messages.error(
            request,
            "El usuario no está asociado a ninguna organización."
        )
        return redirect("dashboard")

    if request.method == "POST":
        form_modelo = ModeloIAForm(request.POST)
        form_version = VersionModeloForm(request.POST)

        if form_modelo.is_valid() and form_version.is_valid():

            organizacion = _lock_organizacion(organizacion)

            modelo = form_modelo.save(commit=False)
            modelo.organizacion = organizacion
            modelo.save()

            version_modelo = form_version.save(commit=False)
            version_modelo.modelo = modelo
            version_modelo.responsable = usuario
            version_modelo.save()

            form_version.save_m2m()

            modelo.version_actual = version_modelo
            modelo.estado_actual = version_modelo.estado
            modelo.save(
                update_fields=[
                    "version_actual",
                    "estado_actual",
                    "actualizado_en",
                ]
            )

            carga_util = {
                "modelo_id": str(modelo.id),
                "nombre_modelo": modelo.nombre,
                "version_modelo": version_modelo.version,
                "hash_artefacto": version_modelo.hash_artefacto,
                "estado": version_modelo.estado,
                "nivel_riesgo": version_modelo.nivel_riesgo,
                "metadatos": version_modelo.metadatos,
            }

            entrada = _append_ledger_entry(
                organizacion=organizacion,
                tipo=TipoEntradaLibroMayor.REGISTRO_MODELO,
                version_modelo=version_modelo,
                carga_util=carga_util,
                actor=usuario,
            )

            _registrar_bitacora(
                request,
                usuario,
                accion="REGISTRAR_MODELO_IA",
                recurso="ModeloIA",
                identificador=str(modelo.id),
                detalle={
                    "secuencia_ledger": entrada.secuencia,
                    "hash": entrada.hash_actual,
                },
            )

            messages.success(
                request,
                "Modelo de IA registrado y asegurado en el ledger correctamente.",
            )
            return redirect("dashboard")

    else:
        form_modelo = ModeloIAForm()
        form_version = VersionModeloForm()

    return render(request, "core/registrar_modelo.html", {
        "form_modelo": form_modelo,
        "form_version": form_version,
    })


# ---------------------------------------------------------------------------
# Cambio de estado de modelos
# ---------------------------------------------------------------------------

@login_required
@transaction.atomic
def cambiar_estado_modelo_view(request, version_id):
    """Transiciona el ciclo de vida de un modelo (RF-05)."""

    usuario = request.user
    organizacion = usuario.organizacion

    if not organizacion:
        messages.error(
            request,
            "El usuario no está asociado a ninguna organización."
        )
        return redirect("dashboard")

    organizacion = _lock_organizacion(organizacion)

    version_modelo = get_object_or_404(
        VersionModelo,
        pk=version_id,
        modelo__organizacion=organizacion,
    )

    if request.method == "POST":
        form = TransicionEstadoForm(request.POST)

        if form.is_valid():
            estado_anterior = version_modelo.estado
            estado_nuevo = form.cleaned_data["estado_nuevo"]
            justificacion = form.cleaned_data["justificacion"]

            if estado_anterior == estado_nuevo:
                form.add_error(
                    "estado_nuevo",
                    "El nuevo estado debe ser diferente al actual.",
                )

            else:
                version_modelo.estado = estado_nuevo
                version_modelo.save(
                    update_fields=["estado", "actualizado_en"]
                )

                modelo = version_modelo.modelo

                # Solo se actualiza el estado general si esta es
                # la versión que actualmente está activa.
                if modelo.version_actual_id == version_modelo.id:
                    modelo.estado_actual = estado_nuevo
                    modelo.save(
                        update_fields=["estado_actual", "actualizado_en"]
                    )

                carga_util = {
                    "modelo_id": str(modelo.id),
                    "version_modelo_id": str(version_modelo.id),
                    "version": version_modelo.version,
                    "estado_anterior": estado_anterior,
                    "estado_nuevo": estado_nuevo,
                    "justificacion": justificacion,
                }

                entrada = _append_ledger_entry(
                    organizacion=organizacion,
                    tipo=TipoEntradaLibroMayor.CAMBIO_ESTADO,
                    version_modelo=version_modelo,
                    carga_util=carga_util,
                    actor=usuario,
                )

                TransicionEstado.objects.create(
                    version_modelo=version_modelo,
                    estado_anterior=estado_anterior,
                    estado_nuevo=estado_nuevo,
                    justificacion=justificacion,
                    actor=usuario,
                    entrada_libro_mayor=entrada,
                    fecha_transicion=entrada.fecha_registro,
                )

                _registrar_bitacora(
                    request,
                    usuario,
                    accion="CAMBIO_ESTADO_MODELO",
                    recurso="VersionModelo",
                    identificador=str(version_modelo.id),
                    detalle={
                        "estado_anterior": estado_anterior,
                        "estado_nuevo": estado_nuevo,
                        "secuencia_ledger": entrada.secuencia,
                        "hash": entrada.hash_actual,
                    },
                )

                messages.success(
                    request,
                    "Transición de estado registrada con éxito en el ledger.",
                )
                return redirect("dashboard")

    else:
        form = TransicionEstadoForm()

    return render(request, "core/cambiar_estado.html", {
        "form": form,
        "version_modelo": version_modelo,
    })


# ---------------------------------------------------------------------------
# Verificación de la cadena
# ---------------------------------------------------------------------------

@login_required
def verificar_cadena_view(request):
    """Valida la integridad de la cadena de hashes del ente."""

    usuario = request.user
    organizacion = usuario.organizacion

    if not organizacion:
        return redirect("dashboard")

    es_valido, entrada_erronea_id, motivo = (
        EntradaLibroMayor.verificar_integridad(organizacion.id)
    )

    entrada_erronea = None

    if entrada_erronea_id:
        entrada_erronea = EntradaLibroMayor.objects.filter(
            pk=entrada_erronea_id
        ).first()

    return render(request, "core/verificar_cadena.html", {
        "organizacion": organizacion,
        "es_valido": es_valido,
        "motivo": motivo,
        "entrada_erronea": entrada_erronea,
    })


# ---------------------------------------------------------------------------
# Control de acceso por roles (Usuario)
# ---------------------------------------------------------------------------

def rol_requerido(roles_permitidos):
    """
    Restringe la vista a los roles indicados (RF-06).
    Bloquea a auditores: aunque estén autenticados, su panel está en /auditor/.
    Registra en bitácora los accesos denegados.
    """

    permitidos = set(roles_permitidos)

    def deco(view):

        @wraps(view)
        def wrapper(request, *args, **kwargs):

            usuario = request.user

            if not usuario.is_authenticated:
                return redirect("login")

            # Un Auditor nunca opera sobre las vistas de Usuario
            if isinstance(usuario, Auditor):
                messages.error(
                    request,
                    "Los auditores no tienen acceso a esta acción."
                )
                return redirect("auditor_home")

            if usuario.rol not in permitidos:

                BitacoraAuditoria.objects.create(
                    usuario=usuario,
                    accion="ACCESO_DENEGADO",
                    recurso=view.__name__,
                    detalle={
                        "rol_actual": usuario.rol,
                        "roles_requeridos": sorted(permitidos),
                    },
                    direccion_ip=request.META.get("REMOTE_ADDR"),
                    agente_usuario=request.META.get(
                        "HTTP_USER_AGENT", ""
                    ),
                    exitoso=False,
                )

                messages.error(
                    request,
                    "No tiene permisos para realizar esta acción."
                )
                return redirect("dashboard")

            return view(request, *args, **kwargs)

        return wrapper

    return deco


# ---------------------------------------------------------------------------
# Alcance y filtros del libro mayor
# ---------------------------------------------------------------------------

def _ledger_scope(user):
    """
    Alcance del ledger según el tipo de usuario:

    - Auditor con alcance_global: todas las organizaciones.
    - Auditor con alcance limitado: solo sus organizaciones.
    - ADMINISTRADOR: todas las organizaciones.
    - Resto (REGISTRADOR / VALIDADOR): únicamente su organización.
    """

    if isinstance(user, Auditor):
        if user.alcance_global:
            return EntradaLibroMayor.objects.all()
        org_ids = user.organizaciones_en_alcance.values_list("id", flat=True)
        return EntradaLibroMayor.objects.filter(organizacion_id__in=org_ids)

    if user.rol == RolUsuario.ADMINISTRADOR:
        return EntradaLibroMayor.objects.all()

    if not user.organizacion_id:
        return EntradaLibroMayor.objects.none()

    return EntradaLibroMayor.objects.filter(
        organizacion_id=user.organizacion_id
    )


def _aplicar_filtros(qs, data):
    """Aplica los filtros del formulario de auditoría (RF-04)."""

    if data.get("organizacion"):
        qs = qs.filter(organizacion=data["organizacion"])

    if data.get("modelo"):
        termino = data["modelo"]

        qs = qs.filter(
            Q(version_modelo__modelo__nombre__icontains=termino)
            | Q(carga_util__nombre_modelo__icontains=termino)
        )

    if data.get("responsable"):
        qs = qs.filter(
            actor__username__icontains=data["responsable"]
        )

    if data.get("version"):
        termino = data["version"]

        qs = qs.filter(
            Q(version_modelo__version__icontains=termino)
            | Q(version_conjunto_datos__version__icontains=termino)
        )

    if data.get("fecha_desde"):
        qs = qs.filter(
            fecha_registro__date__gte=data["fecha_desde"]
        )

    if data.get("fecha_hasta"):
        qs = qs.filter(
            fecha_registro__date__lte=data["fecha_hasta"]
        )

    if data.get("tipo"):
        qs = qs.filter(tipo=data["tipo"])

    return qs


# ---------------------------------------------------------------------------
# Registro de conjuntos de datos
# ---------------------------------------------------------------------------

@login_required
@transaction.atomic
@rol_requerido([RolUsuario.REGISTRADOR, RolUsuario.ADMINISTRADOR])
def registrar_conjunto_datos_view(request):
    """
    Crea un ConjuntoDatos, su primera VersionConjuntoDatos
    y la entrada correspondiente en el ledger.
    """

    usuario = request.user
    organizacion = usuario.organizacion

    if not organizacion:
        messages.error(
            request,
            "El usuario no está asociado a ninguna organización."
        )
        return redirect("dashboard")

    if request.method == "POST":

        form_ds = ConjuntoDatosForm(request.POST)
        form_v = VersionConjuntoDatosForm(request.POST)

        if form_ds.is_valid() and form_v.is_valid():

            organizacion = _lock_organizacion(organizacion)

            conjunto = form_ds.save(commit=False)
            conjunto.organizacion = organizacion
            conjunto.save()

            version = form_v.save(commit=False)
            version.conjunto_datos = conjunto
            version.responsable = usuario
            version.save()

            carga = {
                "conjunto_datos_id": str(conjunto.id),
                "nombre": conjunto.nombre,
                "version": version.version,
                "hash_archivo": version.hash_archivo,
                "algoritmo_hash": version.algoritmo_hash,
                "metadatos": version.metadatos,
            }

            entrada = _append_ledger_entry(
                organizacion=organizacion,
                tipo=TipoEntradaLibroMayor.REGISTRO_DATOS,
                version_modelo=None,
                version_conjunto_datos=version,
                carga_util=carga,
                actor=usuario,
            )

            _registrar_bitacora(
                request,
                usuario,
                "REGISTRAR_CONJUNTO_DATOS",
                "ConjuntoDatos",
                identificador=str(conjunto.id),
                detalle={
                    "secuencia_ledger": entrada.secuencia,
                    "hash": entrada.hash_actual,
                },
            )

            messages.success(
                request,
                "Conjunto de datos y versión inicial registrados en el ledger."
            )
            return redirect("dashboard")

    else:
        form_ds = ConjuntoDatosForm()
        form_v = VersionConjuntoDatosForm()

    return render(request, "core/registrar_conjunto_datos.html", {
        "form_ds": form_ds,
        "form_v": form_v,
    })


@login_required
@transaction.atomic
@rol_requerido([RolUsuario.REGISTRADOR, RolUsuario.ADMINISTRADOR])
def registrar_version_conjunto_datos_view(request, conjunto_id):
    """Añade una nueva versión inmutable a un ConjuntoDatos (RF-02)."""

    usuario = request.user
    organizacion = usuario.organizacion

    if not organizacion:
        return redirect("dashboard")

    organizacion = _lock_organizacion(organizacion)

    conjunto = get_object_or_404(
        ConjuntoDatos,
        pk=conjunto_id,
        organizacion=organizacion,
    )

    if request.method == "POST":

        form = VersionConjuntoDatosForm(request.POST)

        if form.is_valid():

            version = form.save(commit=False)
            version.conjunto_datos = conjunto
            version.responsable = usuario
            version.save()

            carga = {
                "conjunto_datos_id": str(conjunto.id),
                "version": version.version,
                "hash_archivo": version.hash_archivo,
                "algoritmo_hash": version.algoritmo_hash,
                "metadatos": version.metadatos,
            }

            entrada = _append_ledger_entry(
                organizacion=organizacion,
                tipo=TipoEntradaLibroMayor.REGISTRO_DATOS,
                version_modelo=None,
                version_conjunto_datos=version,
                carga_util=carga,
                actor=usuario,
            )

            _registrar_bitacora(
                request,
                usuario,
                "REGISTRAR_VERSION_DATASET",
                "VersionConjuntoDatos",
                identificador=str(version.id),
                detalle={
                    "secuencia_ledger": entrada.secuencia,
                    "version": version.version,
                },
            )

            messages.success(
                request,
                "Nueva versión del conjunto de datos registrada."
            )
            return redirect("dashboard")

    else:
        form = VersionConjuntoDatosForm()

    return render(request, "core/registrar_version_dataset.html", {
        "form": form,
        "conjunto": conjunto,
    })


# ---------------------------------------------------------------------------
# Registro de nuevas versiones de modelos
# ---------------------------------------------------------------------------

@login_required
@transaction.atomic
@rol_requerido([RolUsuario.REGISTRADOR, RolUsuario.ADMINISTRADOR])
def registrar_version_modelo_view(request, modelo_id):
    """
    Añade una nueva VersiónModelo a un ModeloIA existente (RF-02).

    La versión anterior permanece intacta. Se actualizan el puntero
    modelo.version_actual y el estado general del modelo.
    """

    usuario = request.user
    organizacion = usuario.organizacion

    if not organizacion:
        return redirect("dashboard")

    organizacion = _lock_organizacion(organizacion)

    modelo = get_object_or_404(
        ModeloIA,
        pk=modelo_id,
        organizacion=organizacion,
    )

    if request.method == "POST":

        form = VersionModeloForm(request.POST)

        if form.is_valid():

            version = form.save(commit=False)
            version.modelo = modelo
            version.responsable = usuario
            version.save()

            form.save_m2m()

            modelo.version_actual = version
            modelo.estado_actual = version.estado
            modelo.save(
                update_fields=[
                    "version_actual",
                    "estado_actual",
                    "actualizado_en",
                ]
            )

            carga = {
                "modelo_id": str(modelo.id),
                "version_modelo": version.version,
                "hash_artefacto": version.hash_artefacto,
                "estado": version.estado,
                "nivel_riesgo": version.nivel_riesgo,
                "metadatos": version.metadatos,
            }

            entrada = _append_ledger_entry(
                organizacion=organizacion,
                tipo=TipoEntradaLibroMayor.ACTUALIZACION_MODELO,
                version_modelo=version,
                carga_util=carga,
                actor=usuario,
            )

            _registrar_bitacora(
                request,
                usuario,
                "REGISTRAR_VERSION_MODELO",
                "VersionModelo",
                identificador=str(version.id),
                detalle={
                    "secuencia_ledger": entrada.secuencia,
                    "version": version.version,
                },
            )

            messages.success(
                request,
                "Nueva versión del modelo registrada y encadenada."
            )
            return redirect("dashboard")

    else:
        form = VersionModeloForm()

    return render(request, "core/registrar_version_modelo.html", {
        "form": form,
        "modelo": modelo,
    })


# ---------------------------------------------------------------------------
# RF-04 — Auditoría y exportación (Usuario: VALIDADOR / ADMINISTRADOR)
# ---------------------------------------------------------------------------

@login_required
@rol_requerido([
    RolUsuario.VALIDADOR,
    RolUsuario.ADMINISTRADOR,
])
def auditoria_view(request):
    """Búsqueda y auditoría con filtros por ente, modelo, responsable y fechas."""

    form = AuditoriaFilterForm(request.GET or None)
    qs = _ledger_scope(request.user)

    if form.is_valid():
        qs = _aplicar_filtros(qs, form.cleaned_data)

    qs = (
        qs.select_related(
            "organizacion",
            "actor",
            "version_modelo__modelo",
            "version_conjunto_datos__conjunto_datos",
        )
        .order_by("-fecha_registro")
    )

    page = Paginator(qs, 50).get_page(request.GET.get("page"))

    _registrar_bitacora(
        request,
        request.user,
        "CONSULTA_AUDITORIA",
        "EntradaLibroMayor",
        detalle={
            "filtros": {
                k: str(v)
                for k, v in (
                    form.cleaned_data if form.is_valid() else {}
                ).items()
            }
        },
    )

    return render(request, "core/auditoria.html", {
        "form": form,
        "page_obj": page,
    })


class _Echo:
    """Objeto auxiliar para generar CSV mediante streaming."""

    def write(self, value):
        return value


@login_required
@rol_requerido([RolUsuario.ADMINISTRADOR])
def exportar_csv_view(request):
    """Exporta a CSV en streaming (RNF-03)."""

    form = AuditoriaFilterForm(request.GET or None)
    qs = _ledger_scope(request.user)

    if form.is_valid():
        qs = _aplicar_filtros(qs, form.cleaned_data)

    qs = (
        qs.select_related(
            "organizacion",
            "actor",
            "version_modelo__modelo",
            "version_conjunto_datos__conjunto_datos",
        )
        .order_by("secuencia")
    )

    writer = csv.writer(_Echo())

    def filas():

        yield writer.writerow([
            "secuencia",
            "organizacion",
            "tipo",
            "modelo",
            "version",
            "conjunto_datos",
            "version_conjunto_datos",
            "actor",
            "fecha",
            "hash_anterior",
            "hash_actual",
            "integra",
        ])

        for entrada in qs.iterator(chunk_size=2000):

            modelo = ""
            version_modelo = ""
            conjunto_datos = ""
            version_dataset = ""

            if entrada.version_modelo:
                modelo = entrada.version_modelo.modelo.nombre
                version_modelo = entrada.version_modelo.version

            if entrada.version_conjunto_datos:
                conjunto_datos = (
                    entrada.version_conjunto_datos.conjunto_datos.nombre
                )
                version_dataset = entrada.version_conjunto_datos.version

            yield writer.writerow([
                entrada.secuencia,
                entrada.organizacion.siglas or entrada.organizacion.nombre,
                entrada.get_tipo_display(),
                modelo,
                version_modelo,
                conjunto_datos,
                version_dataset,
                entrada.actor.get_username(),
                entrada.fecha_registro.isoformat(),
                entrada.hash_anterior or "",
                entrada.hash_actual,
                "",
            ])

    response = StreamingHttpResponse(
        filas(),
        content_type="text/csv; charset=utf-8",
    )

    response["Content-Disposition"] = (
        'attachment; filename="auditoria_libro_mayor.csv"'
    )

    _registrar_bitacora(
        request,
        request.user,
        "EXPORTAR_CSV",
        "EntradaLibroMayor",
        detalle={
            "filtros": {
                k: str(v)
                for k, v in (
                    form.cleaned_data if form.is_valid() else {}
                ).items()
            }
        },
    )

    return response


@login_required
@rol_requerido([RolUsuario.ADMINISTRADOR])
def exportar_pdf_view(request):
    """Exporta a PDF con límite de filas para mantener el rendimiento."""

    LIMITE = 5000

    form = AuditoriaFilterForm(request.GET or None)
    qs = _ledger_scope(request.user)

    if form.is_valid():
        qs = _aplicar_filtros(qs, form.cleaned_data)

    qs = (
        qs.select_related(
            "organizacion",
            "actor",
            "version_modelo__modelo",
            "version_conjunto_datos__conjunto_datos",
        )
        .order_by("secuencia")
    )

    total = qs.count()
    filas = qs[:LIMITE]

    buf = BytesIO()

    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        title="Reporte de auditoría — Libro Mayor",
    )

    styles = getSampleStyleSheet()

    elementos = [
        Paragraph(
            "Reporte de auditoría — Libro Mayor",
            styles["Title"],
        ),
        Spacer(1, 8),
        Paragraph(
            f"Registros coincidentes: {total} "
            f"(se muestran hasta {LIMITE}).",
            styles["Normal"],
        ),
        Spacer(1, 12),
    ]

    data = [[
        "#",
        "Fecha",
        "Tipo",
        "Modelo / Versión",
        "Conjunto de datos",
        "Actor",
        "Hash actual",
    ]]

    for entrada in filas:

        if entrada.version_modelo:
            referencia = (
                f"{entrada.version_modelo.modelo.nombre} "
                f"v{entrada.version_modelo.version}"
            )

        elif entrada.version_conjunto_datos:
            referencia = (
                f"{entrada.version_conjunto_datos.conjunto_datos.nombre} "
                f"v{entrada.version_conjunto_datos.version}"
            )

        else:
            referencia = "—"

        data.append([
            str(entrada.secuencia),
            entrada.fecha_registro.strftime("%Y-%m-%d %H:%M"),
            entrada.get_tipo_display(),
            referencia,
            (
                entrada.version_conjunto_datos.conjunto_datos.nombre
                if entrada.version_conjunto_datos
                else "—"
            ),
            entrada.actor.get_username(),
            entrada.hash_actual[:16] + "…",
        ])

    tabla = Table(data, repeatRows=1)

    tabla.setStyle(TableStyle([
        (
            "BACKGROUND",
            (0, 0),
            (-1, 0),
            colors.HexColor("#1e3a8a"),
        ),
        (
            "TEXTCOLOR",
            (0, 0),
            (-1, 0),
            colors.white,
        ),
        (
            "FONTSIZE",
            (0, 0),
            (-1, -1),
            8,
        ),
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.25,
            colors.grey,
        ),
        (
            "VALIGN",
            (0, 0),
            (-1, -1),
            "TOP",
        ),
    ]))

    elementos.append(tabla)
    doc.build(elementos)

    response = HttpResponse(
        buf.getvalue(),
        content_type="application/pdf",
    )

    response["Content-Disposition"] = (
        'attachment; filename="auditoria_libro_mayor.pdf"'
    )

    _registrar_bitacora(
        request,
        request.user,
        "EXPORTAR_PDF",
        "EntradaLibroMayor",
        detalle={
            "total": total,
            "mostrados": min(total, LIMITE),
        },
    )

    return response


# ---------------------------------------------------------------------------
# Panel del Auditor (tabla independiente, solo lectura, HTMX)
# ---------------------------------------------------------------------------

@auditor_requerido
def auditor_home_view(request):
    """Cascarón del panel de auditor. Los paneles se cargan vía HTMX."""
    return render(request, "core/auditor/home.html", {
        "auditor": request.user,
    })


@auditor_requerido
def auditor_resumen_partial(request):
    """Tarjetas de totales (HTMX)."""
    return render(request, "core/auditor/partials/resumen.html", {
        "total_orgs": Organizacion.objects.count(),
        "total_modelos": ModeloIA.objects.count(),
        "total_datasets": ConjuntoDatos.objects.count(),
        "total_entradas": EntradaLibroMayor.objects.count(),
    })


@auditor_requerido
def auditor_integridad_partial(request):
    """Estado de integridad por organización (HTMX, polling)."""
    qs_orgs = Organizacion.objects.all()
    if not request.user.alcance_global:
        qs_orgs = request.user.organizaciones_en_alcance.all()

    resultados = []
    for org in qs_orgs:
        es_valido, _, motivo = EntradaLibroMayor.verificar_integridad(org.id)
        resultados.append({
            "organizacion": org,
            "es_valido": es_valido,
            "motivo": motivo,
        })

    return render(request, "core/auditor/partials/integridad.html", {
        "resultados": resultados,
    })


@auditor_requerido
def auditor_ledger_partial(request):
    """Últimas 30 entradas del ledger según el alcance del auditor (HTMX)."""
    qs = _ledger_scope(request.user)
    entradas = (
        qs.select_related(
            "organizacion", "actor",
            "version_modelo__modelo",
            "version_conjunto_datos__conjunto_datos",
        )
        .order_by("-fecha_registro")[:30]
    )
    return render(request, "core/auditor/partials/ledger.html", {
        "entradas": entradas,
    })


@auditor_requerido
def auditor_organizaciones_partial(request):
    """Listado de organizaciones con conteos (HTMX)."""
    qs_orgs = Organizacion.objects.all()
    if not request.user.alcance_global:
        qs_orgs = request.user.organizaciones_en_alcance.all()

    organizaciones = (
        qs_orgs
        .prefetch_related("modelos_ia", "conjuntos_datos")
        .order_by("nombre")
    )
    return render(request, "core/auditor/partials/organizaciones.html", {
        "organizaciones": organizaciones,
    })

