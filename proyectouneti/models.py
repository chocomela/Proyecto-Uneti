from django.contrib.auth.models import ( AbstractBaseUser, BaseUserManager, PermissionsMixin,)
import hashlib
import json
import uuid
from datetime import timezone as dt_timezone
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone



class ModeloBase(models.Model):
    creado_en = models.DateTimeField(auto_now_add=True, db_index=True)
    actualizado_en = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Organizacion(ModeloBase):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nombre = models.CharField(max_length=20, unique=True)
    siglas = models.CharField(max_length=20, blank=True)
    rif = models.CharField(max_length=20, unique=True)
    activo = models.BooleanField(default=True)

    class Meta:
        db_table = "organizacion"
        ordering = ["nombre"]
        verbose_name = "Organización"
        verbose_name_plural = "Organizaciones"

    def __str__(self):
        return f"{self.siglas} - {self.nombre}" if self.siglas else self.nombre


class RolUsuario(models.TextChoices):
    REGISTRADOR = "registrador", "Registrador"
    VALIDADOR = "validador", "Validador"
    ADMINISTRADOR = "administrador", "Administrador"

class AuditorManager(BaseUserManager):
    def create_auditor(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError("El auditor requiere username.")
        auditor = self.model(username=username, **extra_fields)
        auditor.set_password(password)
        auditor.save(using=self._db)
        return auditor


class Auditor(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(blank=True)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)

    credencial = models.CharField(max_length=100, unique=True)
    fecha_acreditacion = models.DateField()
    fecha_expiracion = models.DateField(null=True, blank=True)
    alcance_global = models.BooleanField(
        default=True,
        help_text="Si es False, solo ve las organizaciones listadas abajo.",
    )
    organizaciones_en_alcance = models.ManyToManyField(
        Organizacion, blank=True, related_name="auditores_con_alcance",
    )
    activo = models.BooleanField(default=True)

    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    creado_en = models.DateTimeField(auto_now_add=True)
    actualizado_en = models.DateTimeField(auto_now=True)

    # ── Override de PermissionsMixin: evita clash con Usuario ──
    groups = models.ManyToManyField(
        "auth.Group",
        blank=True,
        related_name="auditores",
        related_query_name="auditor",
        verbose_name="grupos",
    )
    user_permissions = models.ManyToManyField(
        "auth.Permission",
        blank=True,
        related_name="auditores_perm",
        related_query_name="auditor_perm",
        verbose_name="permisos de usuario",
    )

    objects = AuditorManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["credencial"]

    class Meta:
        db_table = "auditor"
        verbose_name = "Auditor"
        verbose_name_plural = "Auditores"
        ordering = ["username"]

    def __str__(self):
        return f"{self.get_full_name() or self.username} ({self.credencial})"

    def get_full_name(self):
        nombre = f"{self.first_name} {self.last_name}".strip()
        return nombre or self.username

    def get_short_name(self):
        return self.first_name or self.username

    @property
    def vigente(self):
        if not self.activo or not self.is_active:
            return False
        if self.fecha_expiracion and self.fecha_expiracion < timezone.now().date():
            return False
        return True



class Usuario(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizacion = models.ForeignKey(
        Organizacion, on_delete=models.PROTECT,
        related_name="usuarios", null=True, blank=True,
    )
    cargo = models.CharField(max_length=50, blank=True)
    rol = models.CharField(
        max_length=20, choices=RolUsuario.choices,
        default=RolUsuario.REGISTRADOR, db_index=True,
    )
    clave_publica = models.TextField(
        blank=True,
        help_text="Clave pública para verificar firmas institucionales (RNF-01).",
    )
    huella_clave_publica = models.CharField(
        max_length=64, blank=True, db_index=True,
        help_text="SHA-256 de la clave pública activa para validar firmas históricas.",
    )

    class Meta:
        db_table = "usuario"
        verbose_name = "Usuario"
        verbose_name_plural = "Usuarios"
        indexes = [models.Index(fields=["organizacion", "rol"])]

    def __str__(self):
        return f"{self.get_full_name() or self.username} ({self.get_rol_display()})"

class Contacto(ModeloBase):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    usuario = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        null=True, blank=True, related_name="contactos",
    )
    auditor = models.ForeignKey(
        Auditor, on_delete=models.CASCADE,
        null=True, blank=True, related_name="contactos",
    )
    telefono = models.CharField(max_length=30, blank=True)
    email = models.EmailField(blank=True)
    principal = models.BooleanField(
        default=True,
        help_text="Contacto preferido para notificaciones y recuperación.",
    )

    class Meta:
        db_table = "contacto"
        verbose_name = "Contacto"
        verbose_name_plural = "Contactos"
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(usuario__isnull=False, auditor__isnull=True)
                    | models.Q(usuario__isnull=True, auditor__isnull=False)
                ),
                name="ck_contacto_un_solo_dueno",
            ),
        ]
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["telefono"]),
        ]

    def __str__(self):
        return self.email or self.telefono or f"Contacto {self.pk}"

class NivelRiesgo(models.TextChoices):
    BAJO = "bajo", "Bajo"
    MEDIO = "medio", "Medio"
    ALTO = "alto", "Alto"


class EstadoModelo(models.TextChoices):
    DESARROLLO = "desarrollo", "En desarrollo"
    VALIDACION = "validacion", "En validación"
    PRODUCCION = "produccion", "En producción"
    RETIRADO = "retirado", "Retirado"


class ConjuntoDatos(ModeloBase):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizacion = models.ForeignKey(
        Organizacion, on_delete=models.PROTECT, related_name="conjuntos_datos",
    )
    nombre = models.CharField(max_length=30)
    fuente = models.URLField(max_length=50, blank=True)
    licencia = models.CharField(max_length=100, blank=True)
    descripcion = models.TextField(blank=True)
    nivel_riesgo = models.CharField(
        max_length=10, choices=NivelRiesgo.choices, default=NivelRiesgo.BAJO,
    )
    sin_datos_personales = models.BooleanField(
        default=True,
        help_text="Garantiza que no contiene datos personales de ciudadanos (RNF-01).",
    )

    class Meta:
        db_table = "conjunto_datos"
        verbose_name = "Conjunto de Datos"
        verbose_name_plural = "Conjuntos de Datos"
        indexes = [models.Index(fields=["organizacion", "nombre"])]
        constraints = [
            models.UniqueConstraint(
                fields=["organizacion", "nombre"],
                name="uq_conjunto_datos_organizacion_nombre",
            ),
            models.CheckConstraint(
                condition=models.Q(sin_datos_personales=True),
                name="ck_conjunto_datos_sin_datos_personales",
            ),
        ]

    def __str__(self):
        return f"{self.nombre} ({self.organizacion.nombre})"


class VersionConjuntoDatos(ModeloBase):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conjunto_datos = models.ForeignKey(
        ConjuntoDatos, on_delete=models.PROTECT, related_name="versiones",
    )
    version = models.CharField(max_length=50)
    hash_archivo = models.CharField(max_length=128, db_index=True)
    algoritmo_hash = models.CharField(max_length=20, default="SHA-256")
    fecha_version = models.DateField()
    metadatos = models.JSONField(default=dict, blank=True)
    responsable = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="versiones_conjunto_datos",
    )

    class Meta:
        db_table = "version_conjunto_datos"
        verbose_name = "Versión de Conjunto de Datos"
        verbose_name_plural = "Versiones de Conjuntos de Datos"
        indexes = [models.Index(fields=["conjunto_datos", "version"])]
        constraints = [
            models.UniqueConstraint(
                fields=["conjunto_datos", "version"],
                name="uq_version_conjunto_datos_dataset_version",
            ),
        ]

    def __str__(self):
        return f"{self.conjunto_datos.nombre} v{self.version}"



class ModeloIA(ModeloBase):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizacion = models.ForeignKey(
        Organizacion, on_delete=models.PROTECT, related_name="modelos_ia",
    )
    nombre = models.CharField(max_length=30)
    proveedor_framework = models.CharField(max_length=25, blank=True)
    proposito = models.TextField(
        blank=True,
        help_text="Proceso o decisión automatizada donde se emplea el modelo.",
    )
    descripcion = models.TextField(blank=True)
    nivel_riesgo = models.CharField(
        max_length=10, choices=NivelRiesgo.choices, default=NivelRiesgo.BAJO,
    )
    estado_actual = models.CharField(
        max_length=20, choices=EstadoModelo.choices,
        default=EstadoModelo.DESARROLLO, db_index=True,
    )
    version_actual = models.ForeignKey(
        "VersionModelo", null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    ficha_publica = models.BooleanField(
        default=False,
        help_text="Si la ficha técnica es consultable por la ciudadanía en producción.",
    )

    class Meta:
        db_table = "modelo_ia"
        verbose_name = "Modelo de IA"
        verbose_name_plural = "Modelos de IA"
        indexes = [
            models.Index(fields=["organizacion", "estado_actual"]),
            models.Index(fields=["nombre"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["organizacion", "nombre"],
                name="uq_modelo_ia_organizacion_nombre",
            ),
        ]

    def __str__(self):
        return f"{self.nombre} [{self.get_estado_actual_display()}]"


class VersionModelo(ModeloBase):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    modelo = models.ForeignKey(
        ModeloIA, on_delete=models.PROTECT, related_name="versiones",
    )
    version = models.CharField(max_length=50)
    hash_artefacto = models.CharField(max_length=128, db_index=True)
    algoritmo_hash = models.CharField(max_length=20, default="SHA-256")
    estado = models.CharField(
        max_length=20, choices=EstadoModelo.choices, default=EstadoModelo.DESARROLLO,
    )
    nivel_riesgo = models.CharField(
        max_length=10, choices=NivelRiesgo.choices, default=NivelRiesgo.BAJO,
    )
    responsable = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="versiones_modelo",
    )
    conjuntos_datos = models.ManyToManyField(
        VersionConjuntoDatos, through="VersionModeloConjuntoDatos",
        related_name="modelos",
    )
    metadatos = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "version_modelo"
        verbose_name = "Versión de Modelo"
        verbose_name_plural = "Versiones de Modelos"
        indexes = [
            models.Index(fields=["modelo", "version"]),
            models.Index(fields=["responsable", "creado_en"]),
            models.Index(fields=["estado", "creado_en"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["modelo", "version"],
                name="uq_version_modelo_modelo_version",
            ),
        ]

    def __str__(self):
        return f"{self.modelo.nombre} v{self.version}"


class RolConjuntoDatos(models.TextChoices):
    ENTRENAMIENTO = "entrenamiento", "Entrenamiento"
    AJUSTE_FINO = "ajuste_fino", "Ajuste fino (Fine-tuning)"
    EVALUACION = "evaluacion", "Evaluación"


class VersionModeloConjuntoDatos(models.Model):
    version_modelo = models.ForeignKey(VersionModelo, on_delete=models.CASCADE)
    version_conjunto_datos = models.ForeignKey(VersionConjuntoDatos, on_delete=models.PROTECT)
    rol = models.CharField(
        max_length=20, choices=RolConjuntoDatos.choices,
        default=RolConjuntoDatos.ENTRENAMIENTO,
    )

    class Meta:
        db_table = "version_modelo_conjunto_datos"
        verbose_name = "Dataset de Versión de Modelo"
        verbose_name_plural = "Datasets de Versiones de Modelos"
        constraints = [
            models.UniqueConstraint(
                fields=["version_modelo", "version_conjunto_datos", "rol"],
                name="uq_vmcd_version_modelo_dataset_rol",
            ),
        ]



class TipoEntradaLibroMayor(models.TextChoices):
    REGISTRO_MODELO = "registro_modelo", "Registro de modelo"
    ACTUALIZACION_MODELO = "actualizacion_modelo", "Actualización de modelo"
    CAMBIO_ESTADO = "cambio_estado", "Cambio de estado"
    REGISTRO_DATOS = "registro_datos", "Registro de conjunto de datos"
    RETIRO = "retiro", "Retiro de modelo"


class EntradaLibroMayor(models.Model):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizacion = models.ForeignKey(
        Organizacion, on_delete=models.PROTECT, related_name="entradas_libro_mayor",
    )
    secuencia = models.BigIntegerField()
    tipo = models.CharField(
        max_length=30, choices=TipoEntradaLibroMayor.choices, db_index=True,
    )
    version_modelo = models.ForeignKey(
        VersionModelo, null=True, blank=True,
        on_delete=models.PROTECT, related_name="entradas_libro_mayor",
    )
    version_conjunto_datos = models.ForeignKey(
        VersionConjuntoDatos, null=True, blank=True,
        on_delete=models.PROTECT, related_name="entradas_libro_mayor",
    )

    version_esquema = models.PositiveSmallIntegerField(default=1)
    algoritmo_hash = models.CharField(max_length=20, default="SHA-256")
    carga_util = models.JSONField()
    hash_anterior = models.CharField(max_length=128, null=True, blank=True)
    hash_actual = models.CharField(max_length=128, unique=True)
    firma_institucional = models.TextField(blank=True)
    huella_clave_firmante = models.CharField(max_length=64, blank=True)
    firmado_por = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.PROTECT, related_name="entradas_firmadas",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="entradas_ejecutadas",
    )
    fecha_registro = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "entrada_libro_mayor"
        verbose_name = "Entrada del Libro Mayor"
        verbose_name_plural = "Entradas del Libro Mayor"
        ordering = ["-fecha_registro"]
        indexes = [
            models.Index(fields=["organizacion", "secuencia"]),
            models.Index(fields=["organizacion", "fecha_registro"]),
            models.Index(fields=["organizacion", "tipo", "fecha_registro"]),
            models.Index(fields=["hash_actual"]),
            models.Index(fields=["hash_anterior"]),
            models.Index(fields=["fecha_registro"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["organizacion", "secuencia"],
                name="uq_entrada_libro_mayor_organizacion_secuencia",
            ),
            models.CheckConstraint(
                condition=models.Q(secuencia__gte=1),
                name="ck_entrada_libro_mayor_secuencia_positiva",
            ),
        ]

    def save(self, *args, **kwargs):
        if self.pk and EntradaLibroMayor.objects.filter(pk=self.pk).exists():
            raise ValidationError("Las entradas del libro mayor son inmutables.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Las entradas del libro mayor no pueden eliminarse.")

    @staticmethod
    def calcular_hash(*, organizacion_id, secuencia, tipo, carga_util,
                      hash_anterior, fecha_registro, actor_id) -> str:
        marca_tiempo = (
            fecha_registro.astimezone(dt_timezone.utc).isoformat()
            if hasattr(fecha_registro, "astimezone") else str(fecha_registro)
        )
        canonico = json.dumps(
            {
                "organizacion_id": str(organizacion_id),
                "secuencia": int(secuencia),
                "tipo": str(tipo),
                "carga_util": carga_util,
                "hash_anterior": hash_anterior or "",
                "fecha_registro": marca_tiempo,
                "actor_id": str(actor_id),
            },
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )
        return hashlib.sha256(canonico.encode("utf-8")).hexdigest()

    @classmethod
    def verificar_integridad(cls, organizacion_id):
        entradas = list(
            cls.objects.filter(organizacion_id=organizacion_id).order_by("secuencia")
        )
        anterior = None
        for entrada in entradas:
            if anterior is None:
                if entrada.secuencia != 1 or entrada.hash_anterior:
                    return False, entrada.id, "Primer registro inconsistente"
            else:
                if entrada.secuencia != anterior.secuencia + 1:
                    return False, entrada.id, "Hueco en la secuencia"
                if entrada.hash_anterior != anterior.hash_actual:
                    return False, entrada.id, "hash_anterior no coincide"

            hash_recalculado = cls.calcular_hash(
                organizacion_id=entrada.organizacion_id,
                secuencia=entrada.secuencia,
                tipo=entrada.tipo,
                carga_util=entrada.carga_util,
                hash_anterior=entrada.hash_anterior,
                fecha_registro=entrada.fecha_registro,
                actor_id=entrada.actor_id,
            )
            if hash_recalculado != entrada.hash_actual:
                return False, entrada.id, "Hash recalculado no coincide"
            anterior = entrada
        return True, None, "OK"

    def __str__(self):
        return f"#{self.secuencia} {self.get_tipo_display()} ({self.hash_actual[:10]}…)"


class TransicionEstado(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    version_modelo = models.ForeignKey(
        VersionModelo, on_delete=models.PROTECT, related_name="transiciones",
    )
    estado_anterior = models.CharField(max_length=20, choices=EstadoModelo.choices)
    estado_nuevo = models.CharField(max_length=20, choices=EstadoModelo.choices)
    justificacion = models.TextField(blank=True)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    entrada_libro_mayor = models.ForeignKey(EntradaLibroMayor, on_delete=models.PROTECT)
    fecha_transicion = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "transicion_estado"
        verbose_name = "Transición de Estado"
        verbose_name_plural = "Transiciones de Estado"
        ordering = ["-fecha_transicion"]
        indexes = [models.Index(fields=["version_modelo", "fecha_transicion"])]

    def __str__(self):
        return f"{self.version_modelo} → {self.get_estado_nuevo_display()}"



class BitacoraAuditoria(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    usuario = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
    )
    accion = models.CharField(max_length=10, db_index=True)
    recurso = models.CharField(max_length=10, db_index=True)
    identificador_recurso = models.CharField(max_length=64, blank=True)
    detalle = models.JSONField(default=dict, blank=True)
    direccion_ip = models.GenericIPAddressField(null=True, blank=True)
    agente_usuario = models.TextField(blank=True)
    exitoso = models.BooleanField(default=True)
    fecha_evento = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "bitacora_auditoria"
        verbose_name = "Registro de Bitácora"
        verbose_name_plural = "Bitácora de Auditoría"
        ordering = ["-fecha_evento"]
        indexes = [
            models.Index(fields=["usuario", "fecha_evento"]),
            models.Index(fields=["accion", "fecha_evento"]),
            models.Index(fields=["recurso", "identificador_recurso"]),
        ]

    def __str__(self):
        return f"[{self.fecha_evento:%Y-%m-%d %H:%M}] {self.accion} - {self.recurso}"