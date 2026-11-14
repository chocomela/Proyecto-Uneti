# proyectouneti/form.py
from django import forms
import re

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.core.validators import MinLengthValidator, RegexValidator
from .models import (
    ConjuntoDatos,
    VersionConjuntoDatos,
    ModeloIA,
    VersionModelo,
    TransicionEstado,
    EstadoModelo,             # noqa: F401 (se usa para que el widget rinda bien las choices)
    TipoEntradaLibroMayor,
    Usuario,
    Organizacion,
)


class ConjuntoDatosForm(forms.ModelForm):
    """Formulario para registrar o actualizar un conjunto de datos base."""
    class Meta:
        model = ConjuntoDatos
        fields = [
            "nombre",
            "fuente",
            "licencia",
            "descripcion",
            "nivel_riesgo",
            "sin_datos_personales",
        ]
        widgets = {
            "nombre": forms.TextInput(attrs={"class": "form-control", "placeholder": "Ej. Registro Nacional de Trámites"}),
            "fuente": forms.URLInput(attrs={"class": "form-control", "placeholder": "https://huggingface.co/datasets/..."}),
            "licencia": forms.TextInput(attrs={"class": "form-control", "placeholder": "Ej. CC-BY 4.0"}),
            "descripcion": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
            "nivel_riesgo": forms.Select(attrs={"class": "form-select"}),
            "sin_datos_personales": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }

    def clean_sin_datos_personales(self):
        val = self.cleaned_data.get("sin_datos_personales")
        if not val:
            raise forms.ValidationError(
                "Por cumplimiento normativo (RNF-01), es obligatorio declarar que "
                "el conjunto de datos está libre de información personal de ciudadanos."
            )
        return val


class VersionConjuntoDatosForm(forms.ModelForm):
    """Formulario para registrar una nueva versión inmutable de un dataset."""
    class Meta:
        model = VersionConjuntoDatos
        # CORRECCIONES:
        # 1) Eliminado "cantidad_registros" (el modelo VersionConjuntoDatos no lo tiene).
        # 2) "algoritmo_hash" va ANTES que "hash_archivo" para que clean_hash_archivo()
        #    ya lo encuentre en cleaned_data.
        fields = [
            "version",
            "algoritmo_hash",
            "hash_archivo",
            "fecha_version",
            "metadatos",
        ]
        widgets = {
            "version": forms.TextInput(attrs={"class": "form-control", "placeholder": "v1.0.0"}),
            "algoritmo_hash": forms.TextInput(attrs={"class": "form-control"}),
            "hash_archivo": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "Hash SHA-256 del archivo de datos",
            }),
            "fecha_version": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
            "metadatos": forms.Textarea(attrs={
                "class": "form-control",
                "rows": 4,
                "placeholder": "JSON con metadatos estructurados",
            }),
        }

    def clean_hash_archivo(self):
        hash_val = self.cleaned_data.get("hash_archivo", "").strip()
        algoritmo = self.cleaned_data.get("algoritmo_hash", "SHA-256")

        if algoritmo == "SHA-256" and len(hash_val) != 64:
            raise forms.ValidationError(
                "El hash SHA-256 debe tener exactamente 64 caracteres hexadecimales."
            )
        return hash_val


class ModeloIAForm(forms.ModelForm):
    """Formulario para registrar el catálogo base de un modelo de IA."""
    class Meta:
        model = ModeloIA
        fields = [
            "nombre",
            "proveedor_framework",
            "proposito",
            "descripcion",
            "nivel_riesgo",
            "ficha_publica",
        ]
        widgets = {
            "nombre": forms.TextInput(attrs={"class": "form-control", "placeholder": "Ej. Clasificador de Documentos Legales"}),
            "proveedor_framework": forms.TextInput(attrs={"class": "form-control", "placeholder": "Ej. PyTorch / Hugging Face Transformers"}),
            "proposito": forms.Textarea(attrs={"class": "form-control", "rows": 3, "placeholder": "Describa el trámite o decisión automatizada..."}),
            "descripcion": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
            "nivel_riesgo": forms.Select(attrs={"class": "form-select"}),
            "ficha_publica": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }


class VersionModeloForm(forms.ModelForm):
    """Formulario para registrar una versión específica de un modelo."""
    class Meta:
        model = VersionModelo

        fields = [
            "version",
            "algoritmo_hash",
            "hash_artefacto",
            "estado",
            "nivel_riesgo",
            "conjuntos_datos",
            "metadatos",
        ]
        widgets = {
            "version": forms.TextInput(attrs={"class": "form-control", "placeholder": "1.0.0"}),
            "algoritmo_hash": forms.TextInput(attrs={"class": "form-control"}),
            "hash_artefacto": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "Hash SHA-256 del artefacto/binario del modelo",
            }),
            "estado": forms.Select(attrs={"class": "form-select"}),
            "nivel_riesgo": forms.Select(attrs={"class": "form-select"}),
            "conjuntos_datos": forms.CheckboxSelectMultiple(),
            "metadatos": forms.Textarea(attrs={
                "class": "form-control",
                "rows": 4,
                "placeholder": "Hiperparámetros, métricas de evaluación, etc. en formato JSON",
            }),
        }

    def clean_hash_artefacto(self):
        hash_val = self.cleaned_data.get("hash_artefacto", "").strip()
        algoritmo = self.cleaned_data.get("algoritmo_hash", "SHA-256")

        if algoritmo == "SHA-256" and len(hash_val) != 64:
            raise forms.ValidationError(
                "El hash SHA-256 del artefacto del modelo debe tener exactamente 64 caracteres."
            )
        return hash_val


class AuditoriaFilterForm(forms.Form):
    organizacion = forms.ModelChoiceField(
        queryset=Organizacion.objects.all(),
        required=False,
        widget=forms.Select(attrs={"class": "form-select"}),
    )
    modelo = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={"class": "form-control"}),
    )
    responsable = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={"class": "form-control"}),
    )
    version = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={"class": "form-control"}),
    )
    fecha_desde = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}),
    )
    fecha_hasta = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}),
    )
    tipo = forms.ChoiceField(
        required=False,
        choices=[("", "Todos")] + list(TipoEntradaLibroMayor.choices),
        widget=forms.Select(attrs={"class": "form-select"}),
    )


class TransicionEstadoForm(forms.ModelForm):
    """Formulario exclusivo para cambiar el estado de ciclo de vida de un modelo (RF-05)."""
    class Meta:
        model = TransicionEstado
        fields = ["estado_nuevo", "justificacion"]
        widgets = {
            "estado_nuevo": forms.Select(attrs={"class": "form-select"}),
            "justificacion": forms.Textarea(attrs={
                "class": "form-control",
                "rows": 3,
                "placeholder": "Justifique el cambio de estado (ej. aprobado en fase de pruebas)...",
            }),
        }

from django.contrib.auth.forms import AuthenticationForm


class LoginForm(AuthenticationForm):
    """AuthenticationForm con inputs estilizados (Tailwind)."""

    INPUT_CLASSES = (
        "block w-full rounded-lg border border-pergamino-300 bg-white "
        "px-3 py-2.5 text-sm text-marino placeholder:text-marino/40 shadow-sm "
        "transition-colors duration-150 "
        "invalid:border-pink-500 invalid:text-pink-600 "
        "focus:border-sky-500 focus:outline focus:outline-2 focus:outline-sky-500 "
        "focus:invalid:border-pink-500 focus:invalid:outline-pink-500 "
        "disabled:border-gray-200 disabled:bg-gray-50 disabled:text-gray-500 "
        "disabled:shadow-none dark:disabled:border-gray-700 dark:disabled:bg-gray-800/20"
    )

    ERROR_CLASSES = (
        "border-pink-500 text-pink-600 "
        "focus:border-pink-500 focus:outline-pink-500"
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs.update({
            "class": self.INPUT_CLASSES,
            "autocomplete": "username",
            "autofocus": True,
            "placeholder": "usuario o usuario institucional",
        })
        self.fields["password"].widget.attrs.update({
            "class": self.INPUT_CLASSES,
            "autocomplete": "current-password",
            "placeholder": "••••••••",
        })

    def apply_error_classes(self):
        if not self.errors:
            return
        for name in ("username", "password"):
            field = self.fields[name]
            classes = field.widget.attrs.get("class", "")
            if self.ERROR_CLASSES not in classes:
                field.widget.attrs["class"] = f"{classes} {self.ERROR_CLASSES}"


# ── Signup ──

_UPPER = RegexValidator(
    regex=r"[A-Z]",
    message="Debe incluir al menos una letra mayúscula.",
)
_LOWER = RegexValidator(
    regex=r"[a-z]",
    message="Debe incluir al menos una letra minúscula.",
)
_SPECIAL = RegexValidator(
    regex=r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]/\\;`~]',
    message="Debe incluir al menos un carácter especial (ej. ! @ # $  & *).",
)
_MIN5 = MinLengthValidator(
    5, message="La contraseña debe tener al menos 5 caracteres."
)


class SignupForm(UserCreationForm):
    """UserCreationForm con email, teléfono y alta/búsqueda de organización."""

    email = forms.EmailField(
        required=True,
        label="Correo electrónico",
    )
    telefono = forms.CharField(
        required=True,
        max_length=30,
        label="Teléfono",
    )
    organizacion_nombre = forms.CharField(
        required=True,
        max_length=20,
        label="Institución / Organización",
        help_text=(
            "Si la institución no existe, se creará automáticamente "
            "con el RIF y las siglas que indique abajo."
        ),
    )
    organizacion_rif = forms.CharField(
        required=True,
        max_length=20,
        label="RIF de la institución",
        help_text="Formato: J-12345678-9",
    )
    organizacion_siglas = forms.CharField(
        required=False,
        max_length=20,
        label="Siglas (opcional)",
        help_text="Ej. MPPRE",
    )

    field_order = [
        "username",
        "email",
        "telefono",
        "organizacion_nombre",
        "organizacion_rif",
        "organizacion_siglas",
        "password1",
        "password2",
    ]

    class Meta:
        model = Usuario
        fields = ("username",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for name, field in self.fields.items():
            field.widget.attrs["class"] = LoginForm.INPUT_CLASSES

        self.fields["username"].label = "Usuario"
        self.fields["password1"].label = "Contraseña"
        self.fields["password2"].label = "Confirmar contraseña"

        self.fields["username"].help_text = (
            "Requerido. Máx. 150 caracteres. Letras, dígitos y @/./+/-/_."
        )
        self.fields["password1"].help_text = (
            "Mín. 5 caracteres, con al menos una mayúscula, una minúscula "
            "y un carácter especial."
        )
        self.fields["password2"].help_text = "Repita la contraseña para verificar."

        self.fields["username"].widget.attrs.update({
            "autocomplete": "username",
            "autofocus": True,
            "placeholder": "usuario.institucional",
        })
        self.fields["email"].widget.attrs.update({
            "type": "email",
            "autocomplete": "email",
            "placeholder": "correo@gob.ve",
        })
        self.fields["telefono"].widget.attrs.update({
            "type": "tel",
            "autocomplete": "tel",
            "placeholder": "+58 412 1234567",
        })
        self.fields["organizacion_nombre"].widget.attrs.update({
            "list": "organizaciones-disponibles",
            "autocomplete": "off",
            "placeholder": "Ej. Ministerio del Poder Popular...",
        })
        self.fields["organizacion_rif"].widget.attrs.update({
            "placeholder": "J-12345678-9",
        })
        self.fields["organizacion_siglas"].widget.attrs.update({
            "placeholder": "MPPRE",
        })
        self.fields["password1"].widget.attrs.update({
            "autocomplete": "new-password",
            "placeholder": "Mín. 5, mayúscula, minúscula y símbolo",
        })
        self.fields["password2"].widget.attrs.update({
            "autocomplete": "new-password",
            "placeholder": "Repita la contraseña",
        })

        self.fields["password1"].validators.extend([
            _MIN5, _UPPER, _LOWER, _SPECIAL,
        ])

        from .models import Organizacion
        self.organizaciones_disponibles = (
            Organizacion.objects.filter(activo=True).order_by("nombre")
        )

    # ── Validaciones ──

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        from .models import Contacto
        if Contacto.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(
                "Este correo ya está registrado en el sistema."
            )
        return email

    def clean_telefono(self):
        telefono = self.cleaned_data["telefono"].strip()
        from .models import Contacto
        if Contacto.objects.filter(telefono=telefono).exists():
            raise forms.ValidationError(
                "Este teléfono ya está registrado en el sistema."
            )
        return telefono

    def clean(self):
        cleaned = super().clean()
        nombre = (cleaned.get("organizacion_nombre") or "").strip()
        rif = (cleaned.get("organizacion_rif") or "").strip().upper()

        if not nombre or not rif:
            return cleaned

        from .models import Organizacion

        # 1) ¿Existe ya por nombre?
        org = Organizacion.objects.filter(nombre__iexact=nombre).first()
        if org:
            if not org.activo:
                self.add_error(
                    "organizacion_nombre",
                    "Esta institución está inactiva. Contacte al administrador.",
                )
                return cleaned
            # Reutilizamos la existente (no exigimos que el RIF coincida)
            cleaned["organizacion"] = org
            return cleaned

        # 2) Si no existe por nombre, verificar que el RIF no esté tomado
        org_por_rif = Organizacion.objects.filter(rif__iexact=rif).first()
        if org_por_rif:
            self.add_error(
                "organizacion_rif",
                f"El RIF ya pertenece a otra institución: {org_por_rif.nombre}.",
            )
            return cleaned

        # 3) No hay conflicto: la vista creará la organización.
        cleaned["organizacion_rif"] = rif
        return cleaned
class AuditorForm(forms.Form):
    """Formulario del admin para crear auditores internos."""

    username = forms.CharField(max_length=150, label="Usuario")
    email = forms.EmailField(required=False, label="Correo electrónico")
    first_name = forms.CharField(max_length=150, required=False, label="Nombre")
    last_name = forms.CharField(max_length=150, required=False, label="Apellido")

    credencial = forms.CharField(max_length=100, label="Credencial")
    fecha_acreditacion = forms.DateField(
        widget=forms.DateInput(attrs={"type": "date"}),
        label="Fecha de acreditación",
    )
    fecha_expiracion = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={"type": "date"}),
        label="Fecha de expiración (opcional)",
    )

    alcance_global = forms.BooleanField(
        required=False,
        initial=True,
        label="Alcance global (todas las organizaciones)",
    )
    organizaciones_en_alcance = forms.ModelMultipleChoiceField(
        queryset=Organizacion.objects.filter(activo=True).order_by("nombre"),
        required=False,
        widget=forms.CheckboxSelectMultiple,
        label="Organizaciones en alcance (solo si no es global)",
    )

    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        label="Contraseña",
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        label="Confirmar contraseña",
    )
    activo = forms.BooleanField(required=False, initial=True, label="Activo")

    field_order = [
        "username", "email", "first_name", "last_name",
        "credencial", "fecha_acreditacion", "fecha_expiracion",
        "alcance_global", "organizaciones_en_alcance",
        "password1", "password2", "activo",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for name, field in self.fields.items():
            if isinstance(field.widget, (forms.CheckboxInput, forms.CheckboxSelectMultiple)):
                field.widget.attrs["class"] = "accent-marino"
            else:
                field.widget.attrs["class"] = LoginForm.INPUT_CLASSES

        self.fields["username"].widget.attrs.update({
            "placeholder": "auditor.apellido",
            "autocomplete": "off",
        })
        self.fields["email"].widget.attrs.update({
            "type": "email",
            "placeholder": "auditor@contraloria.gob.ve",
        })
        self.fields["credencial"].widget.attrs.update({
            "placeholder": "AUD-2026-001",
        })
        self.fields["password1"].widget.attrs.update({
            "placeholder": "Mín. 5, mayúscula, minúscula y símbolo",
        })
        self.fields["password2"].widget.attrs.update({
            "placeholder": "Repita la contraseña",
        })

        self.fields["password1"].validators.extend([
            _MIN5, _UPPER, _LOWER, _SPECIAL,
        ])

    def clean_username(self):
        username = self.cleaned_data["username"].strip()
        from .models import Auditor, Usuario
        if Auditor.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("Ya existe un auditor con ese usuario.")
        if Usuario.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError(
                "Ya existe un usuario institucional con ese nombre. Use otro."
            )
        return username

    def clean_credencial(self):
        credencial = self.cleaned_data["credencial"].strip()
        from .models import Auditor
        if Auditor.objects.filter(credencial__iexact=credencial).exists():
            raise forms.ValidationError("Esta credencial ya está en uso.")
        return credencial

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1")
        p2 = cleaned.get("password2")
        if p1 and p2 and p1 != p2:
            self.add_error("password2", "Las contraseñas no coinciden.")

        if not cleaned.get("alcance_global") and not cleaned.get("organizaciones_en_alcance"):
            self.add_error(
                "organizaciones_en_alcance",
                "Seleccione al menos una organización o marque «Alcance global».",
            )
        return cleaned