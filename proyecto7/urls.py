from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import path

from proyectouneti import views

urlpatterns = [
    path('admin/', admin.site.urls),

    # ── Autenticación ──
    path('login/', views.StyledLoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('signup/', views.signup_view, name='signup'),
    path('recuperar/', views.recuperar_view, name='recuperar'),

    # ── Dashboard ──
    path('', views.dashboard_view, name='dashboard'),

    # ── Modelos de IA ──
    path('modelos/registrar/', views.registrar_modelo_view, name='registrar_modelo'),
    path('modelos/<uuid:version_id>/cambiar-estado/', views.cambiar_estado_modelo_view, name='cambiar_estado_modelo'),
    path('modelos/<uuid:modelo_id>/nueva-version/', views.registrar_version_modelo_view, name='registrar_version_modelo'),

    # ── Conjuntos de datos ──
    path('datos/registrar/', views.registrar_conjunto_datos_view, name='registrar_conjunto_datos'),
    path('datos/<uuid:conjunto_id>/nueva-version/', views.registrar_version_conjunto_datos_view, name='registrar_version_conjunto_datos'),

    # ── Ledger / auditoría ──
    path('ledger/verificar/', views.verificar_cadena_view, name='verificar_cadena'),
    path('auditoria/', views.auditoria_view, name='auditoria'),
    path('auditoria/exportar/csv/', views.exportar_csv_view, name='exportar_csv'),
    path('auditoria/exportar/pdf/', views.exportar_pdf_view, name='exportar_pdf'),
]
