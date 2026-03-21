from django.contrib import admin
from django.urls import include, path


urlpatterns = [
    path("django-admin/", admin.site.urls),
    path("cms/", include("wagtail.admin.urls")),
    path("documents/", include("wagtail.documents.urls")),
    path("api/v1/scanner/", include("apps.scanner.api.urls")),
    path("api/v1/attack/", include("apps.attack.api.urls")),
    path("api/v1/ai/", include("apps.ai.api.urls")),
]
