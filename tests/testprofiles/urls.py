from django.urls import include, path
from django.contrib import admin
from django.http import HttpResponse

testpatterns = (
    [
        path('dashboard/', lambda request: HttpResponse(''), name='dashboard')
    ],
    'testprofiles'  # app_name
)

urlpatterns = [
    path('saml2/', include('djangosaml2.urls')),
    path('admin/', admin.site.urls),
    path('', include(testpatterns))
]
