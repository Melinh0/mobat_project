"""
URL configuration for mobat_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from mobat_app import views as mobat_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', mobat_views.index, name='index'),
    path('visualizar_funcionalidades/', mobat_views.visualizar_funcionalidades, name='visualizar_funcionalidades'),
    path('graficos_comportamento/', mobat_views.graficos_comportamento, name='graficos_comportamento'),
    path('mapeamento_features/', mobat_views.mapeamento_features, name='mapeamento_features'),
    path('clusters/', mobat_views.clusters, name='clusters'),
    path('selecao_caracteristicas/', mobat_views.selecao_caracteristicas, name='selecao_caracteristicas'),
    path('importancias_ml/', mobat_views.importancias_ml, name='importancias_ml'),
    path('score_average_mobat/', mobat_views.score_average_mobat, name='score_average_mobat'),
    path('reputacao_pais/', mobat_views.reputacao_pais, name='reputacao_pais'),
    path('upload_tabela_ips/', mobat_views.upload_tabela_ips, name='upload_tabela_ips'),
    path('heatmap_ips/', mobat_views.heatmap_ips, name='heatmap_ips'),
    path('tabela_acuracia/', mobat_views.tabela_acuracia, name='tabela_acuracia'),
    path('grafico_dispersao/', mobat_views.grafico_dispersao, name='grafico_dispersao'),
]
