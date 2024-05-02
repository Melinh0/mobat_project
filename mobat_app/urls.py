from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('visualizar_funcionalidades/', views.visualizar_funcionalidades, name='visualizar_funcionalidades'),
    path('graficos_comportamento/', views.graficos_comportamento, name='graficos_comportamento'),
    path('mapeamento_features/', views.mapeamento_features, name='mapeamento_features'),
    path('clusters/', views.clusters, name='clusters'),
    path('selecao_caracteristicas/', views.selecao_caracteristicas, name='selecao_caracteristicas'),
    path('importancias_ml/', views.importancias_ml, name='importancias_ml'),
    path('score_average_mobat/', views.score_average_mobat, name='score_average_mobat'),
    path('reputacao_pais/', views.reputacao_pais, name='reputacao_pais'),
    path('upload_tabela_ips/', views.upload_tabela_ips, name='upload_tabela_ips'),
    path('heatmap_ips/', views.heatmap_ips, name='heatmap_ips'),
    path('tabela_acuracia/', views.tabela_acuracia, name='tabela_acuracia_modelos'),
    path('grafico_dispersao/', views.grafico_dispersao, name='grafico_dispersao'),
]
