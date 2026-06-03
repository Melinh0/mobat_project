from django.urls import path
from mobat_app.views import (
    index,
    visualizar_funcionalidades,
    graficos_comportamento,
    mapeamento_features,
    clusters,
    selecao_caracteristicas,
    importancias_ml,
    score_average_mobat,
    reputacao_pais,
    upload_tabela_ips,
    heatmap_ips,
    tabela_acuracia,
    grafico_dispersao,
)

urlpatterns = [
    path('', index, name='index'),
    path('visualizar_funcionalidades/', visualizar_funcionalidades, name='visualizar_funcionalidades'),
    path('graficos_comportamento/', graficos_comportamento, name='graficos_comportamento'),
    path('mapeamento_features/', mapeamento_features, name='mapeamento_features'),
    path('clusters/', clusters, name='clusters'),
    path('selecao_caracteristicas/', selecao_caracteristicas, name='selecao_caracteristicas'),
    path('importancias_ml/', importancias_ml, name='importancias_ml'),
    path('score_average_mobat/', score_average_mobat, name='score_average_mobat'),
    path('reputacao_pais/', reputacao_pais, name='reputacao_pais'),
    path('upload_tabela_ips/', upload_tabela_ips, name='upload_tabela_ips'),
    path('heatmap_ips/', heatmap_ips, name='heatmap_ips'),
    path('tabela_acuracia/', tabela_acuracia, name='tabela_acuracia_modelos'),
    path('grafico_dispersao/', grafico_dispersao, name='grafico_dispersao'),
]