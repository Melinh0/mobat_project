from django.shortcuts import render, redirect

def index(request):
    return render(request, 'index.html')

def visualizar_funcionalidades(request):
    return render(request, 'visualizar_funcionalidades.html')

def graficos_comportamento(request):
    print("Gráficos de Comportamento")
    # Aqui você pode adicionar o código específico para essa funcionalidade
    return render(request, 'graficos_comportamento.html')

def mapeamento_features(request):
    print("Mapeamento das features")
    # Código para esta funcionalidade
    return render(request, 'mapeamento_features.html')

def clusters(request):
    print("Clusters")
    # Código para esta funcionalidade
    return render(request, 'clusters.html')

def selecao_caracteristicas(request):
    print("Seleção de Características")
    # Código para esta funcionalidade
    return render(request, 'selecao_caracteristicas.html')

def importancias_ml(request):
    print("Importâncias para Machine Learning")
    # Código para esta funcionalidade
    return render(request, 'importancias_ml.html')

def score_average_mobat(request):
    print("Score Average Mobat dos IPs com maior variação")
    # Código para esta funcionalidade
    return render(request, 'score_average_mobat.html')

def reputacao_pais(request):
    print("Reputação por País")
    # Código para esta funcionalidade
    return render(request, 'reputacao_pais.html')

def upload_tabela_ips(request):
    print("Upload da Tabela dos Ips do período")
    # Código para esta funcionalidade
    return render(request, 'upload_tabela_ips.html')

def heatmap_ips(request):
    print("HeatMap de Ocorrência dos Ips nos países")
    # Código para esta funcionalidade
    return render(request, 'heatmap_ips.html')

def tabela_acuracia(request):
    print("Tabela de Acurácia e Tempo de Treinamento dos Modelos")
    # Código para esta funcionalidade
    return render(request, 'tabela_acuracia.html')

def grafico_dispersao(request):
    print("Gráfico de Dispersão")
    # Código para esta funcionalidade
    return render(request, 'grafico_dispersao.html')

