from django.shortcuts import render, redirect
from django.http import HttpResponse
import pandas as pd
import base64
from mobat_app.models import IPData
from mobat_app.utils.ml_helpers import plot_feature_selection

def selecao_caracteristicas(request):
    graphic = None
    table_name = request.session.get('table_name')
    if not table_name:
        return redirect('index')

    if request.method == 'POST':
        technique = request.POST.get('technique')
        action = request.POST.get('action')

        if technique == '' and action == 'Visualizar Seleção de Características':
            return HttpResponse("Por favor, selecione uma técnica válida.")

        qs = IPData.objects.filter(semester=table_name).values()
        df = pd.DataFrame.from_records(qs)

        allowed_columns = [
            'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_total_reports',
            'abuseipdb_num_distinct_users', 'virustotal_reputation', 'harmless', 'malicious',
            'suspicious', 'undetected', 'IBM_score', 'IBM_average_history_Score',
            'IBM_most_common_score', 'score_average_Mobat'
        ]

        if action == 'Visualizar Seleção de Características':
            graphic = plot_feature_selection(df, allowed_columns, technique)

        if isinstance(graphic, str) and graphic.startswith("Nenhum dado"):
            return HttpResponse(graphic)

        if graphic:
            request.session['graphic_base64'] = graphic

    if request.method == 'GET' and request.GET.get('download') == 'true':
        graphic_base64 = request.session.get('graphic_base64')
        if graphic_base64:
            img_data = base64.b64decode(graphic_base64)
            response = HttpResponse(img_data, content_type='image/png')
            response['Content-Disposition'] = 'attachment; filename="graphic.png"'
            return response

    return render(request, 'selecao_caracteristicas.html', {'graphic': request.session.get('graphic_base64')})