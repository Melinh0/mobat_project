from django.shortcuts import render, redirect
from django.http import HttpResponse
import sqlite3
import pandas as pd
import base64
from mobat_app.utils.ml_helpers import plot_feature_selection

def selecao_caracteristicas(request):
    graphic = None
    if request.method == 'POST':
        technique = request.POST.get('technique')
        action = request.POST.get('action')
        if technique == '' and action == 'Visualizar Seleção de Características':
            return HttpResponse("Por favor, selecione uma técnica válida.")

        table_name = request.session.get('table_name')
        db_path = request.session.get('db_path')
        if not table_name or not db_path:
            return redirect('index')

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        columns = [
            'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
            'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
            'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
            'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
            'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn',
            'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
        ]
        data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
        conn.close()
        df = pd.DataFrame(data, columns=columns)

        allowed_columns = [
            'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_total_reports',
            'abuseipdb_num_distinct_users', 'virustotal_reputation', 'harmless', 'malicious',
            'suspicious', 'undetected', 'IBM_score', 'IBM_average history Score',
            'IBM_most common score', 'score_average_Mobat'
        ]

        if action == 'Visualizar Seleção de Características':
            graphic = plot_feature_selection(df, allowed_columns, technique)
            if isinstance(graphic, str) and graphic.startswith("Nenhum dado"):
                return HttpResponse(graphic)
            request.session['graphic_base64'] = graphic

    if request.method == 'GET' and request.GET.get('download') == 'true':
        graphic_base64 = request.session.get('graphic_base64')
        if graphic_base64:
            img_data = base64.b64decode(graphic_base64)
            response = HttpResponse(img_data, content_type='image/png')
            response['Content-Disposition'] = 'attachment; filename="graphic.png"'
            return response

    return render(request, 'selecao_caracteristicas.html', {'graphic': request.session.get('graphic_base64')})