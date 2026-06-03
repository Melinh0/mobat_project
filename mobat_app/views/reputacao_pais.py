from django.shortcuts import render, redirect
from django.http import HttpResponse
import sqlite3
import pandas as pd
import io
import base64
import os
from mobat_app.utils.plot_helpers import plot_country_score_average

def reputacao_pais(request):
    graphic = None
    if request.method == 'POST':
        country = request.POST.get('country')
        action = request.POST.get('action')
        if country == '' and action == 'Visualizar o País Escolhido':
            return HttpResponse("Por favor, selecione um país válido.")
        table_name = request.session.get('table_name')
        db_path = request.session.get('db_path')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
        conn.close()
        df = pd.DataFrame(data, columns=[
            'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
            'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
            'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
            'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
            'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn',
            'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
        ])
        if action == 'Visualizar o País Escolhido':
            graphic = plot_country_score_average(df, country)
        elif action == 'Visualizar Todos os Países':
            graphic = plot_country_score_average(df)
        if isinstance(graphic, str) and graphic.startswith("Nenhum dado"):
            return HttpResponse(graphic)
        request.session['graphic'] = graphic
    elif request.method == 'GET' and 'download' in request.GET:
        graphic = request.session.get('graphic')
        if graphic:
            with io.BytesIO(base64.b64decode(graphic)) as buffer:
                buffer.seek(0)
                temp_file_path = os.path.join(os.path.dirname(__file__), 'graphic.png')
                with open(temp_file_path, "wb") as f:
                    f.write(buffer.read())
            with open(temp_file_path, "rb") as f:
                response = HttpResponse(f.read(), content_type='image/png')
                response['Content-Disposition'] = 'attachment; filename="graphic.png"'
            os.remove(temp_file_path)
            return response
    return render(request, 'reputacao_pais.html', {'graphic': graphic})