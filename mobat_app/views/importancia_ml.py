from django.shortcuts import render, redirect
from django.http import HttpResponse
import sqlite3
import pandas as pd
import io
import base64
from mobat_app.utils.ml_helpers import plot_feature_importance

def importancias_ml(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        model_type = request.POST.get('model_type')
        table_name = request.session.get('table_name')
        db_path = request.session.get('db_path')
        if not db_path:
            return HttpResponse("Caminho do banco de dados não encontrado.", status=400)

        conn = sqlite3.connect(str(db_path))
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

        if action == 'Visualizar Gráfico de Importância':
            graphic = plot_feature_importance(df, allowed_columns, model_type)
            request.session['graphic'] = graphic
            return render(request, 'importancias_ml.html', {'graphic': graphic})
        elif action == 'Baixar Gráfico':
            graphic = request.session.get('graphic')
            if graphic:
                with io.BytesIO(base64.b64decode(graphic)) as buffer:
                    buffer.seek(0)
                    response = HttpResponse(buffer.read(), content_type='image/png')
                    response['Content-Disposition'] = 'attachment; filename="importancias_ml.png"'
                del request.session['graphic']
                return response

    return render(request, 'importancias_ml.html')