from django.shortcuts import render, redirect
from django.http import HttpResponse
import pandas as pd
import matplotlib.pyplot as plt
import tempfile
import base64
import os
from mobat_app.models import IPData

def grafico_dispersao(request):
    allowed_columns = [
        'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_total_reports',
        'abuseipdb_num_distinct_users', 'virustotal_reputation', 'harmless', 'malicious',
        'suspicious', 'undetected', 'IBM_score', 'IBM_average_history_Score',
        'IBM_most_common_score', 'ALIENVAULT_reputation', 'score_average_Mobat'
    ]

    table_name = request.session.get('table_name')
    if not table_name:
        return redirect('index')

    if request.method == 'POST':
        x_axis = request.POST.get('x_axis')
        y_axis = request.POST.get('y_axis')

        if not x_axis or not y_axis:
            return render(request, 'grafico_dispersao.html', {'error': 'Por favor, selecione características para ambos os eixos.'})
        if x_axis not in allowed_columns or y_axis not in allowed_columns:
            return render(request, 'grafico_dispersao.html', {'error': 'As características selecionadas não são permitidas.'})

        qs = IPData.objects.filter(semester=table_name).values()
        df = pd.DataFrame.from_records(qs)

        x_data = df[x_axis]
        y_data = df[y_axis]
        y_value_counts = y_data.value_counts()
        y_weights = y_data.map(y_value_counts)

        plt.figure(figsize=(12, 7))
        plt.scatter(x_data, y_data, s=y_weights*10, color='blue', alpha=0.6)
        plt.title(f'Dispersão: {x_axis} vs {y_axis}')
        plt.xlabel(x_axis)
        plt.ylabel(y_axis)
        plt.grid(True)
        plt.subplots_adjust(top=0.92, bottom=0.08, left=0.1, right=0.95, hspace=0.2, wspace=0.2)

        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
            plt.savefig(tmp.name)
            tmp_path = tmp.name
        plt.close()

        with open(tmp_path, "rb") as f:
            data_uri = f"data:image/png;base64,{base64.b64encode(f.read()).decode()}"
        request.session['temp_file_path'] = tmp_path

        return render(request, 'grafico_dispersao.html', {'plot': data_uri})

    if 'download' in request.GET:
        tmp_path = request.session.get('temp_file_path', '')
        if tmp_path and os.path.exists(tmp_path):
            with open(tmp_path, "rb") as f:
                response = HttpResponse(f.read(), content_type='image/png')
                response['Content-Disposition'] = 'attachment; filename="grafico_dispersao.png"'
            os.remove(tmp_path)
            return response

    return render(request, 'grafico_dispersao.html')