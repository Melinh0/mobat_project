from django.shortcuts import render, redirect
from django.http import HttpResponse
import pandas as pd
import io
import base64
from mobat_app.models import IPData
from mobat_app.utils.ml_helpers import plot_feature_importance

def importancias_ml(request):
    table_name = request.session.get('table_name')
    if not table_name:
        return redirect('index')

    if request.method == 'POST':
        action = request.POST.get('action')
        model_type = request.POST.get('model_type')

        if not model_type:
            return HttpResponse("Selecione um modelo.", status=400)

        qs = IPData.objects.filter(semester=table_name).values()
        df = pd.DataFrame.from_records(qs)

        allowed_columns = [
            'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_total_reports',
            'abuseipdb_num_distinct_users', 'virustotal_reputation', 'harmless', 'malicious',
            'suspicious', 'undetected', 'IBM_score', 'IBM_average_history_Score',
            'IBM_most_common_score', 'score_average_Mobat'
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