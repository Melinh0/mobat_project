from django.shortcuts import render, redirect
from django.http import HttpResponse
import pandas as pd
import tempfile
import base64
import os
import matplotlib.pyplot as plt
from mobat_app.models import IPData

def mapeamento_features(request):
    table_name = request.session.get('table_name')
    if not table_name:
        return redirect('index')

    if request.method == 'POST':
        action = request.POST.get('action')
        feature = request.POST.get('feature')

        qs = IPData.objects.filter(semester=table_name).values()
        df = pd.DataFrame.from_records(qs)

        if action == 'Mapear Feature' and feature:
            value_counts = df[feature].value_counts().nlargest(5)
            plt.figure(figsize=(16, 8))
            bars = plt.bar([str(val) for val in value_counts.index], value_counts.values, color='skyblue')
            plt.ylabel('Quantidade')
            plt.title(f'Gráfico de Barras - {feature} (Top 5 Valores)')
            plt.xticks(rotation=45, ha='right')
            for bar, valor in zip(bars, value_counts.values):
                plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, str(valor), ha='center', va='bottom')
            plt.subplots_adjust(top=0.94, bottom=0.215, left=0.125, right=0.9, hspace=0.2, wspace=0.2)
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                plt.savefig(tmp.name)
                tmp_path = tmp.name
            plt.close()
            with open(tmp_path, "rb") as f:
                data_uri = f"data:image/png;base64,{base64.b64encode(f.read()).decode()}"
            os.remove(tmp_path)
            return render(request, 'mapeamento_features.html', {'plot': data_uri})

        elif action == 'Baixar Todas as Features Mapeadas':
            with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
                with pd.ExcelWriter(tmp.name, engine='xlsxwriter') as writer:
                    for col in df.columns:
                        count_df = df[col].value_counts().reset_index()
                        count_df.columns = [col, 'Quantidade']
                        count_df.to_excel(writer, sheet_name=col[:31], index=False)
                tmp.seek(0)
                response = HttpResponse(tmp.read(), content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                response['Content-Disposition'] = 'attachment; filename="features_mapeadas.xlsx"'
                return response

    return render(request, 'mapeamento_features.html')