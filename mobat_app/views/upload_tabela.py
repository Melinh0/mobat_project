from django.shortcuts import render
from django.http import HttpResponse
import sqlite3
import pandas as pd
from django.conf import settings

def upload_tabela_ips(request):
    if request.method == 'POST':
        file_type = request.POST.get('file_type')
        table_name = request.session.get('table_name')
        db_path = settings.BASE_DIR / request.session.get('db_path')

        if not table_name or not db_path.exists():
            return HttpResponse("Tabela não encontrada", status=400)

        conn = sqlite3.connect(db_path)
        df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)
        conn.close()
        return download_all_ip_data(df, file_type)

    return render(request, 'upload_tabela_ips.html')

def clean_xml_tag(tag):
    tag = tag.replace(' ', '_')
    tag = ''.join(c for c in tag if c.isalnum() or c in ['_', '-'])
    return tag

def download_all_ip_data(df, file_type):
    df_filled = df.fillna('None')
    if file_type == 'excel':
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.xlsx'
        df_filled.to_excel(response, index=False)
    elif file_type == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.csv'
        df_filled.to_csv(response, index=False)
    elif file_type == 'parquet':
        response = HttpResponse(content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.parquet'
        df_filled.to_parquet(response, index=False)
    elif file_type == 'json':
        response = HttpResponse(content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.json'
        df_filled.to_json(response, orient='records')
    elif file_type == 'orc':
        response = HttpResponse(content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.orc'
        df_filled.to_orc(response, index=False)
    elif file_type == 'avro':
        response = HttpResponse(content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.avro'
        df_filled.to_avro(response, index=False)
    elif file_type == 'xml':
        response = HttpResponse(content_type='application/xml')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.xml'
        df_filled.columns = [clean_xml_tag(col) for col in df_filled.columns]
        xml_data = df_filled.to_xml(index=False)
        response.write(xml_data)
    else:
        return HttpResponse("Tipo de arquivo inválido")
    return response