from django.shortcuts import render, redirect
from django.http import HttpResponse
import pandas as pd
from mobat_app.models import IPData
from mobat_app.utils.ml_helpers import plot_show_results_table

def tabela_acuracia(request):
    table_name = request.session.get('table_name')
    if not table_name:
        return redirect('index')

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'Gerar Tabela':
            qs = IPData.objects.filter(semester=table_name).values()
            df = pd.DataFrame.from_records(qs)

            allowed_columns = [
                'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
                'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
            ]

            results_df = plot_show_results_table(df, allowed_columns)
            results_html = results_df.to_html(classes="table table-striped table-bordered", index=False)
            request.session['results_html'] = results_html
            request.session['results_df'] = results_df.to_json()
            request.session['table_generated'] = True

            return render(request, 'tabela_acuracia.html', {
                'results_html': results_html,
                'table_generated': True
            })

        elif action == 'Baixar Tabela':
            results_df_json = request.session.get('results_df')
            if results_df_json:
                results_df = pd.read_json(results_df_json)
                response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                response['Content-Disposition'] = 'attachment; filename="tabela_acuracia.xlsx"'
                results_df.to_excel(response, index=False)
                return response

    return render(request, 'tabela_acuracia.html', {
        'results_html': request.session.get('results_html'),
        'table_generated': request.session.get('table_generated', False)
    })