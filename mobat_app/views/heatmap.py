from django.shortcuts import render, redirect
from django.http import HttpResponse
import sqlite3
import pandas as pd
import geopandas as gpd
import matplotlib.pyplot as plt
import tempfile
import base64
import os
from mobat_app.utils.data_helpers import alpha2_to_alpha3

def heatmap_ips(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'Gerar HeatMap':
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

            df_selected = df.dropna(subset=["abuseipdb_country_code"])
            serie_country_counts = df_selected["abuseipdb_country_code"].value_counts()
            min_count, max_count = serie_country_counts.min(), serie_country_counts.max()
            df_country_counts = serie_country_counts.rename_axis("country_code").reset_index(name="count")
            df_country_counts["country_code"] = df_country_counts["country_code"].apply(alpha2_to_alpha3)
            df_country_counts.dropna(subset=["country_code"], inplace=True)

            shapefile_path = "mobat_app/shapefiles/ne_10m_admin_0_countries.shp"
            geo_df = gpd.read_file(shapefile_path)[["ADMIN", "ADM0_A3", "geometry"]]
            geo_df.columns = ["country", "country_code", "geometry"]
            geo_df = geo_df.drop(geo_df.loc[geo_df["country"] == "Antarctica"].index)
            geo_df = geo_df.merge(df_country_counts, on="country_code", how="left")
            geo_df["count"] = geo_df["count"].fillna(0)
            geo_df["normalized_count"] = (geo_df["count"] - min_count) / (max_count - min_count) if max_count > min_count else 0

            fig, ax = plt.subplots(figsize=(20, 10))
            geo_df.plot(
                ax=ax, column="normalized_count", linewidth=0.5, cmap="Reds",
                legend=True, legend_kwds={"label": "Quantidade de Ocorrência Normalizada", "orientation": "horizontal"},
                edgecolor="gray"
            )
            plt.suptitle("Países com maior ocorrência de denúncias de IP", x=0.5, y=0.95, fontsize=20)
            plt.axis("off")
            plt.subplots_adjust(top=0.9, bottom=0.08, left=0.03, right=0.95, hspace=0.2, wspace=0.2)

            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                plt.savefig(tmp.name)
                tmp_path = tmp.name
            plt.close()

            with open(tmp_path, "rb") as f:
                data_uri = f"data:image/png;base64,{base64.b64encode(f.read()).decode()}"
            context = {'image_path': data_uri, 'temp_file_path': tmp_path}
            return render(request, 'heatmap_ips.html', context)

        elif action == 'Baixar HeatMap':
            temp_file_path = request.POST.get('temp_file_path', '')
            if temp_file_path and os.path.exists(temp_file_path):
                with open(temp_file_path, "rb") as f:
                    response = HttpResponse(f.read(), content_type='image/png')
                    response['Content-Disposition'] = 'attachment; filename="heatmap.png"'
                os.remove(temp_file_path)
                return response

    return render(request, 'heatmap_ips.html')