import pandas as pd
import sqlite3

df = pd.read_csv('/home/yago/mobat_project/Total - Total.csv.csv')
conn = sqlite3.connect('/home/yago/mobat_project/mobat_app/Seasons/Total.sqlite')
df.to_sql('Total', conn, if_exists='replace', index=False)
conn.close()
