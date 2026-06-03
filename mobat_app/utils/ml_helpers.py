import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
import time
from sklearn.cluster import KMeans
from sklearn.feature_selection import VarianceThreshold, SelectKBest, f_classif, f_regression, mutual_info_regression
from sklearn.linear_model import Lasso, LinearRegression, ElasticNet
from sklearn.ensemble import GradientBoostingRegressor, RandomForestRegressor, ExtraTreesRegressor, AdaBoostRegressor
from sklearn.neighbors import KNeighborsRegressor
from sklearn.metrics import mean_squared_error
from sklearn.model_selection import train_test_split
from xgboost import XGBRegressor

def categorize_non_numeric_columns(df):
    df = df.copy()
    for col in df.select_dtypes(include=['object', 'category']).columns:
        if col != 'IP':
            df[col] = df[col].astype('category').cat.codes
    return df

def handle_missing_values(X):
    return X.fillna(0)

def plot_clusters(df, selected_feature, num_clusters):
    X = df[[selected_feature]]
    kmeans = KMeans(n_clusters=num_clusters, random_state=0, n_init=10).fit(X)
    df['cluster'] = kmeans.labels_
    mean_feature_all = df[selected_feature].mean()
    plt.figure(figsize=(16, 8))
    labels = []
    for cluster in df['cluster'].unique():
        cluster_data = df[df['cluster'] == cluster]
        plt.scatter(cluster_data.index, cluster_data[selected_feature], label=f'Cluster {cluster}')
        unique_ips = cluster_data['IP'].nunique()
        labels.append(f'Cluster {cluster} [Num. of Unique IPs: {unique_ips}]')
    labels.append(f'Mean {selected_feature} All: {mean_feature_all:.2f}')
    plt.axhline(y=mean_feature_all, color='r', linestyle='--', label=f'Mean {selected_feature} All: {mean_feature_all:.2f}')
    plt.title(f'Clusters da coluna "{selected_feature}"')
    plt.ylabel(selected_feature)
    plt.legend(labels=labels)
    plt.grid(True)
    plt.tight_layout()
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    graphic = base64.b64encode(buffer.getvalue()).decode('utf-8')
    plt.close()
    return graphic

def plot_feature_selection(df, allowed_columns, technique):
    df_filtered = categorize_non_numeric_columns(df[allowed_columns])

    def plot_bar(data, title, xlabels=None):
        if isinstance(data, np.ndarray):
            data = pd.Series(data, index=xlabels)
        plt.figure(figsize=(12, 6))
        plt.bar(data.index, data)
        plt.title(title)
        plt.ylabel('Score')
        plt.xticks(rotation=45, ha='right')
        for i, v in enumerate(data):
            plt.text(i, v + 0.01, f'{v:.2f}', ha='center', va='bottom', fontsize=8)
        plt.subplots_adjust(top=0.945, bottom=0.315, left=0.15, right=0.9, hspace=0.2, wspace=0.2)

    if technique == 'variance_threshold':
        selector = VarianceThreshold()
        selector.fit(df_filtered)
        variances = pd.Series(selector.variances_, index=df_filtered.columns)
        plot_bar(variances, 'Variância das Features')
    elif technique == 'select_kbest':
        selector = SelectKBest(score_func=f_classif, k=5)
        selector.fit(df_filtered.drop('score_average_Mobat', axis=1), df_filtered['score_average_Mobat'])
        kbest_features = df_filtered.drop('score_average_Mobat', axis=1).columns[selector.get_support()]
        plot_bar(selector.scores_[selector.get_support()], 'SelectKBest - Top 5 Features', list(kbest_features))
    elif technique == 'lasso':
        lasso = Lasso(alpha=0.1)
        lasso.fit(df_filtered.drop('score_average_Mobat', axis=1), df_filtered['score_average_Mobat'])
        lasso_coef = np.abs(lasso.coef_)
        plot_bar(lasso_coef, 'Lasso Coefficients', list(df_filtered.drop('score_average_Mobat', axis=1).columns))
    elif technique == 'mutual_info':
        mutual_info_vals = mutual_info_regression(df_filtered.drop('score_average_Mobat', axis=1), df_filtered['score_average_Mobat'])
        plot_bar(mutual_info_vals, 'Mutual Information', list(df_filtered.drop('score_average_Mobat', axis=1).columns))
    elif technique == 'correlation_matrix':
        plt.figure(figsize=(20, 10))
        sns.heatmap(df_filtered.corr(), annot=False, cmap='coolwarm')
        plt.title('Matriz de Correlação')
        plt.subplots_adjust(top=0.945, bottom=0.5, left=0.125, right=0.9, hspace=0.2, wspace=0.2)
    else:
        raise ValueError("Invalid technique")

    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    plt.close()
    buffer.seek(0)
    graphic = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return graphic

def plot_feature_importance(df, allowed_columns, model_type):
    df_filtered = categorize_non_numeric_columns(df[allowed_columns])
    models = {
        'GradientBoostingRegressor': GradientBoostingRegressor(),
        'RandomForestRegressor': RandomForestRegressor(),
        'ExtraTreesRegressor': ExtraTreesRegressor(),
        'AdaBoostRegressor': AdaBoostRegressor(),
        'XGBRegressor': XGBRegressor(),
        'ElasticNet': ElasticNet()
    }
    model = models.get(model_type)
    if not model:
        raise ValueError("Model type not supported.")
    model.fit(df_filtered.drop('score_average_Mobat', axis=1), df_filtered['score_average_Mobat'])
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
    elif hasattr(model, 'coef_'):
        importances = np.abs(model.coef_)
    else:
        raise ValueError("Model does not have 'feature_importances_' or 'coef_'.")
    ordered_importances = [importances[i] for i, col in enumerate(allowed_columns) if col != 'score_average_Mobat']
    feature_names = [col for col in allowed_columns if col != 'score_average_Mobat']
    plt.figure(figsize=(16, 8))
    plt.bar(feature_names, ordered_importances)
    plt.xlabel('Características')
    plt.ylabel('Importância')
    plt.title(f'Importância das características no modelo {model_type} para score_average_Mobat')
    plt.xticks(rotation=45, ha='right')
    for feature, importance in zip(feature_names, ordered_importances):
        plt.text(feature, importance + 0.005, f'{importance:.2f}', ha='center', va='bottom', rotation=45, fontsize=8)
    plt.tight_layout()
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    plt.close()
    buffer.seek(0)
    graphic = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return graphic

def plot_show_results_table(df, allowed_columns):
    df = categorize_non_numeric_columns(df)
    X = df[allowed_columns]
    y = df['score_average_Mobat']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    X_train = handle_missing_values(X_train)
    X_test = handle_missing_values(X_test)

    vt = VarianceThreshold()
    start_vt = time.time()
    X_train_vt = vt.fit_transform(X_train)
    X_test_vt = vt.transform(X_test)
    end_vt = time.time()

    skb = SelectKBest(score_func=f_regression, k=5)
    start_skb = time.time()
    X_train_skb = skb.fit_transform(X_train, y_train)
    X_test_skb = skb.transform(X_test)
    end_skb = time.time()

    mrmr_5 = SelectKBest(score_func=mutual_info_regression, k=5)
    start_mrmr5 = time.time()
    X_train_mrmr5 = mrmr_5.fit_transform(X_train, y_train)
    X_test_mrmr5 = mrmr_5.transform(X_test)
    end_mrmr5 = time.time()

    mrmr_7 = SelectKBest(score_func=mutual_info_regression, k=7)
    start_mrmr7 = time.time()
    X_train_mrmr7 = mrmr_7.fit_transform(X_train, y_train)
    X_test_mrmr7 = mrmr_7.transform(X_test)
    end_mrmr7 = time.time()

    lasso = Lasso()
    start_lasso = time.time()
    lasso.fit(X_train, y_train)
    selected_lasso = X.columns[lasso.coef_ != 0]
    X_train_lasso = X_train[selected_lasso]
    X_test_lasso = X_test[selected_lasso]
    end_lasso = time.time()

    lr = LinearRegression()
    start_lr = time.time()
    lr.fit(X_train, y_train)
    selected_lr = X.columns[lr.coef_ != 0]
    X_train_lr = X_train[selected_lr]
    X_test_lr = X_test[selected_lr]
    end_lr = time.time()

    models = [
        ('GradientBoostingRegressor', GradientBoostingRegressor()),
        ('RandomForestRegressor', RandomForestRegressor()),
        ('ExtraTreesRegressor', ExtraTreesRegressor()),
        ('KNeighborsRegressor', KNeighborsRegressor()),
    ]
    results = []
    for name, model in models:
        start = time.time()
        model.fit(X_train, y_train)
        end = time.time()
        y_pred = model.predict(X_test)
        mse = mean_squared_error(y_test, y_pred)
        results.append({'Model': name, 'Selection Technique': 'None', 'MSE': mse, 'Training Time': end - start})

    for name, model in models:
        for X_train_sel, X_test_sel, sel_name, start_time, end_time in [
            (X_train_vt, X_test_vt, 'VarianceThreshold', start_vt, end_vt),
            (X_train_skb, X_test_skb, 'SelectKBest', start_skb, end_skb),
            (X_train_mrmr5, X_test_mrmr5, 'MRMR-5', start_mrmr5, end_mrmr5),
            (X_train_mrmr7, X_test_mrmr7, 'MRMR-7', start_mrmr7, end_mrmr7),
            (X_train_lasso, X_test_lasso, 'Lasso', start_lasso, end_lasso),
            (X_train_lr, X_test_lr, 'LinearRegression', start_lr, end_lr)
        ]:
            start = time.time()
            model.fit(X_train_sel, y_train)
            end = time.time()
            y_pred = model.predict(X_test_sel)
            mse = mean_squared_error(y_test, y_pred)
            results.append({'Model': name, 'Selection Technique': sel_name, 'MSE': mse, 'Training Time': end - start})

    results_df = pd.DataFrame(results)
    return results_df