import pandas as pd
import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.utils import resample
import joblib


DATASET_PATH = './datasets/CSE-CIC-IDS2018-Dataset/Processed_CSVs/'


SELECTED_CSV_FILES = [
    'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv',
]

COLUMNS_TO_DROP = [
    'Flow ID', 'Source IP', 'Destination IP', 'Timestamp',
    'Flow Pkts/s', 'Flow Byts/s',
    'Fwd Pkts/s', 'Bwd Pkts/s',
    'Subflow Fwd Byts', 'Subflow Bwd Byts',
    'Subflow Fwd Pkts', 'Subflow Bwd Pkts',
]

# --- Model Training Logic ---


def train_models():
    all_files_to_load = [os.path.join(
        DATASET_PATH, f) for f in SELECTED_CSV_FILES if os.path.exists(os.path.join(DATASET_PATH, f))]

    if not all_files_to_load:
        print(
            f"Error: No selected CSV files found in {DATASET_PATH}. Please check SELECTED_CSV_FILES list and path.")
        return

    print(
        f"[*] Found {len(all_files_to_load)} selected CSV files. Loading data...")
    list_df = []
    for f in all_files_to_load:
        try:
            df = pd.read_csv(f, low_memory=False, encoding='latin1')
            list_df.append(df)
        except Exception as e:
            print(f"[-] Error loading {f}: {e}")
            continue

    if not list_df:
        print("Error: No data loaded from CSVs. Exiting.")
        return

    df = pd.concat(list_df, ignore_index=True)
    print(f"[*] Total DataFrame shape after initial loading: {df.shape}")

    print("\n[*] Starting data preprocessing...")

    df.columns = df.columns.str.strip()

    df['Label'] = df['Label'].replace('Benign', 0)
    df.loc[df['Label'] != 0, 'Label'] = 1

    print(
        f"Label distribution after binary conversion:\n{df['Label'].value_counts()}")

    initial_cols = set(df.columns)
    df = df.drop(
        columns=[col for col in COLUMNS_TO_DROP if col in df.columns], errors='ignore')
    final_cols = set(df.columns)
    dropped_cols_actual = list(initial_cols - final_cols)
    if dropped_cols_actual:
        print(f"[*] Dropped columns: {dropped_cols_actual}")
    else:
        print("[*] No specified columns were dropped (perhaps they weren't present or were already handled).")

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    print(
        f"[*] Replaced Inf values with NaN. Total NaN after Inf replacement: {df.isnull().sum().sum()}")

    df.fillna(0, inplace=True)
    print(
        f"[*] Missing values filled with 0. Total NaN after fillna: {df.isnull().sum().sum()}")

    for col in df.columns.drop('Label'):
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df.fillna(0, inplace=True)
    print("[*] All feature columns ensured to be numeric.")

    df_majority = df[df.Label == 0]
    df_minority = df[df.Label == 1]

    if not df_minority.empty and len(df_majority) > len(df_minority) * 2:
        print(
            f"[*] Imbalanced data detected. Majority (Benign): {len(df_majority)}, Minority (Attack): {len(df_minority)}")
        df_majority_undersampled = resample(df_majority,
                                            replace=False,
                                            n_samples=len(df_minority),
                                            random_state=42)

        df_balanced = pd.concat([df_majority_undersampled, df_minority])
        print(
            f"[*] Dataset balanced using undersampling. New shape: {df_balanced.shape}")
        print(
            f"New label distribution:\n{df_balanced['Label'].value_counts()}")
        df = df_balanced
    else:
        print(
            "[*] Dataset imbalance not severe enough for undersampling or minority class is empty.")

    X = df.drop('Label', axis=1)
    y = df['Label']

    numeric_cols = X.select_dtypes(include=np.number).columns.tolist()
    X = X[numeric_cols]
    print(f"[*] Final feature set shape after preprocessing: {X.shape}")
    print(f"[*] Final label set shape: {y.shape}")

    # --- 3. Split Data into Training and Testing Sets ---
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y)
    print(f"[*] Data split: Train {X_train.shape}, Test {X_test.shape}")

    # --- 4. Model Training and Evaluation ---
    print("\n[*] Training Machine Learning Models...")

    print("\n--- Random Forest Classifier ---")
    rf_model = RandomForestClassifier(
        n_estimators=50, max_depth=15, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)
    y_pred_rf = rf_model.predict(X_test)

    print("Random Forest Accuracy:", accuracy_score(y_test, y_pred_rf))
    print("Random Forest Classification Report:\n",
          classification_report(y_test, y_pred_rf, zero_division=0))
    print("Random Forest Confusion Matrix:\n",
          confusion_matrix(y_test, y_pred_rf))

    print("\n--- Logistic Regression ---")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    lr_model = LogisticRegression(
        random_state=42, solver='liblinear', n_jobs=1)
    lr_model.fit(X_train_scaled, y_train)
    y_pred_lr = lr_model.predict(X_test_scaled)

    print("Logistic Regression Accuracy:", accuracy_score(y_test, y_pred_lr))
    print("Logistic Regression Classification Report:\n",
          classification_report(y_test, y_pred_lr, zero_division=0))
    print("Logistic Regression Confusion Matrix:\n",
          confusion_matrix(y_test, y_pred_lr))

    # --- 5. Save Trained Models and Scaler ---
    print("\n[*] Saving trained models and scaler...")
    MODEL_DIR = './trained_models'
    os.makedirs(MODEL_DIR, exist_ok=True)

    joblib.dump(rf_model, os.path.join(MODEL_DIR, 'random_forest_model.pkl'))
    joblib.dump(lr_model, os.path.join(
        MODEL_DIR, 'logistic_regression_model.pkl'))
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.pkl'))
    print(f"Models and scaler saved to {MODEL_DIR}/")


if __name__ == "__main__":
    train_models()
