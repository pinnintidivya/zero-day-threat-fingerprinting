"""Shared model-loading and triage logic used across every page of the app."""
import streamlit as st
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler

MITRE = {
    "DoS": "Impact",
    "Probe": "Reconnaissance",
    "R2L": "Initial Access",
    "U2R": "Privilege Escalation",
}

VERDICT_COLORS = {
    "Known Attack": "#f85149",
    "Zero-Day Suspicious": "#d29922",
    "Benign": "#3fb950",
}

VERDICT_ICON = {
    "Known Attack": "🔴",
    "Zero-Day Suspicious": "🟡",
    "Benign": "🟢",
}


@st.cache_resource
def load_artifacts():
    train_df = pd.read_csv("data/train_clean_app.csv")
    clf = joblib.load("known_attack_classifier.pkl")
    detector = joblib.load("anomaly_detector.pkl")
    return train_df, clf, detector


@st.cache_resource
def build_scaler_and_centroids():
    train_df, _, _ = load_artifacts()
    numeric_cols, categorical_cols, feature_cols = get_columns()
    scaler = StandardScaler().fit(train_df[numeric_cols])
    centroids = {}
    for cat in ["DoS", "Probe", "R2L", "U2R"]:
        rows = train_df[train_df["attack_category"] == cat][numeric_cols]
        centroids[cat] = scaler.transform(rows).mean(axis=0)
    return scaler, centroids


@st.cache_data
def get_columns():
    train_df, _, _ = load_artifacts()
    DROP_COLS = ["label", "difficulty", "attack_category"]
    categorical_cols = ["protocol_type", "service", "flag"]
    numeric_cols = [c for c in train_df.columns if c not in DROP_COLS and c not in categorical_cols]
    feature_cols = numeric_cols + categorical_cols
    return numeric_cols, categorical_cols, feature_cols


def triage_row(row_df, threshold=0.5):
    _, clf, detector = load_artifacts()
    scaler, centroids = build_scaler_and_centroids()
    numeric_cols, categorical_cols, feature_cols = get_columns()

    proba = clf.predict_proba(row_df)[0]
    classes = clf.named_steps["model"].classes_
    top_idx = np.argmax(proba)
    pred_class, confidence = classes[top_idx], proba[top_idx]
    anomaly_flag = detector.predict(row_df)[0]
    anomaly_score = detector.named_steps["model"].decision_function(
        detector.named_steps["prep"].transform(row_df)
    )[0]

    if pred_class != "Normal" and confidence >= threshold:
        return {
            "verdict": "Known Attack",
            "category": pred_class,
            "confidence": round(float(confidence), 3),
            "mitre_tactic": MITRE.get(pred_class, "Unknown"),
            "fingerprint_guess": None,
            "anomaly_score": round(float(anomaly_score), 3),
        }
    elif anomaly_flag == -1:
        vec = scaler.transform(row_df[numeric_cols])[0]
        sims = {cat: -np.linalg.norm(vec - c) for cat, c in centroids.items()}
        ranked = sorted(sims.items(), key=lambda kv: -kv[1])
        best_cat = ranked[0][0]
        return {
            "verdict": "Zero-Day Suspicious",
            "category": None,
            "confidence": round(float(confidence), 3),
            "mitre_tactic": MITRE.get(best_cat, "Unknown") + " (hypothesized)",
            "fingerprint_guess": best_cat,
            "anomaly_score": round(float(anomaly_score), 3),
        }
    else:
        return {
            "verdict": "Benign",
            "category": "Normal",
            "confidence": round(float(confidence), 3),
            "mitre_tactic": None,
            "fingerprint_guess": None,
            "anomaly_score": round(float(anomaly_score), 3),
        }


def analyze_dataframe(df, threshold=0.5):
    _, _, feature_cols = get_columns()
    results = []
    for i in range(len(df)):
        row = df.iloc[[i]][feature_cols]
        r = triage_row(row, threshold)
        r["row_index"] = i
        results.append(r)
    return pd.DataFrame(results)


def inject_base_css():
    st.markdown(
        """
        <style>
        .metric-card {
            background: #f0f9ff;
            border: 1px solid #bae6fd;
            border-radius: 10px;
            padding: 16px 20px;
        }
        div[data-testid="stMetric"] {
            background: #f0f9ff;
            border: 1px solid #bae6fd;
            border-radius: 10px;
            padding: 10px 16px;
        }
        section[data-testid="stSidebar"] {
            background: #f0f9ff;
            border-right: 1px solid #bae6fd;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
