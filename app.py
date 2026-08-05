import streamlit as st
import pandas as pd
import numpy as np
import joblib

# -----------------------------
# Page config
# -----------------------------
st.set_page_config(
    page_title="Zero-Day Threat Fingerprinting Console",
    page_icon="🛰️",
    layout="wide",
)

# -----------------------------
# Load artifacts (cached so it only runs once per session)
# -----------------------------
@st.cache_resource
def load_artifacts():
    train_df = pd.read_csv("train_clean.csv")
    clf = joblib.load("known_attack_classifier.pkl")
    detector = joblib.load("anomaly_detector.pkl")
    return train_df, clf, detector

train_df, clf, detector = load_artifacts()

DROP_COLS = ["label", "difficulty", "attack_category"]
categorical_cols = ["protocol_type", "service", "flag"]
numeric_cols = [c for c in train_df.columns if c not in DROP_COLS and c not in categorical_cols]
feature_cols = numeric_cols + categorical_cols

from sklearn.preprocessing import StandardScaler

@st.cache_resource
def build_scaler_and_centroids():
    scaler = StandardScaler().fit(train_df[numeric_cols])
    centroids = {}
    for cat in ["DoS", "Probe", "R2L", "U2R"]:
        rows = train_df[train_df["attack_category"] == cat][numeric_cols]
        centroids[cat] = scaler.transform(rows).mean(axis=0)
    return scaler, centroids

scaler, centroids = build_scaler_and_centroids()

MITRE = {
    "DoS": "Impact",
    "Probe": "Reconnaissance",
    "R2L": "Initial Access",
    "U2R": "Privilege Escalation",
}

# -----------------------------
# Sidebar — controls + explanation
# -----------------------------
st.sidebar.title("🛰️ Console Controls")
conf_threshold = st.sidebar.slider(
    "Known-attack confidence threshold",
    min_value=0.1, max_value=0.95, value=0.5, step=0.05,
    help="Rows below this confidence get sent to the anomaly detector instead of being called a known attack.",
)

st.sidebar.markdown("---")
st.sidebar.subheader("How this works")
st.sidebar.markdown(
    """
This tool triages network traffic in two stages:

1. **Supervised classifier** — trained on known attack categories
   (DoS, Probe, R2L, U2R). If it's confident, the row is labeled
   a **Known Attack**.
2. **Anomaly detector** (Isolation Forest) — catches traffic the
   classifier isn't confident about. If it looks anomalous but
   doesn't match a known pattern, it's flagged **Zero-Day Suspicious**,
   and we guess its closest attack *family* by comparing it to the
   centroid of each known category in feature space — a lightweight
   fingerprinting step, not a guess out of thin air.

Each verdict is mapped to a **MITRE ATT&CK tactic** for analyst context.
"""
)

# -----------------------------
# Core triage logic
# -----------------------------
def triage_row(row_df, threshold):
    proba = clf.predict_proba(row_df)[0]
    classes = clf.named_steps["model"].classes_
    top_idx = np.argmax(proba)
    pred_class, confidence = classes[top_idx], proba[top_idx]
    anomaly_flag = detector.predict(row_df)[0]

    if pred_class != "Normal" and confidence >= threshold:
        return {
            "verdict": "Known Attack",
            "category": pred_class,
            "confidence": round(float(confidence), 3),
            "mitre_tactic": MITRE.get(pred_class, "Unknown"),
            "fingerprint_guess": None,
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
        }
    else:
        return {
            "verdict": "Benign",
            "category": "Normal",
            "confidence": round(float(confidence), 3),
            "mitre_tactic": None,
            "fingerprint_guess": None,
        }

VERDICT_COLORS = {
    "Known Attack": "🔴",
    "Zero-Day Suspicious": "🟡",
    "Benign": "🟢",
}

# -----------------------------
# Main layout
# -----------------------------
st.title("🛰️ Zero-Day Threat Fingerprinting Console")
st.caption("Upload network traffic (CSV) to triage known attacks, benign traffic, and unseen zero-day patterns.")

uploaded_file = st.file_uploader("Upload traffic CSV", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)

    with st.spinner("Analyzing traffic..."):
        results = []
        for i in range(len(df)):
            row = df.iloc[[i]][feature_cols]
            r = triage_row(row, conf_threshold)
            r["row_index"] = i
            results.append(r)

    results_df = pd.DataFrame(results)

    # ---- Summary metrics ----
    n_rows = len(results_df)
    n_known = (results_df["verdict"] == "Known Attack").sum()
    n_zero = (results_df["verdict"] == "Zero-Day Suspicious").sum()
    n_benign = (results_df["verdict"] == "Benign").sum()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Rows analyzed", n_rows)
    c2.metric("Known Attacks", n_known)
    c3.metric("Zero-Day Suspicious", n_zero)
    c4.metric("Benign", n_benign)

    st.markdown("---")

    # ---- Charts ----
    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Verdict distribution")
        st.bar_chart(results_df["verdict"].value_counts())

    with col_b:
        st.subheader("Known-attack category breakdown")
        known_df = results_df[results_df["verdict"] == "Known Attack"]
        if len(known_df):
            st.bar_chart(known_df["category"].value_counts())
        else:
            st.info("No known attacks in this batch.")

    st.markdown("---")

    # ---- Alert cards ----
    st.subheader("Alert detail")
    for _, r in results_df.iterrows():
        icon = VERDICT_COLORS.get(r["verdict"], "⚪")
        with st.expander(f"{icon} Row #{r['row_index']} — {r['verdict']}"):
            st.write(f"**Confidence:** {r['confidence']}")
            if r["category"]:
                st.write(f"**Category:** {r['category']}")
            if r["mitre_tactic"]:
                st.write(f"**MITRE tactic:** {r['mitre_tactic']}")
            if r["fingerprint_guess"]:
                st.write(f"**Fingerprint guess:** resembles **{r['fingerprint_guess']}** family")
            st.dataframe(df.iloc[[r['row_index']]], use_container_width=True)

else:
    st.info("👆 Upload a CSV file to begin analysis. It should contain the same feature columns used during training (protocol_type, service, flag, and the numeric traffic features).")
