import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.metrics import accuracy_score
from core import inject_base_css, load_artifacts, get_columns

st.set_page_config(
    page_title="Zero-Day Threat Fingerprinting Platform",
    page_icon="🛰️",
    layout="wide",
)
inject_base_css()

train_df, clf, detector = load_artifacts()
numeric_cols, categorical_cols, feature_cols = get_columns()

st.markdown(
    """
    <div style="padding:28px 32px; border-radius:14px;
                background:linear-gradient(120deg,#e0f2fe,#f0fdfa);
                border:1px solid #bae6fd; margin-bottom:24px;">
        <h1 style="margin:0; color:#0c4a6e;">🛰️ Zero-Day Threat Fingerprinting Platform</h1>
        <p style="margin-top:8px; color:#334155; font-size:16px;">
            Live network intrusion triage — known-attack classification + anomaly-based
            zero-day detection, running on the NSL-KDD benchmark.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------
# Live-computed headline numbers (no hardcoded copy)
# ---------------------------------------------------------
try:
    eval_df = pd.read_csv("data/eval_holdout.csv")
    X_eval = eval_df[feature_cols]
    y_true = eval_df["attack_category"]
    y_pred = clf.predict(X_eval)
    live_acc = accuracy_score(y_true, y_pred)
except FileNotFoundError:
    live_acc = None

c1, c2, c3, c4 = st.columns(4)
c1.metric("Training records", f"{len(train_df):,}")
c2.metric("Attack families detected", "4", help="DoS, Probe, R2L, U2R")
if live_acc is not None:
    c3.metric("Live classifier accuracy", f"{live_acc:.1%}", help="Computed on demand from a labeled holdout set")
else:
    c3.metric("Detection layers", "2")
c4.metric("MITRE tactics mapped", "4")

st.markdown("---")

# ---------------------------------------------------------
# Real dataset composition, not a bullet list
# ---------------------------------------------------------
col1, col2 = st.columns([1.1, 1])

with col1:
    st.subheader("Traffic composition in the training data")
    dist = train_df["attack_category"].value_counts()
    fig = px.pie(
        values=dist.values, names=dist.index, hole=0.45,
        color=dist.index,
        color_discrete_map={"Normal": "#22c55e", "DoS": "#ef4444", "Probe": "#f59e0b", "R2L": "#0ea5e9", "U2R": "#a855f7"},
    )
    fig.update_layout(template="plotly_white", height=340, margin=dict(t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)
    st.caption("R2L and U2R are intentionally rare — this imbalance is why the anomaly detector matters, not a data quality issue.")

with col2:
    st.subheader("How a verdict gets decided")
    st.markdown(
        """
        <div style="background:#f0f9ff; border:1px solid #bae6fd; border-radius:10px; padding:18px 22px;">

        **1.** Random Forest scores traffic against 5 classes

        **2.** Confident known-attack prediction → **Known Attack**

        **3.** Not confident, but Isolation Forest flags it as an outlier → **Zero-Day Suspicious**, matched to the nearest known family by feature-space distance

        **4.** Otherwise → **Benign**

        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("")
    st.info("👈 Open **Live Triage Console** to run traffic through this pipeline, or **Model Insights** for the full live evaluation.")
