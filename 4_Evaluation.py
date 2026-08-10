import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from core import inject_base_css, load_artifacts, get_columns

st.set_page_config(page_title="Evaluation", page_icon="📈", layout="wide")
inject_base_css()

st.title("📈 Two-Layer vs. Single-Model Evaluation")
st.caption("Does adding the anomaly detector actually help catch attacks the classifier alone would miss? Measured directly, not asserted.")

train_df, clf, detector = load_artifacts()
numeric_cols, categorical_cols, feature_cols = get_columns()

try:
    eval_df = pd.read_csv("data/eval_holdout.csv").reset_index(drop=True)
    X_eval = eval_df[feature_cols]
    y_true = eval_df["attack_category"]

    # --- Layer 1 alone: what the classifier gets right by itself ---
    proba = clf.predict_proba(X_eval)
    classes = clf.named_steps["model"].classes_
    top_idx = np.argmax(proba, axis=1)
    y_pred = classes[top_idx]
    confidence = proba[np.arange(len(proba)), top_idx]
    clf_only_correct = (y_pred == y_true.values)

    # --- Full two-layer pipeline, computed in bulk (not row-by-row) ---
    anomaly_flags = detector.predict(X_eval)  # vectorized — fast even on 1000+ rows
    threshold = 0.5
    known_attack_mask = (y_pred != "Normal") & (confidence >= threshold)
    zero_day_mask = (~known_attack_mask) & (anomaly_flags == -1)
    flagged = known_attack_mask | zero_day_mask

    # Focus specifically on the hardest, rarest categories — this is the
    # "zero-day-like" test: attacks the classifier struggles with most
    hard_mask = y_true.isin(["R2L", "U2R"])

    clf_catch_rate_hard = clf_only_correct[hard_mask].mean()
    full_catch_rate_hard = flagged[hard_mask].mean()

    clf_catch_rate_all = clf_only_correct.mean()
    full_catch_rate_all = flagged[y_true != "Normal"].mean()

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Rare attacks (R2L / U2R) — hardest category")
        st.caption(f"{hard_mask.sum()} rows in this holdout")
        comp_df = pd.DataFrame({
            "Approach": ["Classifier alone\n(exact match)", "Full pipeline\n(flagged as non-benign)"],
            "Catch rate": [clf_catch_rate_hard, full_catch_rate_hard],
        })
        fig = px.bar(
            comp_df, x="Approach", y="Catch rate", color="Approach",
            color_discrete_sequence=["#94a3b8", "#0ea5e9"], text_auto=".0%",
        )
        fig.update_layout(template="plotly_white", showlegend=False, height=360, yaxis_tickformat=".0%")
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.subheader("All attack traffic")
        st.caption(f"{(y_true != 'Normal').sum()} attack rows in this holdout")
        comp_df2 = pd.DataFrame({
            "Approach": ["Classifier alone\n(exact match)", "Full pipeline\n(flagged as non-benign)"],
            "Catch rate": [clf_catch_rate_all, full_catch_rate_all],
        })
        fig2 = px.bar(
            comp_df2, x="Approach", y="Catch rate", color="Approach",
            color_discrete_sequence=["#94a3b8", "#22c55e"], text_auto=".0%",
        )
        fig2.update_layout(template="plotly_white", showlegend=False, height=360, yaxis_tickformat=".0%")
        st.plotly_chart(fig2, use_container_width=True)

    st.info(
        f"On this holdout, the classifier alone correctly names only **{clf_catch_rate_hard:.0%}** of "
        f"R2L/U2R attacks — but the full two-layer pipeline flags **{full_catch_rate_hard:.0%}** of them as "
        f"suspicious (Known Attack or Zero-Day Suspicious) rather than letting them pass as Benign. "
        f"This is the concrete, measured case for why anomaly detection is doing real work here, not just "
        f"sitting alongside the classifier for show."
    )

    st.markdown("---")

    # --- False positive check: how often is Normal traffic wrongly flagged? ---
    st.subheader("Cost check: false-positive rate on Normal traffic")
    normal_mask = y_true == "Normal"
    fp_rate = flagged[normal_mask].mean()
    st.metric("Normal traffic wrongly flagged as non-benign", f"{fp_rate:.1%}")
    st.caption(
        "Catching more attacks is only useful if it doesn't drown analysts in false alarms — "
        "this is that trade-off, measured on the same holdout set."
    )

except FileNotFoundError:
    st.warning("eval_holdout.csv not found — this page needs it to run the comparison.")

st.markdown("---")
st.subheader("Reference: architecture")
st.markdown(
    """
    | Component | What it is |
    |---|---|
    | Known-attack classifier | Random Forest (100 trees, balanced class weights) |
    | Anomaly detector | Isolation Forest, trained only on normal traffic |
    | Fingerprinting | Centroid-distance match in scaled feature space |
    | Stack | scikit-learn · pandas/numpy · Streamlit · Plotly |
    """
)
