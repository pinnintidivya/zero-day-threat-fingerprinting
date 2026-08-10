import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from sklearn.metrics import confusion_matrix, classification_report
from core import inject_base_css, load_artifacts, get_columns

st.set_page_config(page_title="Model Insights", page_icon="📊", layout="wide")
inject_base_css()

st.title("📊 Model Insights")
st.caption("A transparent look at how the models actually perform — not just a black box.")

train_df, clf, detector = load_artifacts()
numeric_cols, categorical_cols, feature_cols = get_columns()

# ---------------------------------------------------------
# Feature importance
# ---------------------------------------------------------
st.subheader("What drives the classifier's decisions")

model = clf.named_steps["model"]
prep = clf.named_steps["prep"]
feature_names = prep.get_feature_names_out()
importances = model.feature_importances_

imp_df = pd.DataFrame({"feature": feature_names, "importance": importances})
imp_df["feature"] = imp_df["feature"].str.replace("cat__", "", regex=False).str.replace("remainder__", "", regex=False)
imp_df = imp_df.sort_values("importance", ascending=False).head(15)

fig = px.bar(
    imp_df.sort_values("importance"), x="importance", y="feature", orientation="h",
    color="importance", color_continuous_scale="Tealgrn",
    title="Top 15 most influential features",
)
fig.update_layout(template="plotly_white", height=450, showlegend=False)
st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# ---------------------------------------------------------
# Live evaluation on labeled holdout set
# ---------------------------------------------------------
st.subheader("Live evaluation on a held-out labeled test set")
st.caption("Computed on demand from `data/eval_holdout.csv` — 1,267 rows the models never trained on.")

try:
    eval_df = pd.read_csv("data/eval_holdout.csv")
    X_eval = eval_df[feature_cols]
    y_true = eval_df["attack_category"]
    y_pred = clf.predict(X_eval)

    labels = sorted(y_true.unique())
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    col1, col2 = st.columns([1.2, 1])

    with col1:
        st.markdown("**Confusion matrix**")
        fig_cm = px.imshow(
            cm, x=labels, y=labels, text_auto=True, color_continuous_scale="Blues",
            labels=dict(x="Predicted", y="Actual", color="Count"),
        )
        fig_cm.update_layout(template="plotly_white", height=420)
        st.plotly_chart(fig_cm, use_container_width=True)

    with col2:
        st.markdown("**Per-class metrics**")
        report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
        report_df = pd.DataFrame(report).T.round(3)
        report_df = report_df.drop(index=[c for c in ["accuracy"] if c in report_df.index])
        st.dataframe(report_df, use_container_width=True)
        acc = report.get("accuracy", None)
        if acc is not None:
            st.metric("Overall accuracy", f"{acc:.1%}")

    st.markdown("---")
    st.subheader("Anomaly detector: flag rate by true category")
    st.caption("The Isolation Forest was trained only on normal traffic — this shows how often it correctly flags each attack type as anomalous, independent of the classifier.")
    eval_df["_anomaly"] = detector.predict(X_eval)
    flag_rate = eval_df.groupby("attack_category")["_anomaly"].apply(lambda s: (s == -1).mean()).sort_values(ascending=False)
    fig_flag = px.bar(
        flag_rate, orientation="h", color=flag_rate.values, color_continuous_scale="Oranges",
        labels={"value": "Anomaly flag rate", "attack_category": "True category"},
    )
    fig_flag.update_layout(template="plotly_white", height=350, showlegend=False)
    st.plotly_chart(fig_flag, use_container_width=True)

    st.info(
        "R2L and U2R are the hardest categories to classify confidently — this is a well-documented, "
        "intentional property of NSL-KDD (these attacks are rare in training and statistically resemble normal "
        "traffic). It's exactly the scenario the anomaly-detection + fingerprinting layer exists for: when the "
        "classifier can't confidently name an attack, the system still flags it as suspicious instead of missing it."
    )

except FileNotFoundError:
    st.warning("eval_holdout.csv not found — this page needs it to compute live metrics.")
