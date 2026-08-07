import streamlit as st
from core import inject_base_css

st.set_page_config(page_title="About this project", page_icon="ℹ️", layout="wide")
inject_base_css()

st.title("ℹ️ About this project")

st.subheader("Dataset")
st.markdown(
    """
    **NSL-KDD** — a widely used network intrusion detection benchmark that
    improves on the original KDD Cup 1999 dataset by removing redundant
    records. Training set: 125,973 labeled connections. Test set (used for
    the Model Insights page): 22,544 connections, including attack subtypes
    that were never seen during training — this is an intentional, documented
    property of NSL-KDD that makes it a genuinely hard benchmark, not an easy one.
    """
)

st.subheader("Architecture")
st.markdown(
    """
    | Component | What it is | Why it's there |
    |---|---|---|
    | Known-attack classifier | Random Forest (100 trees, balanced class weights) | High-precision recognition of attack families it has seen before |
    | Anomaly detector | Isolation Forest, trained only on normal traffic | Catches statistically unusual traffic independent of the classifier — this is what gives the system a chance against unseen attacks |
    | Fingerprinting layer | Centroid-distance comparison in scaled feature space | Turns "I don't recognize this" into "this looks like X" — an actionable hypothesis instead of a dead end |
    | MITRE ATT&CK mapping | Static lookup table | Translates ML output into language a security analyst already uses |
    """
)

st.subheader("Tech stack")
st.markdown(
    """
    - **scikit-learn** — Random Forest classifier, Isolation Forest anomaly detector
    - **pandas / numpy** — feature engineering and centroid math
    - **Streamlit** — multi-page interactive frontend
    - **Plotly** — live confusion matrix, feature importance, and anomaly-rate charts
    """
)

st.subheader("What makes this more than a classroom classifier")
st.markdown(
    """
    1. **It doesn't just classify — it reasons about uncertainty.** A single
       confidence threshold routes traffic between "confident known attack"
       and "investigate this anomaly," rather than forcing every row into
       one of five fixed buckets.
    2. **It attempts zero-day fingerprinting**, a genuinely non-trivial idea:
       using feature-space distance to hypothesize an attack family for
       traffic the classifier has never confidently seen.
    3. **It's transparent about its own limitations** — the Model Insights
       page shows real confusion matrices and per-class metrics computed
       live, including where the model struggles (R2L/U2R), instead of
       hiding weak spots behind a polished demo.
    4. **It speaks the analyst's language** via MITRE ATT&CK mapping, closing
       the gap between "the model said 0.87" and "here's what to do about it."
    """
)
