import streamlit as st
from core import inject_base_css, load_artifacts

st.set_page_config(
    page_title="Zero-Day Threat Fingerprinting Platform",
    page_icon="🛰️",
    layout="wide",
)
inject_base_css()

# Warm up the cached models once so every page navigates instantly after this
load_artifacts()

st.title("🛰️ Zero-Day Threat Fingerprinting Platform")
st.caption("An AI-driven network intrusion triage system built on the NSL-KDD benchmark dataset.")

st.markdown("---")

col1, col2 = st.columns([1.3, 1])

with col1:
    st.subheader("The problem")
    st.markdown(
        """
        Traditional signature-based intrusion detection only catches attacks
        it has already seen before. Anything genuinely new — a **zero-day**
        attack pattern — slips through undetected until a human analyst
        manually investigates the anomaly, which can take hours or days.

        This platform closes that gap with a **two-model triage pipeline**:
        one model that recognizes known attack families with high confidence,
        and a second model that catches anything unusual *regardless* of
        whether it's ever been seen — then makes an educated guess about
        which attack family it most resembles.
        """
    )

    st.subheader("Why this approach is different")
    st.markdown(
        """
        Most classroom IDS projects stop at "classify traffic into attack
        categories." This platform goes a step further with **zero-day
        fingerprinting**: when the classifier isn't confident and the traffic
        looks statistically anomalous, the system compares it against the
        *centroid* of each known attack family in feature space and reports
        the closest match as a hypothesis — giving an analyst a starting
        point instead of a dead end.
        """
    )

with col2:
    st.subheader("Pipeline at a glance")
    st.markdown(
        """
        <div class="metric-card">

        **1. Ingest** — upload raw traffic (CSV, NSL-KDD feature schema)

        **2. Classify** — Random Forest scores it against 4 known attack
        families + Normal

        **3. Detect anomalies** — Isolation Forest (trained only on normal
        traffic) flags statistical outliers independently

        **4. Fingerprint** — low-confidence anomalies get matched to the
        nearest known attack family via centroid distance

        **5. Report** — verdict, confidence, MITRE ATT&CK tactic, and
        fingerprint hypothesis

        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("---")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Training records", "125,973", help="Full NSL-KDD KDDTrain+ set")
c2.metric("Attack families modeled", "4", help="DoS, Probe, R2L, U2R")
c3.metric("Detection layers", "2", help="Supervised classifier + unsupervised anomaly detector")
c4.metric("MITRE tactics mapped", "4")

st.markdown("---")
st.info(
    "👈 Use the sidebar to open the **Live Triage Console** to analyze traffic, "
    "**Model Insights** to see how the models actually perform, or **MITRE ATT&CK Mapping** "
    "and **About** for the technical writeup."
)
