import streamlit as st
import pandas as pd
import plotly.express as px
from core import inject_base_css, analyze_dataframe, VERDICT_COLORS, VERDICT_ICON

st.set_page_config(page_title="Live Triage Console", page_icon="🛡️", layout="wide")
inject_base_css()

st.title("🛡️ Live Triage Console")
st.caption("Upload network traffic and get an instant, explainable verdict per row.")

# ---------------------------------------------------------
# Sidebar controls
# ---------------------------------------------------------
st.sidebar.header("Controls")
conf_threshold = st.sidebar.slider(
    "Known-attack confidence threshold",
    min_value=0.1, max_value=0.95, value=0.5, step=0.05,
    help="Rows below this confidence get routed to the anomaly detector instead of being called a known attack outright.",
)

st.sidebar.markdown("---")
st.sidebar.subheader("Sample traffic files")
st.sidebar.caption("Five distinct samples pulled from the held-out NSL-KDD test set — pick the scenario you want to demo.")

SAMPLES = {
    "🟢 Normal traffic only": "data/demo_normal_traffic.csv",
    "🔴 DoS attack traffic": "data/demo_dos_attack.csv",
    "🔍 Probe / reconnaissance traffic": "data/demo_probe_attack.csv",
    "🟡 Rare R2L / U2R traffic": "data/demo_rare_r2l_u2r.csv",
    "🎲 Mixed traffic (all types)": "data/demo_mixed_traffic.csv",
}

for label, path in SAMPLES.items():
    try:
        with open(path, "rb") as f:
            st.sidebar.download_button(
                label, data=f, file_name=path.split("/")[-1],
                mime="text/csv", key=path, use_container_width=True,
            )
    except FileNotFoundError:
        pass

# ---------------------------------------------------------
# Main upload + analysis
# ---------------------------------------------------------
uploaded_file = st.file_uploader("Upload traffic CSV", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)

    with st.spinner("Analyzing traffic..."):
        results_df = analyze_dataframe(df, conf_threshold)

    n_rows = len(results_df)
    n_known = (results_df["verdict"] == "Known Attack").sum()
    n_zero = (results_df["verdict"] == "Zero-Day Suspicious").sum()
    n_benign = (results_df["verdict"] == "Benign").sum()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Rows analyzed", n_rows)
    c2.metric("🔴 Known Attacks", n_known)
    c3.metric("🟡 Zero-Day Suspicious", n_zero)
    c4.metric("🟢 Benign", n_benign)

    st.markdown("---")

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Verdict distribution")
        vc = results_df["verdict"].value_counts().reindex(list(VERDICT_COLORS.keys())).fillna(0).astype(int)
        fig_vc = px.bar(
            x=vc.index, y=vc.values,
            color=vc.index, color_discrete_map=VERDICT_COLORS,
            labels={"x": "", "y": "Rows"},
        )
        fig_vc.update_layout(template="plotly_white", showlegend=False, height=340, plot_bgcolor="#ffffff", paper_bgcolor="#ffffff")
        st.plotly_chart(fig_vc, use_container_width=True)
    with col_b:
        st.subheader("Known-attack category breakdown")
        known_df = results_df[results_df["verdict"] == "Known Attack"]
        if len(known_df):
            cat_counts = known_df["category"].value_counts()
            fig_cat = px.bar(
                x=cat_counts.index, y=cat_counts.values,
                color=cat_counts.index,
                color_discrete_sequence=px.colors.qualitative.Set2,
                labels={"x": "", "y": "Rows"},
            )
            fig_cat.update_layout(template="plotly_white", showlegend=False, height=340, plot_bgcolor="#ffffff", paper_bgcolor="#ffffff")
            st.plotly_chart(fig_cat, use_container_width=True)
        else:
            st.info("No known attacks in this batch.")

    st.subheader("Anomaly score distribution")
    st.caption("Lower (more negative) = more anomalous, as scored by the Isolation Forest.")
    fig_anom = px.bar(
        results_df, x="row_index", y="anomaly_score", color="verdict",
        color_discrete_map=VERDICT_COLORS,
        labels={"row_index": "Row #", "anomaly_score": "Anomaly score"},
    )
    fig_anom.update_layout(template="plotly_white", height=320, plot_bgcolor="#ffffff", paper_bgcolor="#ffffff", legend_title_text="")
    st.plotly_chart(fig_anom, use_container_width=True)

    st.markdown("---")
    st.subheader("Alert detail")

    filter_choice = st.multiselect(
        "Filter by verdict",
        options=list(VERDICT_COLORS.keys()),
        default=list(VERDICT_COLORS.keys()),
    )
    filtered = results_df[results_df["verdict"].isin(filter_choice)]

    for _, r in filtered.iterrows():
        icon = VERDICT_ICON.get(r["verdict"], "⚪")
        color = VERDICT_COLORS.get(r["verdict"], "#8b949e")
        with st.expander(f"{icon} Row #{r['row_index']} — {r['verdict']}"):
            st.markdown(
                f'<div style="border-left:4px solid {color}; padding-left:12px; margin-bottom:10px;">'
                f'<span style="color:{color}; font-weight:600;">{r["verdict"]}</span></div>',
                unsafe_allow_html=True,
            )
            cols = st.columns(3)
            cols[0].metric("Confidence", r["confidence"])
            cols[1].metric("Anomaly score", r["anomaly_score"])
            cols[2].metric("Category", r["category"] or "—")
            if r["mitre_tactic"]:
                st.write(f"**MITRE ATT&CK tactic:** {r['mitre_tactic']}")
            if r["fingerprint_guess"]:
                st.write(f"**Fingerprint guess:** resembles the **{r['fingerprint_guess']}** family")
            st.dataframe(df.iloc[[r["row_index"]]], use_container_width=True)

    st.markdown("---")
    csv_out = results_df.drop(columns=[]).to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Download full results as CSV", data=csv_out, file_name="triage_results.csv", mime="text/csv")

else:
    st.info("👆 Upload a CSV to begin, or grab one of the sample files from the sidebar for an instant demo.")
