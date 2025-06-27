import streamlit as st
import pandas as pd
from agents.analysis_agent import AnalysisAgent
from agents.advisory_agent import AdvisoryAgent
from agents.rag_engine import RAGEngine
import os
from agents.report_agent import ReportGenerator

FAKE_ADVISORIES = [
    {
        "AdvisoryID": "FAKE-001",
        "Title": "Simulated Zero-Day in Browser",
        "Threat Type": "Vulnerability",
        "Impact": "Critical — Allows RCE",
        "Date": "2025-06-24",
        "Alert": True
    },
    {
        "AdvisoryID": "FAKE-002",
        "Title": "Banking Trojan Campaign",
        "Threat Type": "Malware",
        "Impact": "High - Banking info theft",
        "Date": "2025-06-23",
        "Alert": True
    }
]
st.set_page_config(page_title="CSIRT Report Gen", layout="wide")
st.title("🛡️ CSIRT Reports")

# Initialize session state
session_defaults = {
    "insights": None,
    "advisories": None,
    "generated_report": None
}
for key, val in session_defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val

# === Upload and Analyze ===
st.header("📁 Upload Threat Dataset")
uploaded_file = st.file_uploader("Upload a .csv threat dataset", type=["csv"])
if uploaded_file:
    df = pd.read_csv(uploaded_file)
    agent = AnalysisAgent(df)
    insights = agent.run()

    # Generate smart summary using RAG
    rag = RAGEngine()
    insights["smart_summary"] = rag.generate_smart_summary(insights)

    st.session_state.insights = insights

    # Display charts - USING DICTIONARY ACCESS
    st.subheader("📊 Threat Overview")
    col1, col2 = st.columns(2)
    with col1:
        st.image(insights["threat_categories"]["bar_chart"], caption="Top Threat Categories")
    with col2:
        st.image(insights["threat_categories"]["doughnut_chart"])

    st.image(insights["top_regions"]["bar_chart"], caption="Top 5 Regions")
    st.image(insights["top_malware"]["bar_chart"], caption="Top Malware")
    st.image(insights["top_c2_ips"]["doughnut_chart"], caption="Top 5 C2 IPs")

    st.subheader("🧾 Vulnerability Summary")
    st.write(insights["vulnerability_summary"])
# === Advisories ===
st.header("🌐 Live NCC-CSIRT Advisories")
if st.button("Fetch Latest Advisories"):
    advisory_agent = AdvisoryAgent()
    st.session_state.advisories = advisory_agent.run() or FAKE_ADVISORIES

if st.session_state.advisories:
    for adv in st.session_state.advisories:
        st.container().write(f"""
            {"🚨" if adv["Alert"] else "ℹ️"} 
            **{adv['Title']}**  
            *{adv['Date']}* | Impact: {adv['Impact']}
        """)

# === Report Generation ===
st.header("📄 Generate Comprehensive Report")
if st.session_state.insights:
    tab1, tab2 = st.tabs(["📝 Text Report", "🖥️ HTML Report"])
    
    with tab1:
        if st.button("Generate Text Analysis"):
            rag = RAGEngine()
            st.session_state.generated_report = rag.generate_report(
                st.session_state.insights,
                st.session_state.advisories or FAKE_ADVISORIES
            )

        if st.session_state.generated_report:
            st.text_area("Analysis Report", 
                        st.session_state.generated_report,
                        height=400)
    
    with tab2:
        if st.button("Generate Full HTML Report"):
            rag = RAGEngine()
            html_content, narrative = rag.generate_report(
                st.session_state.insights,
                st.session_state.advisories or FAKE_ADVISORIES
            )

            from agents.report_agent import ReportGenerator
            report_gen = ReportGenerator()

            # Generate final HTML using Jinja2 + narrative
            html_path = report_gen.run(
                insights=st.session_state.insights,
                advisories=st.session_state.advisories or FAKE_ADVISORIES,
                narrative=narrative
            )

            with open(html_path, "r") as f:
                html_output = f.read()

            st.download_button(
                "Download Report",
                html_output,
                file_name="threat_report.html"
            )

            st.components.v1.html(html_output, height=800, scrolling=True)
