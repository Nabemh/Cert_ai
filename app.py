import streamlit as st
import pandas as pd
from agents.analysis_agent import AnalysisAgent
from agents.advisory_agent import AdvisoryAgent
from agents.rag_engine import RAGEngine
import os
from agents.report_agent import ReportGenerator
from agents.query_agent import QueryAgent
import asyncio
from db.connect import load_threat_data


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
    "generated_report": None,
    "query_agent": None
}

for key, val in session_defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val

# === Upload and Analyze ===
st.header("🧠 Run Threat Analysis")
if st.button("Run Analysis"):
    with st.spinner("Loading data from PostgreSQL..."):
        try:
            df = load_threat_data()
            agent = AnalysisAgent(df)
            insights = agent.run()

            # Generate smart summary using RAG
            rag = RAGEngine()
            insights["smart_summary"] = rag.generate_smart_summary(insights)

            st.session_state.insights = insights
            st.session_state.query_agent = QueryAgent(insights_data=insights)

            st.success("Analysis complete!")

            # === Display Charts ===
            st.subheader("📊 Threat Overview")
            col1, col2 = st.columns(2)
            with col1:
                st.image(insights["threat_categories"]["bar_chart"], caption="Top Threat Categories")
            with col2:
                st.image(insights["threat_categories"]["doughnut_chart"])

            st.image(insights["top_regions"]["bar_chart"], caption="Top 5 Regions")
            st.image(insights["top_malware"]["bar_chart"], caption="Top Malware")
            st.image(insights["top_c&c_ips"]["doughnut_chart"], caption="Top 5 C2 IPs")

            st.subheader("🧾 Vulnerability Summary")
            st.write(insights["vulnerability_summary"])

        except Exception as e:
            st.error(f"Error: {str(e)}")
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

# === Threat Intelligence Chatbot ===
st.header("🤖 Threat Intelligence Chatbot")

query_input = st.text_input("Ask a question about the threat insights or IP addresses:")

if st.button("Get Response") and query_input:
    with st.spinner("Analyzing..."):
        # Initialize QueryAgent with current insights
        agent = QueryAgent(insights_data=st.session_state.insights or {})

        # Run the query
        response = asyncio.run(agent.process_query(query_input, query_type="auto"))

    st.subheader("🔎 Response")
    st.text_area("Bot Response", value=response, height=300)


# === Report Generation ===
st.header("📄 Generate Comprehensive Report")
if st.session_state.insights:
    tab1, tab2 = st.tabs(["📝 Text Report", "🖥️ Report Markdown"])

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
     if st.button("Generate Full Markdown Report"):
        rag = RAGEngine()
        markdown_content = rag.generate_report(
        st.session_state.insights,
        st.session_state.advisories or FAKE_ADVISORIES
        )


        st.download_button(
            "Download Markdown Report",
            markdown_content,
            file_name="threat_report.md"
        )

        st.markdown(markdown_content, unsafe_allow_html=False)
