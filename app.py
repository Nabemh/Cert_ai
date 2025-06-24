import streamlit as st
import pandas as pd
from agents.analysis_agent import AnalysisAgent
from agents.advisory_agent import AdvisoryAgent
from agents.report_agent import ReportGenerator
from agents.rag_engine import RAGEngine

st.set_page_config(page_title="Cyber Threat Dashboard", layout="wide")
st.title("🛡️ Cyber Threat Intelligence Dashboard")

# Initialize session state
if "insights" not in st.session_state:
    st.session_state.insights = None
if "advisories" not in st.session_state:
    st.session_state.advisories = None

# === Upload CSV and Analyze ===
st.header("📁 Upload Threat Dataset")
uploaded_file = st.file_uploader("Upload a .csv threat dataset", type=["csv"])
if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.success("✅ Data loaded successfully.")

    agent = AnalysisAgent(df)
    insights = agent.run()
    st.session_state.insights = insights

    # Display charts
    st.subheader("📊 Threat Overview")
    st.image(insights["threat_categories"]["bar_chart"], caption="Top Threat Categories")
    st.image(insights["threat_categories"]["doughnut_chart"])

    st.image(insights["top_regions"]["bar_chart"], caption="Top 5 Regions")
    st.image(insights["top_malware"]["bar_chart"], caption="Top Malware")
    st.image(insights["top_c2_ips"]["doughnut_chart"], caption="Top 5 C2 IPs")

    st.subheader("🧾 Vulnerability Summary")
    st.write(insights["vulnerability_summary"])

# === Fetch Advisories ===
st.header("🌐 Live NCC-CSIRT Advisories")
if st.button("Fetch Latest Advisories"):
    advisory_agent = AdvisoryAgent()
    advisories = advisory_agent.run()
    st.session_state.advisories = advisories

    for adv in advisories:
        if adv["Alert"]:
            st.error(f"🚨 {adv['Date']} | {adv['Title']} — {adv['Impact']}")
        else:
            st.info(f"{adv['Date']} | {adv['Title']} — {adv['Impact']}")

# === Generate Full Report ===
st.header("📄 Generate PDF Report")
if st.button("Generate PDF"):
    if st.session_state.insights and st.session_state.advisories:
        gen = ReportGenerator()
        path = gen.run(st.session_state.insights, st.session_state.advisories)
        st.success(f"✅ Report generated at: {path}")
        with open(path, "rb") as f:
            st.download_button("Download Report", f, file_name="threat_report.pdf")
    else:
        st.warning("You need to run both analysis and advisories first.")

# === RAG: Ask a Question or Generate a Report ===
st.header("💬 Ask the RAG Agent")
query = st.text_input("Ask something like 'What malware was most common this week?'")

if st.button("Ask RAG"):
    if query:
        rag = RAGEngine()
        response = rag.answer_query(query)
        st.markdown("**🧠 Answer:**")
        st.write(response)
    else:
        st.warning("Enter a question first.")

st.subheader("🧠 Generate Text-Based Threat Report")
if st.button("Generate with RAG"):
    if st.session_state.insights and st.session_state.advisories:
        rag = RAGEngine()
        response = rag.generate_report(st.session_state.insights, st.session_state.advisories)
        st.text_area("📋 Generated Report", response, height=400)
    else:
        st.warning("Run insights and advisories first.")
