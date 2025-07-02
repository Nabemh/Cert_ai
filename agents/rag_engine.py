from langchain.vectorstores import Chroma
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate
import os
from dotenv import load_dotenv
import base64
from markupsafe import Markup
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

load_dotenv()


DEFAULT_TEMPLATE = """STANDARD INCIDENT REPORT TEMPLATE:

1. Executive Summary
   - Brief overview of incident
   - Impact assessment

2. Incident Details
   - Timeline
   - Affected systems

3. Analysis
   - Root cause
   - Vulnerabilities exploited

4. Recommendations
   - Immediate actions
   - Long-term fixes
   """


# REPORT_PROMPT_TEMPLATE = """
# You are a cybersecurity analyst assistant. Write a professional cyber threat intelligence report.

# Use the example report below to model your tone, structure, and language style.

# **Example Report Section (Style Guide):**
# {style_reference}

# **Instructions:**
# 1. Start with an executive summary
# 2. Include monitoring summaries, C2 IP analysis, malware, and affected regions in different bullet points under the heading Key Findings 
#     and the subheading Cyberspace Monitoring Activities
# 3. Use numeric insights

# **Data:**
# Insights:
# {insights}

# """

SECTION_PROMPTS = {
    "executive_summary": """You are a cyber threat analyst and this is an official introduction to this document, which highlights a few insights that were gotten from this month's report you do not need an official heading that says  'Executive Summary' that is already handled
                            Make it in one paragraph, """,


    "malware_summary": """Summarize the malware activity from the insights below. Mention top families, anomalies, and key numbers:\n\n{insights} keep this brief and concise this is only a summary of the malware activity""",

    "c2_summary": """Summarize the Command & Control (C&C) infrastructure trends and notable IPs based on this insight:\n\n{insights} keep this brief and concise this is only a summary of the C&C activity""",

    "geo_summary": """Analyze the geographic distribution of attacks. Focus on the most affected regions and anomalies:\n\n{insights} keep this brief and concise this is only a summary of the geographic activity""",

    "key_findings": """You are a cyber threat analyst. Write and Include monitoring summaries, C&C IP analysis, malware, and affected regions in a few different bullet points under the heading Key Findings 
    and the subheading Cyberspace Monitoring Activities: \n\nInsights:\n{insights}\n\nAdvisories:\n{advisories} """,

    "recommendations": """
                        You are a cyber threat analyst. Write recommendations based on the insights and advisories provided use bullet points. 
                        Focus on actionable steps to mitigate threats and improve security posture. Use the following insights: \n\nInsights:\n{insights}\n\nAdvisories:\n{advisories}""",

}



class RAGEngine:
    def __init__(self, vectorstore_path="vectorstore/"):
        if not os.path.exists(vectorstore_path):
            raise FileNotFoundError(f"Vectorstore directory not found: {vectorstore_path}")

        google_api_key = os.getenv("GOOGLE_API_KEY")
        if not google_api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment variables")

        # Initialize embeddings
        self.embedding = GoogleGenerativeAIEmbeddings(
            model="models/embedding-001",
            google_api_key=google_api_key
        )

        # Initialize Chroma vectorstore
        self.vectorstore = Chroma(
            persist_directory=vectorstore_path,
            embedding_function=self.embedding
        )
        self.retriever = self.vectorstore.as_retriever()

        # Initialize Gemini LLM
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash",
            temperature=0.3,
            google_api_key=google_api_key
        )

    def image_to_base64(self, image_path):
        """Convert image file to base64 encoded string"""
        try:
            return base64.b64encode(Path(image_path).read_bytes()).decode('utf-8')
        except Exception as e:
            print(f"Error loading image {image_path}: {e}")
            return ""

    def answer_query(self, query):
        qa_chain = RetrievalQA.from_chain_type(
            llm=self.llm,
            retriever=self.retriever,
            return_source_documents=True
        )
        result = qa_chain.run(query)
        return result

    # def generate_narrative(self, insights, advisories):
    #     """LLM generates narrative report using embedded PDF as style reference."""
    #     try:
    #         style_doc = self.vectorstore.similarity_search(
    #             "summary of threat activity",
    #             filter={"section": "Executive Summary"},
    #             k=1
    #         )
    #         style_reference = style_doc[0].page_content if style_doc else DEFAULT_TEMPLATEa
    #     except Exception as e:
    #         print(f"Style fallback: {e}")
    #         style_reference = DEFAULT_TEMPLATE

    #     prompt = PromptTemplate(
    #         input_variables=["style_reference", "insights", "advisories"],
    #         template=REPORT_PROMPT_TEMPLATE
    #     )
    #     final_prompt = prompt.format(
    #         style_reference=style_reference,
    #         insights=str(insights),
    #         advisories=str(advisories)
    #     )

    #     return self.llm.invoke(final_prompt).content


    def generate_smart_summary(self, insights: dict) -> str:
        summary_prompt = PromptTemplate.from_template("""
            You are a cybersecurity analyst. Summarize the following dataset into 3-5 bullet points of key intelligence findings.

            Be concise, use metrics (e.g. "92564 events", "26094 unique IPs"), and mention top threat categories, regions, malware, and any anomaly.

            Insights:
            {insights}
            """)

        prompt_text = summary_prompt.format(insights=str(insights))
        return self.llm.invoke(prompt_text).content
    
    def generate_section(self, section_key, insights, advisories=None):
        try:
            template_str = SECTION_PROMPTS[section_key]
            prompt = PromptTemplate(
                input_variables=["insights", "advisories"],
                template=template_str
            )
            filled_prompt = prompt.format(
                insights=str(insights),
                advisories=str(advisories) if advisories else ""
            )
            return self.llm.invoke(filled_prompt).content
        except Exception as e:
            print(f"[{section_key}] Error: {e}")
            return f"Could not generate {section_key}."


    # def generate_report(self, insights: dict, advisories: list, plot_dir="plots"):
    #     # 1. Get style for narrative
    #     narrative = self.generate_narrative(insights, advisories)

    #     # 2. Encode plots to base64
    #     images = {
    #         'threat_categories_bar': self.image_to_base64(f"{plot_dir}/threat_categories_bar.png"),
    #         'threat_categories_doughnut': self.image_to_base64(f"{plot_dir}/threat_categories_doughnut.png"),
    #         'regions': self.image_to_base64(f"{plot_dir}/regions.png"),
    #         'malware': self.image_to_base64(f"{plot_dir}/malware.png"),
    #         'c2_ips': self.image_to_base64(f"{plot_dir}/c2_ips.png")
    #     }

    #     # 3. Load Jinja2 template
    #     env = Environment(loader=FileSystemLoader("templates"))
    #     template = env.get_template("report_template.md")

    #     # 4. Render
    #     md_content = template.render(
    #     narrative=narrative,
    #     insights=insights,
    #     advisories=advisories,
    #     images=images
    # )
    #     return md_content, narrative

    def generate_report(self, insights: dict, advisories: list, plot_dir="plots"):
        # Base64 encode images
        images = {
            'threat_categories_bar': self.image_to_base64(f"{plot_dir}/threat_categories_bar.png"),
            'threat_categories_doughnut': self.image_to_base64(f"{plot_dir}/threat_categories_doughnut.png"),
            'regions': self.image_to_base64(f"{plot_dir}/regions.png"),
            'malware': self.image_to_base64(f"{plot_dir}/malware.png"),
            'c2_ips': self.image_to_base64(f"{plot_dir}/c2_ips.png")
        }

        # Modular LLM-generated sections
        context = {
            "executive_summary": self.generate_section("executive_summary", insights, advisories),
            "malware_summary": self.generate_section("malware_summary", insights),
            "c2_summary": self.generate_section("c2_summary", insights),
            "geo_summary": self.generate_section("geo_summary", insights),
            "key_findings": self.generate_section("key_findings", insights),
            "recommendations": self.generate_section("recommendations", insights, advisories),
            "insights": insights,
            "advisories": advisories,
            "images": images
        }

        # Load and render template
        env = Environment(loader=FileSystemLoader("templates"))
        template = env.get_template("report_template.md")
        return template.render(**context)
