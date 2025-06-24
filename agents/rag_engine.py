from langchain.vectorstores import Chroma
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate
import os
from dotenv import load_dotenv
import base64
from pathlib import Path

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


REPORT_PROMPT_TEMPLATE = """
**Task:** Generate a comprehensive threat intelligence report using the provided data and visualizations.

**Formatting Guide:**
{formatting_guide}

**Data Overview:**
- Threat categories (already visualized)
- Top geographical regions (already visualized)
- Prevalent malware types (already visualized)
- Command & Control infrastructure (already visualized)

**Specific Instructions:**
1. Begin with an executive summary highlighting key findings
2. Analyze each threat category with context from the visualizations
3. Explain geographical distribution patterns
4. Detail malware trends and their implications
5. Assess C2 infrastructure significance
6. Include actionable recommendations
7. Maintain professional, technical tone suitable for security analysts

**Raw Data:**
{insights}

**Advisories:**
{advisories}

**Note:** The charts are already embedded in the report. Reference them naturally in your analysis.
"""

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

    def generate_report(self, insights: dict, advisories: list, plot_dir="plots"):
    # Safely get template
        try:
            results = self.vectorstore.similarity_search("incident report template", k=1)
            formatting_guide = results[0].page_content if results else DEFAULT_TEMPLATE
        except Exception as e:
            print(f"Template loading error: {e}")
            formatting_guide = DEFAULT_TEMPLATE

        # Convert all images to base64
        image_data = {
            'threat_categories_bar': self.image_to_base64(f"{plot_dir}/top_threat_categories_bar.png"),
            'threat_categories_doughnut': self.image_to_base64(f"{plot_dir}/top_threat_categories_doughnut.png"),
            'regions': self.image_to_base64(f"{plot_dir}/top_regions.png"),
            'malware': self.image_to_base64(f"{plot_dir}/top_malware.png"),
            'c2_ips': self.image_to_base64(f"{plot_dir}/top_C2_ips.png")
        }

        # Generate HTML with proper dictionary access
        html_report = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Threat Intelligence Report</title>
        <style>
            /* Your existing styles */
        </style>
    </head>
    <body>
        <h1>Threat Intelligence Report</h1>
        
        <h2>🔎 Threat Categories (Top 3)</h2>
        <div class="image-row">
            <img src="data:image/png;base64,{image_data['threat_categories_bar']}" 
                alt="Threat Categories Bar Chart">
            <img src="data:image/png;base64,{image_data['threat_categories_doughnut']}" 
                alt="Threat Categories Doughnut Chart">
        </div>
        
        <table>
            <tr><th>Category</th><th>Frequency</th><th>Unique IPs</th></tr>
            {"".join(
                f"<tr><td>{row['Category']}</td><td>{row['Count of TID']}</td><td>{row['Count of IP']}</td></tr>"
                for row in insights["threat_categories"]["summary_table"]  # Fixed dictionary access
            )}
        </table>
        
        <!-- Repeat for other sections with similar fixes -->
    </body>
    </html>
        """
        return html_report