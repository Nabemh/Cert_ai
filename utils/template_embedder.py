from langchain_community.document_loaders import PyPDFLoader
from langchain_community.vectorstores import Chroma
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_core.documents import Document
from dotenv import load_dotenv
import os

load_dotenv()

def embed_pdf_sections(pdf_path="templates/JUNE 2024 NCC_CSIRT CYBERSECURITY REPORT_.pdf", db_path="vectorstore/"):
    loader = PyPDFLoader(pdf_path)
    pages = loader.load()
    full_text = "\n".join([page.page_content for page in pages])

    # Define known section headers and map them
    section_map = {
        "introduction": "Executive Summary",
        "key findings": "Key Findings",
        "cyberspace monitoring activities": "Monitoring Activities",
        "report summary of the cyberspace monitoring activities": "Monitoring Summary",
        "alerts & warning activities": "Alerts & Warnings",
        "conclusion": "Conclusion",
        "appendix": "Appendix"
    }

    # Split by section using simple keyword matching
    sections = {}
    current_section = "Unknown"

    for line in full_text.splitlines():
        line = line.strip()
        if not line:
            continue

        # Find if the line contains a known section header
        match = [label for keyword, label in section_map.items() if keyword in line.lower()]
        if match:
            current_section = match[0]
            sections[current_section] = ""
        elif current_section not in sections:
            sections[current_section] = line + "\n"
        else:
            sections[current_section] += line + "\n"

    documents = [
        Document(page_content=content.strip(), metadata={"section": section})
        for section, content in sections.items()
        if content.strip()
    ]

    google_api_key = os.getenv("GOOGLE_API_KEY")
    if not google_api_key:
        raise ValueError("GOOGLE_API_KEY not found in environment variables")

    # Embed documents into Chroma
    embeddings = GoogleGenerativeAIEmbeddings(
        model="models/embedding-001",
        google_api_key=google_api_key
    )

    vectorstore = Chroma.from_documents(
        documents=documents,
        embedding=embeddings,
        persist_directory=db_path
    )
    vectorstore.persist()
    print("✅ Section-based PDF embedded into vector store.")

if __name__ == "__main__":
    embed_pdf_sections()
