from langchain.document_loaders import PyPDFLoader
from langchain.vectorstores import Chroma
from langchain.embeddings import GoogleGenerativeAIEmbeddings
from langchain.schema import Document
from dotenv import load_dotenv
import os

load_dotenv()

def embed_pdf_sections(pdf_path="templates/JUNE 2024 NCC_CSIRT CYBERSECURITY REPORT_.pdf", db_path="vectorstore/"):
    # Load and concatenate full PDF text
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

        match = [label for keyword, label in section_map.items() if keyword in line.lower()]
        if match:
            current_section = match[0]
            sections[current_section] = ""
        elif current_section not in sections:
            sections[current_section] = line + "\n"
        else:
            sections[current_section] += line + "\n"

    # Prepare documents with metadata
    documents = [
        Document(page_content=content.strip(), metadata={"section": section})
        for section, content in sections.items()
        if content.strip()
    ]

    # Embed the documents into Chroma
    vectorstore = Chroma.from_documents(
        documents,
        embedding=GoogleGenerativeAIEmbeddings(model="models/embedding-001"),
        persist_directory=db_path
    )

    vectorstore.persist()
    print("✅ Section-based PDF embedded into vector store.")

if __name__ == "__main__":
    embed_pdf_sections()
