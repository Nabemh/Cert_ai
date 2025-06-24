from langchain.document_loaders import PyPDFLoader
from langchain.vectorstores import Chroma
from langchain.embeddings import OpenAIEmbeddings
from langchain.text_splitter import CharacterTextSplitter

def embed_pdf_template(pdf_path="templates/JUNE 2024 NCC_CSIRT CYBERSECURITY REPORT_.docx", db_path="vectorstore/"):
    loader = PyPDFLoader(pdf_path)
    pages = loader.load()

    # Optional: small chunk since it's just a template
    splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    docs = splitter.split_documents(pages)

    vectorstore = Chroma.from_documents(docs, embedding=OpenAIEmbeddings(), persist_directory=db_path)
    vectorstore.persist()
    print("✅ Template embedded into vector store.")

if __name__ == "__main__":
    embed_pdf_template()
