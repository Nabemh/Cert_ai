import os
from dotenv import load_dotenv
import pandas as pd
from langchain_community.document_loaders import CSVLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from fpdf import FPDF

class ReportGenerator:

    def __init__(self, csv_path, embedding_model="text-embedding-3-small"):
        self.csv_path = csv_path
        self.embedding_model = OpenAIEmbeddings(model=embedding_model)
        self.vector_store = None
        self.llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0.3)

    def load_and_process(self):
        loader =CSVLoader(file_path=self.csv_path)
        documents = loader.load()

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200
        )
        splits = text_splitter.split_documents(documents)

        self.vector_store = Chroma.from_documents(
            documents=splits,
            embedding=self.embedding_model,
            persist_directory="./vector_store"
        )

        return "Data loaded and processed successfully."