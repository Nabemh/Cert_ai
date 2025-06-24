from langchain.vectorstores import Chroma
from langchain.embeddings import OpenAIEmbeddings
from langchain.llms import OpenAI
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate

class RAGEngine:
    def __init__(self, vectorstore_path="vectorstore/"):
        self.embedding = OpenAIEmbeddings()
        self.vectorstore = Chroma(persist_directory=vectorstore_path, embedding_function=self.embedding)
        self.retriever = self.vectorstore.as_retriever()
        self.llm = OpenAI(temperature=0.3)

    def answer_query(self, query):
        qa_chain = RetrievalQA.from_chain_type(
            llm=self.llm,
            retriever=self.retriever,
            return_source_documents=True
        )
        result = qa_chain.run(query)
        return result

    def generate_report(self, insights: dict, advisories: list):
        # Retrieve format/style from the embedded PDF
        template_doc = self.vectorstore.similarity_search("incident report template")[0]
        formatting_guide = template_doc.page_content

        # Build structured prompt
        prompt = PromptTemplate(
            input_variables=["insights", "advisories", "formatting_guide"],
            template="""
Use the following example formatting guide:

{formatting_guide}

Now generate a full threat report using the following insights and advisories:

Insights:
{insights}

Advisories:
{advisories}

Return a structured professional report.
"""
        )

        final_prompt = prompt.format(
            formatting_guide=formatting_guide,
            insights=str(insights),
            advisories=str(advisories)
        )

        return self.llm.predict(final_prompt)
