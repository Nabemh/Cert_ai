import requests
import json
import os
import logging
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from typing import Dict, Any, Optional
import ipaddress
from datetime import datetime
import asyncio
import aiohttp
import ssl
import certifi

load_dotenv()
logging.basicConfig(level=logging.INFO)

class QueryAgent:
    def __init__(self, insights_data: Dict = None):
        self.insights_data = insights_data or {}
        self.ip_cache = {}

        google_api_key = os.getenv("GOOGLE_API_KEY")
        if not google_api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment variables")

        self.llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash",
            temperature=0.3,
            google_api_key=google_api_key
        )

        self.ipinfo_token = os.getenv("IPINFO_TOKEN")
        self.ipgeolocation_key = os.getenv("IPGEOLOCATION_KEY")
        self.tavily_key = os.getenv("TAVILY_API_KEY")
        self.abuseipdb_key = os.getenv("ABUSEIPDB_KEY")

        self._setup_prompts()

    def _setup_prompts(self):
        self.ip_analysis_prompt = PromptTemplate(
            input_variables=["ip_data", "user_query"],
            template="""
            You are a cybersecurity analyst. Analyze the following IP address information and answer the user's query.

            IP Address Information:
            {ip_data}

            User Query: {user_query}

            Provide a comprehensive analysis focusing on:
            1. Geographic location and ISP details
            2. Hosting information and ASN details
            3. Security implications (if any)
            4. Reputation and abuse history
            5. Any suspicious indicators

            Format your response clearly and highlight important security-relevant information.
            """
        )

        self.insights_prompt = PromptTemplate(
            input_variables=["insights", "user_query"],
            template="""
            You are a cybersecurity analyst with access to threat intelligence data. Answer the user's query based on the following insights:

            Available Insights:
            {insights}

            User Query: {user_query}

            Provide accurate, data-driven responses. Include specific metrics and statistics when available.
            If the query cannot be answered with the available data, clearly state this and suggest alternatives.
            """
        )

        self.general_prompt = PromptTemplate(
            input_variables=["context", "user_query", "web_results"],
            template="""
            You are a cybersecurity expert assistant. Answer the user's query using the provided context and web search results.

            Context Data:
            {context}

            Web Search Results:
            {web_results}

            User Query: {user_query}

            Provide accurate, comprehensive responses. Combine information from multiple sources when relevant.
            """
        )

    def summarize_insights(self) -> str:
        summary = []
        tcats = self.insights_data.get("threat_categories", {}).get("summary_table", [])
        summary.append("Top Threat Categories:")
        for row in tcats:
            summary.append(f"- {row.get('Category', 'N/A')}: {row.get('Count of TID', 0)} events")

        vuls = self.insights_data.get("vulnerability_summary", {})
        summary.append("\nVulnerabilities:")
        summary.append(f"- Occurrences: {vuls.get('Frequency of Occurrence', 0)}")
        summary.append(f"- Unique IPs: {vuls.get('Count of Unique IP', 0)}")

        return "\n".join(summary)

    def validate_ip(self, ip_address: str) -> bool:
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    async def get_ip_info_basic(self, ip_address: str) -> Dict:
        url = f"https://ipinfo.io/{ip_address}/json"
        headers = {"Authorization": f"Bearer {self.ipinfo_token}"} if self.ipinfo_token else {}

        ssl_context = ssl.create_default_context(cafile=certifi.where())
        connector = aiohttp.TCPConnector(ssl=ssl_context)

        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=headers) as response:
                logging.info(f"[IPINFO] Status: {response.status}")
                return await response.json()


    async def get_ip_geolocation(self, ip_address: str) -> Dict:
        if not self.ipgeolocation_key:
            return {"error": "IPGeolocation API key not configured"}

        url = "https://api.ipgeolocation.io/ipgeo"
        params = {
            "apiKey": self.ipgeolocation_key,
            "ip": ip_address,
            "fields": "geo,isp,security_threat,usage_type"
        }

        ssl_context = ssl.create_default_context(cafile=certifi.where())
        connector = aiohttp.TCPConnector(ssl=ssl_context)

        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, params=params) as response:
                logging.info(f"[IPGEO] Status: {response.status}")
                return await response.json()


    async def get_abuse_info(self, ip_address: str) -> Dict:
        if not self.abuseipdb_key:
            return {"error": "AbuseIPDB API key not configured"}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.abuseipdb_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": True
        }

        ssl_context = ssl.create_default_context(cafile=certifi.where())
        connector = aiohttp.TCPConnector(ssl=ssl_context)

        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=headers, params=params) as response:
                logging.info(f"[ABUSEIPDB] Status: {response.status}")
                return await response.json()


    async def get_comprehensive_ip_info(self, ip_address: str) -> Dict:
        if ip_address in self.ip_cache:
            return self.ip_cache[ip_address]

        tasks = [
            self.get_ip_info_basic(ip_address),
            self.get_ip_geolocation(ip_address),
            self.get_abuse_info(ip_address)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        data = {
            "ip_address": ip_address,
            "timestamp": datetime.now().isoformat(),
            "basic_info": results[0],
            "geolocation": results[1],
            "abuse_info": results[2]
        }
        self.ip_cache[ip_address] = data
        return data

    def format_ip_summary(self, ip_data: Dict) -> str:
        summary = f"IP Address Analysis: {ip_data.get('ip_address', 'Unknown')}\n"
        summary += "=" * 50 + "\n\n"

        basic = ip_data.get('basic_info', {})
        if 'error' not in basic:
            summary += f"ASN: {basic.get('org', 'Unknown')}\n"
            summary += f"City: {basic.get('city', 'Unknown')}\n"
            summary += f"Region: {basic.get('region', 'Unknown')}\n"
            summary += f"Country: {basic.get('country', 'Unknown')}\n\n"

        geo = ip_data.get('geolocation', {})
        if 'error' not in geo:
            summary += f"ISP: {geo.get('isp', 'Unknown')}\n"
            summary += f"Usage Type: {geo.get('usage_type', 'Unknown')}\n"

        abuse = ip_data.get('abuse_info', {})
        if 'error' not in abuse and 'data' in abuse:
            abuse_data = abuse['data']
            summary += f"Abuse Confidence: {abuse_data.get('abuseConfidencePercentage', 0)}%\n"
            summary += f"Total Reports: {abuse_data.get('totalReports', 0)}\n"

        return summary

    async def query_ip_address(self, ip_address: str, user_query: str = "") -> str:
        ip_data = await self.get_comprehensive_ip_info(ip_address)
        formatted_data = self.format_ip_summary(ip_data)

        if not user_query:
            return formatted_data

        prompt = self.ip_analysis_prompt.format(ip_data=formatted_data, user_query=user_query)
        response = self.llm.invoke(prompt)
        return response.content

    def query_insights(self, user_query: str) -> str:
        if not self.insights_data:
            return "No insights data available. Please load insights first."

        prompt = self.insights_prompt.format(
            insights=self.summarize_insights(),
            user_query=user_query
        )
        response = self.llm.invoke(prompt)
        return response.content

    async def general_query(self, user_query: str, include_web_search: bool = False) -> str:
        web_results = ""

        if include_web_search and self.tavily_key:
            url = "https://api.tavily.com/search"
            headers = {"Content-Type": "application/json"}
            data = {
                "api_key": self.tavily_key,
                "query": user_query,
                "search_depth": "basic",
                "max_results": 5
            }

            ssl_context = ssl.create_default_context(cafile=certifi.where())
            connector = aiohttp.TCPConnector(ssl=ssl_context)

            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(url, headers=headers, json=data) as response:
                    web_results = json.dumps(await response.json(), indent=2)

        context = {
            "insights": self.insights_data,
            "timestamp": datetime.now().isoformat()
        }

        prompt = self.general_prompt.format(
            context=json.dumps(context, indent=2),
            user_query=user_query,
            web_results=web_results
        )

        response = self.llm.invoke(prompt)
        return response.content


    def update_insights(self, new_insights: Dict):
        self.insights_data = new_insights

    def ask(self, query: str, query_type: str = "auto") -> str:
        return asyncio.run(self.process_query(query, query_type=query_type))

    async def process_query(self, query: str, query_type: str = "auto") -> str:
        query = query.strip()

        if query_type == "auto":
            words = query.split()
            for word in words:
                if self.validate_ip(word):
                    query_type = "ip"
                    break

            insight_keywords = ["threat", "malware", "region", "category", "analysis", "data", "insights"]
            if any(k in query.lower() for k in insight_keywords):
                query_type = "insights"
            else:
                query_type = "general"

        if query_type == "ip":
            for word in query.split():
                if self.validate_ip(word):
                    return await self.query_ip_address(word, query)
            return "Please provide a valid IP address."

        elif query_type == "insights":
            return self.query_insights(query)

        elif query_type == "general":
            return await self.general_query(query, include_web_search=True)

        return "Invalid query type."
