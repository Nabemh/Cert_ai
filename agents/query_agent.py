import requests
import json
import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from typing import Dict, Any, Optional
import ipaddress
from datetime import datetime
import asyncio
import aiohttp

load_dotenv()

class QueryAgent:
    def __init__(self, insights_data: Dict = None):
        """
        Initialize the Query Agent with multiple data sources and LLM capabilities

        Args:
            insights_data: Dictionary containing analysis insights from your AnalysisAgent
        """
        self.insights_data = insights_data or {}

        # Initialize LLM
        google_api_key = os.getenv("GOOGLE_API_KEY")
        if not google_api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment variables")

        self.llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash",
            temperature=0.3,
            google_api_key=google_api_key
        )

        # API Keys for IP intelligence services
        self.ipinfo_token = os.getenv("IPINFO_TOKEN")  # Get from ipinfo.io
        self.ipgeolocation_key = os.getenv("IPGEOLOCATION_KEY")  # Get from ipgeolocation.io
        self.tavily_key = os.getenv("TAVILY_API_KEY")  # For web search
        self.abuseipdb_key = os.getenv("ABUSEIPDB_KEY")  # For abuse/reputation data

        # Initialize prompt templates
        self._setup_prompts()

    def _setup_prompts(self):
        """Setup prompt templates for different query types"""

        # IP Analysis prompt
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

        # Insights query prompt
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

        # General query prompt with web search integration
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

    def validate_ip(self, ip_address: str) -> bool:
        """Validate if the input is a valid IP address"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    async def get_ip_info_basic(self, ip_address: str) -> Dict:
        """Get basic IP information from ipinfo.io"""
        url = f"https://ipinfo.io/{ip_address}/json"
        headers = {}

        if self.ipinfo_token:
            headers["Authorization"] = f"Bearer {self.ipinfo_token}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {"error": f"HTTP {response.status}"}
        except Exception as e:
            return {"error": str(e)}

    async def get_ip_geolocation(self, ip_address: str) -> Dict:
        """Get detailed geolocation from ipgeolocation.io"""
        if not self.ipgeolocation_key:
            return {"error": "IPGeolocation API key not configured"}

        url = f"https://api.ipgeolocation.io/ipgeo"
        params = {
            "apiKey": self.ipgeolocation_key,
            "ip": ip_address,
            "fields": "geo,isp,security_threat,usage_type"
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {"error": f"HTTP {response.status}"}
        except Exception as e:
            return {"error": str(e)}

    async def get_abuse_info(self, ip_address: str) -> Dict:
        """Get abuse/reputation information from AbuseIPDB"""
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

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {"error": f"HTTP {response.status}"}
        except Exception as e:
            return {"error": str(e)}

    async def search_web(self, query: str) -> Dict:
        """Perform web search using Tavily"""
        if not self.tavily_key:
            return {"error": "Tavily API key not configured"}

        url = "https://api.tavily.com/search"
        headers = {
            "Content-Type": "application/json"
        }
        data = {
            "api_key": self.tavily_key,
            "query": query,
            "search_depth": "basic",
            "max_results": 5
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=data) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {"error": f"HTTP {response.status}"}
        except Exception as e:
            return {"error": str(e)}

    async def get_comprehensive_ip_info(self, ip_address: str) -> Dict:
        """Get comprehensive IP information from multiple sources"""
        if not self.validate_ip(ip_address):
            return {"error": "Invalid IP address format"}

        # Gather data from multiple sources concurrently
        tasks = [
            self.get_ip_info_basic(ip_address),
            self.get_ip_geolocation(ip_address),
            self.get_abuse_info(ip_address)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Combine results
        comprehensive_data = {
            "ip_address": ip_address,
            "timestamp": datetime.now().isoformat(),
            "basic_info": results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])},
            "geolocation": results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])},
            "abuse_info": results[2] if not isinstance(results[2], Exception) else {"error": str(results[2])}
        }

        return comprehensive_data

    def format_ip_summary(self, ip_data: Dict) -> str:
        """Format IP information into a readable summary"""
        summary = f"IP Address Analysis: {ip_data.get('ip_address', 'Unknown')}\n"
        summary += "=" * 50 + "\n\n"

        # Basic Info
        basic = ip_data.get('basic_info', {})
        if 'error' not in basic:
            summary += f"ASN: {basic.get('org', 'Unknown')}\n"
            summary += f"Hostname: {basic.get('hostname', 'No Hostname')}\n"
            summary += f"City: {basic.get('city', 'Unknown')}\n"
            summary += f"Region: {basic.get('region', 'Unknown')}\n"
            summary += f"Country: {basic.get('country', 'Unknown')}\n"
            summary += f"Postal Code: {basic.get('postal', 'Unknown')}\n"
            summary += f"Timezone: {basic.get('timezone', 'Unknown')}\n"
            summary += f"Coordinates: {basic.get('loc', 'Unknown')}\n\n"

        # Geolocation Details
        geo = ip_data.get('geolocation', {})
        if 'error' not in geo:
            summary += f"ISP: {geo.get('isp', 'Unknown')}\n"
            summary += f"Connection Type: {geo.get('connection_type', 'Unknown')}\n"
            summary += f"Usage Type: {geo.get('usage_type', 'Unknown')}\n"
            summary += f"AS Number: {geo.get('asn', 'Unknown')}\n"
            summary += f"Domain: {geo.get('domain', 'Unknown')}\n\n"

        # Security/Abuse Info
        abuse = ip_data.get('abuse_info', {})
        if 'error' not in abuse and 'data' in abuse:
            abuse_data = abuse['data']
            summary += f"Abuse Confidence: {abuse_data.get('abuseConfidencePercentage', 0)}%\n"
            summary += f"Is Whitelisted: {abuse_data.get('isWhitelisted', False)}\n"
            summary += f"Usage Type: {abuse_data.get('usageType', 'Unknown')}\n"
            summary += f"Domain: {abuse_data.get('domain', 'Unknown')}\n"

            if abuse_data.get('reports'):
                summary += f"Total Reports: {abuse_data.get('totalReports', 0)}\n"

        return summary

    async def query_ip_address(self, ip_address: str, user_query: str = "") -> str:
        """Main method to query IP address information"""
        # Get comprehensive IP data
        ip_data = await self.get_comprehensive_ip_info(ip_address)

        if "error" in ip_data:
            return f"Error retrieving IP information: {ip_data['error']}"

        # Format the data
        formatted_data = self.format_ip_summary(ip_data)

        # If no specific query, return formatted summary
        if not user_query:
            return formatted_data

        # Use LLM to analyze based on user query
        prompt = self.ip_analysis_prompt.format(
            ip_data=formatted_data,
            user_query=user_query
        )

        response = self.llm.invoke(prompt)
        return response.content

    def query_insights(self, user_query: str) -> str:
        """Query the insights data with natural language"""
        if not self.insights_data:
            return "No insights data available. Please load insights first."

        # Format insights data for LLM
        insights_text = json.dumps(self.insights_data, indent=2)

        prompt = self.insights_prompt.format(
            insights=insights_text,
            user_query=user_query
        )

        response = self.llm.invoke(prompt)
        return response.content

    async def general_query(self, user_query: str, include_web_search: bool = False) -> str:
        """Handle general queries with optional web search"""
        web_results = ""

        if include_web_search:
            search_results = await self.search_web(user_query)
            if "error" not in search_results:
                web_results = json.dumps(search_results.get("results", []), indent=2)

        # Combine available context
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
        """Update the insights data"""
        self.insights_data = new_insights

    async def process_query(self, query: str, query_type: str = "auto") -> str:
        """
        Main query processing method

        Args:
            query: The user's query
            query_type: 'ip', 'insights', 'general', or 'auto' for automatic detection

        Returns:
            String response to the query
        """
        query = query.strip()

        # Auto-detect query type if not specified
        if query_type == "auto":
            # Check if query contains an IP address
            words = query.split()
            for word in words:
                if self.validate_ip(word):
                    query_type = "ip"
                    break

            # Check if query is about insights/data
            insight_keywords = ["threat", "malware", "region", "category", "analysis", "data", "insights"]
            if any(keyword in query.lower() for keyword in insight_keywords):
                query_type = "insights"
            else:
                query_type = "general"

        # Process based on query type
        if query_type == "ip":
            # Extract IP address from query
            words = query.split()
            ip_address = None
            for word in words:
                if self.validate_ip(word):
                    ip_address = word
                    break

            if ip_address:
                return await self.query_ip_address(ip_address, query)
            else:
                return "Please provide a valid IP address in your query."

        elif query_type == "insights":
            return self.query_insights(query)

        elif query_type == "general":
            return await self.general_query(query, include_web_search=True)

        else:
            return "Invalid query type. Use 'ip', 'insights', 'general', or 'auto'."
