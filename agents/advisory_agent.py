import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime

class AdvisoryAgent:
    def __init__(self, url="https://csirt.ncc.gov.ng/", alert_keywords=None):
        self.url = url
        self.alert_keywords = alert_keywords or ["zero-day", "banking", "credential", "APT", "exploit"]

    def fetch_html(self):
        response = requests.get(self.url)
        response.raise_for_status()
        return response.text

    def parse_advisories(self, html):
        soup = BeautifulSoup(html, "html.parser")
        advisories = []

        table = soup.find("table")
        if not table:
            return advisories

        rows = table.find_all("tr")[1:]  # skip header

        for row in rows:
            cols = row.find_all("td")
            if len(cols) < 5:
                continue

            advisory_id = cols[0].text.strip()
            title = cols[1].text.strip()
            threat_type = cols[2].text.strip()
            impact = cols[3].text.strip()
            date_text = cols[4].text.strip()

            # Try to parse date (adjust format as needed)
            try:
                date = datetime.strptime(date_text, "%d %B, %Y").strftime("%Y-%m-%d")
            except:
                date = date_text  # fallback

            # Check for alert keywords
            is_alert = any(kw.lower() in title.lower() or kw.lower() in impact.lower() for kw in self.alert_keywords)

            advisories.append({
                "AdvisoryID": advisory_id,
                "Title": title,
                "Threat Type": threat_type,
                "Impact": impact,
                "Date": date,
                "Alert": is_alert
            })

        return advisories

    def run(self):
        html = self.fetch_html()
        parsed = self.parse_advisories(html)
        return parsed
