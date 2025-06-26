import pandas as pd
import matplotlib.pyplot as plt
import os

class AnalysisAgent:
    def __init__(self, df: pd.DataFrame, output_dir: str = "plots"):
        self.df = df
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _save_plot(self, fig, name):
        path = os.path.join(self.output_dir, f"{name}.png")
        fig.savefig(path, bbox_inches='tight')
        plt.close(fig)
        return path

    def top_threat_categories(self):
        # Group
        type_summary = self.df.groupby('Category').agg({
            'TID': 'count',
            'IP': pd.Series.nunique
        }).rename(columns={'TID': 'Count of TID', 'IP': 'Count of IP'})
        top3 = type_summary.sort_values('Count of TID', ascending=False).head(3)

        # Plot bar
        fig, ax = plt.subplots(figsize=(10,6))
        top3.plot(kind='bar', ax=ax)
        ax.set_title("Top 3 Threat Categories")
        ax.set_ylabel("Count")
        ax.set_xticklabels(top3.index, rotation=45)
        for container in ax.containers:
            ax.bar_label(container, fmt='%.0f', padding=3)

        bar_path = self._save_plot(fig, "threat_categories_bar")

        # Plot doughnut
        top3_ip = self.df.groupby('Category')['IP'].nunique().sort_values(ascending=False).head(3)
        fig, ax = plt.subplots(figsize=(4,4))
        ax.pie(top3_ip, labels=top3_ip.index, autopct='%1.1f%%', startangle=90, wedgeprops={'width': 0.4})
        ax.set_title("Top 3 Threat Categories by Unique IPs")
        doughnut_path = self._save_plot(fig, "threat_categories_doughnut")

        return {
            "summary_table": top3.reset_index().to_dict(orient="records"),
            "bar_chart": bar_path,
            "doughnut_chart": doughnut_path
        }

    def vulnerability_summary(self):
        vuln_df = self.df[self.df['Category'] == 'Vulnerability']
        return {
            "Frequency of Occurrence": int(vuln_df['TID'].count()),
            "Count of Unique IP": int(vuln_df['IP'].nunique())
        }

    def top_regions(self):
        region_summary = self.df.groupby('Region').agg({
            'TID': 'count',
            'IP': pd.Series.nunique
        }).rename(columns={'TID': 'Count of TID', 'IP': 'Count of Unique IP'})
        top5 = region_summary.sort_values('Count of TID', ascending=False).head(5)

        fig, ax = plt.subplots(figsize=(10,6))
        top5.plot(kind='bar', ax=ax, color=['steelblue', 'orange'])
        ax.set_title("Top 5 Regions with Most Threats")
        ax.set_ylabel("Count")
        ax.set_xticklabels(top5.index, rotation=45)
        for container in ax.containers:
            ax.bar_label(container, fmt='%.0f', padding=3)

        plot_path = self._save_plot(fig, "regions")

        return {
            "top_regions_table": top5.reset_index().to_dict(orient="records"),
            "bar_chart": plot_path
        }

    def top_c2_ips(self):
        ccip_summary = self.df.groupby('CC_Ip')['IP'].nunique().sort_values(ascending=False).head(5)

        fig, ax = plt.subplots(figsize=(5,5))
        ax.pie(ccip_summary, labels=ccip_summary.index, autopct='%1.1f%%', startangle=90, wedgeprops={'width': 0.4})
        ax.set_title("Top 5 C&C IPs by Unique IPs")

        plot_path = self._save_plot(fig, "c2_ips")

        return {
            "top_cc_ips": ccip_summary.reset_index().rename(columns={"CC_Ip": "IP", "IP": "Unique Count"}).to_dict(orient="records"),
            "doughnut_chart": plot_path
        }

    def top_malware(self):
        malware_df = self.df[self.df['Type'].isin(['Malware', 'SpamBot'])]
        malware_summary = malware_df.groupby('Infection').agg({
            'TID': 'count',
            'IP': pd.Series.nunique
        }).rename(columns={
            'TID': 'Frequency of Occurrence',
            'IP': 'Count of Unique IPs'
        }).sort_values(by='Frequency of Occurrence', ascending=False).head(5)

        fig, ax = plt.subplots(figsize=(10,6))
        malware_summary.plot(kind='bar', ax=ax, color=['steelblue', 'orange'])
        ax.set_title("Top 5 Prevalent Malware (Including SpamBot)")
        ax.set_ylabel("Count")
        ax.set_xticklabels(malware_summary.index, rotation=45)
        ax.grid(axis='y', linestyle='--', alpha=0.7)
        for container in ax.containers:
            ax.bar_label(container, fmt='%.0f', padding=3)

        plot_path = self._save_plot(fig, "malware")

        return {
            "top_malware_table": malware_summary.reset_index().to_dict(orient="records"),
            "bar_chart": plot_path
        }

    def run(self):
        return {
            "threat_categories": self.top_threat_categories(),
            "vulnerability_summary": self.vulnerability_summary(),
            "top_regions": self.top_regions(),
            "top_c2_ips": self.top_c2_ips(),
            "top_malware": self.top_malware(),
            "smart_summary": ''
        }

