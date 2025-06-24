from jinja2 import Environment, FileSystemLoader
import markdown
import pdfkit
import os

class ReportGenerator:
    def __init__(self, template_dir="templates", output_dir="outputs/reports"):
        self.template_dir = template_dir
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_html(self, insights: dict, advisories: list, template_name="report_template.md"):
        env = Environment(loader=FileSystemLoader(self.template_dir))
        template = env.get_template(template_name)

        html_content = template.render(insights=insights, advisories=advisories)
        return html_content

    def export_pdf(self, html_content: str, output_filename="threat_report.pdf"):
        output_path = os.path.join(self.output_dir, output_filename)
        pdfkit.from_string(html_content, output_path)
        return output_path

    def run(self, insights, advisories, output_filename="threat_report.pdf"):
        html = self.generate_html(insights, advisories)
        return self.export_pdf(html, output_filename)
