from jinja2 import Environment, FileSystemLoader
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

    def export_html_file(self, html_content: str, output_filename="threat_report.html"):
        output_path = os.path.join(self.output_dir, output_filename)
        with open(output_path, "w") as f:
            f.write(html_content)
        return output_path

    def run(self, insights, advisories, output_filename="threat_report.html"):
        html = self.generate_html(insights, advisories)
        return self.export_html_file(html, output_filename)
