from jinja2 import Environment, FileSystemLoader
import os

class ReportGenerator:
    def generate_markdown(self, context: dict, template_name="report_template.md"):
        env = Environment(loader=FileSystemLoader(self.template_dir))
        template = env.get_template(template_name)
        return template.render(**context)

    def export_markdown_file(self, markdown_content: str, output_filename="threat_report.md"):
        output_path = os.path.join(self.output_dir, output_filename)
        with open(output_path, "w") as f:
            f.write(markdown_content)
        return output_path

    def run(self, context: dict, output_filename="threat_report.md"):
        markdown = self.generate_markdown(context)
        return self.export_markdown_file(markdown, output_filename)
