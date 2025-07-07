# reporting.py
import json
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from io import BytesIO
from datetime import datetime
from utils.helpers import format_timestamp, categorize_subdomain

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()
    
    def _setup_styles(self):
        """Setup report styles"""
        self.title_style = ParagraphStyle(
            'Title', parent=self.styles['Title'],
            fontSize=24, spaceAfter=20, alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        self.heading_style = ParagraphStyle(
            'Heading', parent=self.styles['Heading1'],
            fontSize=16, spaceAfter=12, textColor=colors.darkblue
        )
        self.subheading_style = ParagraphStyle(
            'SubHeading', parent=self.styles['Heading2'],
            fontSize=14, spaceAfter=8, textColor=colors.darkgreen
        )
        self.body_style = ParagraphStyle(
            'Body', parent=self.styles['Normal'],
            fontSize=10, spaceAfter=6, alignment=TA_JUSTIFY
        )
    
    def generate_pdf(self, scan_results):
        """Generate PDF report"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            rightMargin=36, leftMargin=36,
            topMargin=72, bottomMargin=36
        )
        
        story = []
        story.extend(self._create_title_page(scan_results))
        story.extend(self._create_summary(scan_results))
        story.extend(self._create_subdomain_analysis(scan_results))
        
        if 'ai_analysis' in scan_results:
            story.extend(self._create_ai_analysis(scan_results['ai_analysis']))
        
        story.extend(self._create_findings(scan_results))
        story.extend(self._create_appendix())
        
        doc.build(story)
        return buffer.getvalue()
    
    def _create_title_page(self, scan_results):
        """Create title page"""
        elements = [
            Paragraph("Security Recon Report", self.title_style),
            Spacer(1, 0.5*inch),
            Paragraph(f"Target: {scan_results['domain']}", self.heading_style),
            Spacer(1, 0.3*inch)
        ]
        
        info = [
            ['Scan ID:', scan_results.get('scan_id', 'N/A')],
            ['Date:', format_timestamp(scan_results.get('timestamp', ''))],
            ['Subdomains:', len(scan_results.get('subdomains', []))],
            ['Active:', len([s for s in scan_results.get('subdomains', []) 
                           if s.get('http_status') or s.get('https_status')])]
        ]
        
        table = Table(info, colWidths=[2*inch, 3*inch])
        table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold')
        ]))
        
        elements.append(table)
        elements.append(PageBreak())
        return elements
    
    def _create_summary(self, scan_results):
        """Create summary section"""
        elements = [
            Paragraph("Executive Summary", self.heading_style),
            Spacer(1, 0.2*inch)
        ]
        
        analysis = scan_results.get('ai_analysis', {})
        summary = f"""
        This report presents findings from automated reconnaissance of {scan_results['domain']}. 
        Found {len(scan_results.get('subdomains', []))} subdomains, with 
        {len([s for s in scan_results.get('subdomains', []) if s.get('http_status') or s.get('https_status')])} active.
        """
        
        elements.append(Paragraph(summary, self.body_style))
        
        if 'risk_assessment' in analysis:
            risk = analysis['risk_assessment']
            elements.extend([
                Spacer(1, 0.2*inch),
                Paragraph(f"Risk Level: {risk.get('level', 'Unknown')}", self.body_style),
                Paragraph(f"Score: {risk.get('score', 0)}/100", self.body_style)
            ])
        
        elements.append(PageBreak())
        return elements
    
    def _create_subdomain_analysis(self, scan_results):
        """Create subdomain analysis"""
        elements = [Paragraph("Subdomain Analysis", self.heading_style)]
        
        subdomains = scan_results.get('subdomains', [])
        active = [s for s in subdomains if s.get('http_status') or s.get('https_status')]
        
        stats = [
            ['Total Subdomains', len(subdomains)],
            ['Active', len(active)],
            ['HTTPS', len([s for s in active if s.get('https_status')])],
            ['HTTP Only', len([s for s in active if s.get('http_status') and not s.get('https_status')])]
        ]
        
        table = Table(stats, colWidths=[3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightblue),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        
        elements.extend([table, Spacer(1, 0.3*inch), PageBreak()])
        return elements
    
    def _create_ai_analysis(self, analysis):
        """Create AI analysis section"""
        elements = [Paragraph("Security Analysis", self.heading_style)]
        
        if 'insights' in analysis:
            elements.append(Paragraph("Key Insights:", self.subheading_style))
            for insight in analysis['insights'][:5]:
                elements.append(Paragraph(f"• {insight}", self.body_style))
        
        if 'recommendations' in analysis:
            elements.extend([
                Spacer(1, 0.2*inch),
                Paragraph("Recommendations:", self.subheading_style)
            ])
            for rec in analysis['recommendations'][:5]:
                elements.append(Paragraph(f"- {rec.get('action', '')}", self.body_style))
        
        elements.append(PageBreak())
        return elements
    
    def _create_findings(self, scan_results):
        """Create detailed findings"""
        elements = [Paragraph("Detailed Findings", self.heading_style)]
        
        active = [s for s in scan_results.get('subdomains', []) 
                 if s.get('http_status') or s.get('https_status')]
        
        if not active:
            return [Paragraph("No active subdomains found.", self.body_style)]
        
        # Group by category
        categories = {}
        for sub in active:
            cat = categorize_subdomain(sub['subdomain'])
            categories.setdefault(cat, []).append(sub)
        
        for cat, subs in categories.items():
            elements.append(Paragraph(f"{cat.title()} Subdomains", self.subheading_style))
            
            data = [['Subdomain', 'IP', 'HTTP', 'HTTPS']]
            for sub in subs[:20]:
                data.append([
                    sub['subdomain'],
                    sub.get('ip', ''),
                    sub.get('http_status', '-'),
                    sub.get('https_status', '-')
                ])
            
            table = Table(data, colWidths=[3*inch, 1.5*inch, 1*inch, 1*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
                ('GRID', (0,0), (-1,-1), 1, colors.black)
            ]))
            
            elements.extend([table, Spacer(1, 0.2*inch)])
        
        elements.append(PageBreak())
        return elements
    
    def _create_appendix(self):
        """Create appendix"""
        elements = [
            Paragraph("Appendix", self.heading_style),
            Paragraph("Methodology", self.subheading_style),
            Paragraph("Automated subdomain enumeration and analysis.", self.body_style),
            Spacer(1, 0.2*inch),
            Paragraph("Disclaimer", self.subheading_style),
            Paragraph("For authorized security testing only.", self.body_style)
        ]
        return elements
    
    def generate_json(self, scan_results):
        """Generate JSON report"""
        return json.dumps({
            'metadata': {
                'domain': scan_results['domain'],
                'timestamp': scan_results.get('timestamp'),
                'subdomains': len(scan_results.get('subdomains', []))
            },
            'subdomains': scan_results.get('subdomains', []),
            'analysis': scan_results.get('ai_analysis', {})
        }, indent=2)
