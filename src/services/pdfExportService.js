import jsPDF from 'jspdf';

class PDFExportService {
  constructor() {
    this.doc = null;
    this.pageHeight = 0;
    this.margin = 20;
    this.currentY = 0;
    this.lineHeight = 6;
  }

  initializeDocument() {
    this.doc = new jsPDF('p', 'mm', 'a4');
    this.pageHeight = this.doc.internal.pageSize.height;
    this.currentY = this.margin;
  }

  addHeader(title, subtitle = '') {
    // Title
    this.doc.setFontSize(20);
    this.doc.setFont('helvetica', 'bold');
    this.doc.text(title, this.margin, this.currentY);
    this.currentY += 10;

    // Subtitle
    if (subtitle) {
      this.doc.setFontSize(12);
      this.doc.setFont('helvetica', 'normal');
      this.doc.text(subtitle, this.margin, this.currentY);
      this.currentY += 8;
    }

    // Date
    const currentDate = new Date().toLocaleDateString();
    this.doc.setFontSize(10);
    this.doc.text(`Generated on: ${currentDate}`, this.margin, this.currentY);
    this.currentY += 15;
  }

  addSection(title, content) {
    // Check if we need a new page
    if (this.currentY > this.pageHeight - 40) {
      this.doc.addPage();
      this.currentY = this.margin;
    }

    // Section title
    this.doc.setFontSize(14);
    this.doc.setFont('helvetica', 'bold');
    this.doc.text(title, this.margin, this.currentY);
    this.currentY += 8;

    // Section content
    this.doc.setFontSize(10);
    this.doc.setFont('helvetica', 'normal');
    
    if (typeof content === 'string') {
      const lines = this.doc.splitTextToSize(content, 170);
      this.doc.text(lines, this.margin, this.currentY);
      this.currentY += lines.length * this.lineHeight + 5;
    } else if (Array.isArray(content)) {
      content.forEach(item => {
        if (this.currentY > this.pageHeight - 20) {
          this.doc.addPage();
          this.currentY = this.margin;
        }
        this.doc.text(`• ${item}`, this.margin + 5, this.currentY);
        this.currentY += this.lineHeight;
      });
      this.currentY += 5;
    }
  }

  addTable(headers, data, title = '') {
    // Check if we need a new page
    if (this.currentY > this.pageHeight - 60) {
      this.doc.addPage();
      this.currentY = this.margin;
    }

    if (title) {
      this.doc.setFontSize(12);
      this.doc.setFont('helvetica', 'bold');
      this.doc.text(title, this.margin, this.currentY);
      this.currentY += 8;
    }

    // Table headers
    this.doc.setFontSize(9);
    this.doc.setFont('helvetica', 'bold');
    const colWidths = [15, 60, 30, 85]; // Adjust based on content
    let xPos = this.margin;

    headers.forEach((header, index) => {
      this.doc.text(header, xPos, this.currentY);
      xPos += colWidths[index];
    });
    this.currentY += 6;

    // Table data
    this.doc.setFont('helvetica', 'normal');
    data.forEach((row, rowIndex) => {
      if (this.currentY > this.pageHeight - 20) {
        this.doc.addPage();
        this.currentY = this.margin;
      }

      xPos = this.margin;
      row.forEach((cell, cellIndex) => {
        const cellText = String(cell || '').substring(0, 50); // Truncate long text
        this.doc.text(cellText, xPos, this.currentY);
        xPos += colWidths[cellIndex];
      });
      this.currentY += 5;
    });
    this.currentY += 10;
  }

  addSummary(components) {
    const totalComponents = components.length;
    const withVulnerabilities = components.filter(c => c.vulnerabilities && c.vulnerabilities.length > 0).length;
    const withPatchStatus = components.filter(c => c.patchStatus && c.patchStatus !== 'Unknown').length;
    const withCriticality = components.filter(c => c.criticality && c.criticality !== 'Unknown').length;

    const summary = [
      `Total Components: ${totalComponents}`,
      `Components with Vulnerabilities: ${withVulnerabilities}`,
      `Components with Patch Status: ${withPatchStatus}`,
      `Components with Criticality: ${withCriticality}`,
      `Compliance Rate: ${Math.round((withPatchStatus + withCriticality) / (totalComponents * 2) * 100)}%`
    ];

    this.addSection('Summary', summary);
  }

  addComplianceInfo() {
    const complianceInfo = [
      'This SBOM has been processed to include CERT-In required properties:',
      '• Component Name, Version, and Description',
      '• Vulnerability information and Criticality assessment',
      '• Patch Status and Release Date information',
      '• End-of-Life Date and Usage Restrictions',
      '• Component Supplier and External References',
      '• Digital Signature for integrity verification'
    ];

    this.addSection('CERT-In Compliance', complianceInfo);
  }


  exportDetailedPDF(sbom, components, filename = 'sbom-comprehensive-report.pdf') {
    try {
      this.initializeDocument();

      // Header
      this.addHeader(
        'CERT-In SBOM Comprehensive Report',
        'Complete Software Bill of Materials Analysis with CERT-In Compliance'
      );

      // Summary
      this.addSummary(components);

      // SBOM Information
      const sbomInfo = [
        `SBOM Version: ${sbom.specVersion || '1.5'}`,
        `Serial Number: ${sbom.serialNumber || 'N/A'}`,
        `Version: ${sbom.version || '1'}`,
        `Metadata Timestamp: ${sbom.metadata?.timestamp || 'N/A'}`,
        `Tools Used: ${sbom.metadata?.tools?.map(t => t.name).join(', ') || 'N/A'}`
      ];
      this.addSection('SBOM Information', sbomInfo);

      // Components Overview Table
      const tableHeaders = ['#', 'Component', 'Version', 'Criticality', 'Patch Status'];
      const tableData = components.map((comp, index) => [
        index + 1,
        comp.name || 'N/A',
        comp.version || 'N/A',
        comp.criticality || 'Unknown',
        comp.patchStatus || 'Unknown'
      ]);

      this.addTable(tableHeaders, tableData, 'Components Overview');

      // Detailed Components
      this.addSection('Detailed Component Analysis', 'Individual component details with all available information:');
      
      components.forEach((comp, index) => {
        if (index > 0 && index % 15 === 0) {
          this.doc.addPage();
          this.currentY = this.margin;
        }

        const componentDetails = [
          `Component: ${comp.name || 'N/A'}`,
          `Version: ${comp.version || 'N/A'}`,
          `Type: ${comp.type || 'N/A'}`,
          `Description: ${comp.description || 'No description available'}`,
          `Criticality: ${comp.criticality || 'Unknown'}`,
          `Patch Status: ${comp.patchStatus || 'Unknown'}`,
          `Release Date: ${comp.releaseDate || 'N/A'}`,
          `End-of-Life: ${comp.endOfLifeDate || 'N/A'}`,
          `Component Supplier: ${comp.componentSupplier || 'N/A'}`,
          `Usage Restrictions: ${comp.usageRestrictions || 'N/A'}`,
          `PURL: ${comp.purl || 'N/A'}`,
          `Vulnerabilities: ${comp.vulnerabilities ? comp.vulnerabilities.length : 0} found`,
          `External References: ${comp.externalReferences ? comp.externalReferences.length : 0} found`,
          `Hashes: ${comp.hashes ? comp.hashes.length : 0} available`
        ];

        this.addSection(`Component ${index + 1}: ${comp.name || 'Unnamed'}`, componentDetails);
      });

      // Compliance Information
      this.addComplianceInfo();

      // Footer
      this.doc.setFontSize(8);
      this.doc.setFont('helvetica', 'italic');
      this.doc.text('Generated by CERT-In SBOM Mapper', this.margin, this.pageHeight - 10);
      this.doc.text('For compliance with CERT-In Technical Guidelines', 120, this.pageHeight - 10);

      // Save the PDF
      this.doc.save(filename);
      return { success: true, message: 'Comprehensive PDF exported successfully!' };

    } catch (error) {
      console.error('PDF export error:', error);
      return { success: false, message: 'Failed to export PDF: ' + error.message };
    }
  }
}

export default PDFExportService;
