"""Minimum elements from the CERT-In Technical Guidelines v2.0 (09.07.2025).

Each table below is transcribed from the guideline; ``key`` is the stable
identifier used in ``cert-in:*`` properties, ``cert-in:known_unknowns`` and the
validation report.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Field:
    key: str
    label: str
    description: str


# Table 5 - Minimum Elements of SBOM (Data Fields), section 4.2 definitions.
SBOM_FIELDS: tuple[Field, ...] = (
    Field("name", "Component Name", "Name of the software component or library."),
    Field("version", "Component Version", "Version number or identifier of the component."),
    Field("description", "Component Description", "Brief summary of the component's functionality and purpose."),
    Field("supplier", "Component Supplier", "Entity that supplied the component (vendor, third party, open-source project)."),
    Field("license", "Component License", "License under which the component is distributed (SPDX identifier/expression)."),
    Field("origin", "Component Origin", "Whether the component is proprietary, open-source or from a third-party vendor."),
    Field("dependencies", "Component Dependencies", "Other components this component depends on."),
    Field("vulnerabilities", "Vulnerabilities", "Known vulnerabilities with severity and CVE/advisory references."),
    Field("patch_status", "Patch Status", "Whether patches/updates are available for known vulnerabilities."),
    Field("release_date", "Release Date", "Date the component was released."),
    Field("eol_date", "End-of-Life (EOL) Date", "Date support/maintenance is scheduled to end."),
    Field("criticality", "Criticality", "Importance to the application: critical, high, medium or low."),
    Field("usage_restrictions", "Usage Restrictions", "Export control, IP or licence restrictions."),
    Field("hashes", "Checksums or Hashes", "Cryptographic hashes of the component files."),
    Field("comments", "Comments or Notes", "Additional notes relevant to the component."),
    Field("sbom_author", "Author of SBOM Data", "Entity that created the SBOM data for this component."),
    Field("timestamp", "Timestamp", "Date and time of SBOM data assembly."),
    Field("executable", "Executable Property", "Whether the component can be executed."),
    Field("archive", "Archive Property", "Whether the component is stored as an archive/compressed file."),
    Field("structured", "Structured Property", "Whether the component has an organised/structured data format."),
    Field("unique_id", "Unique Identifier", "Unique identifier (purl: pkg:type/namespace/name@version?qualifiers#subpath)."),
)

# Table 5 - "Practices and Processes" the organisation must define.
SBOM_PRACTICES = (
    "Frequency", "Depth", "Known Unknowns", "Distribution and Delivery",
    "Access Control", "Accommodation of Mistakes",
)

CRITICALITY_VALUES = ("critical", "high", "medium", "low")

# Table 9 - Minimum Elements pertaining to Cryptographic Asset (CBOM).
CBOM_FIELDS: dict[str, tuple[Field, ...]] = {
    "algorithm": (
        Field("name", "Name", "Algorithm name, e.g. AES-128-GCM."),
        Field("asset_type", "Asset Type", "'algorithm'."),
        Field("primitive", "Primitive", "Cryptographic primitive, e.g. signature, block-cipher, hash."),
        Field("mode", "Mode", "Operational mode, e.g. gcm (block ciphers only)."),
        Field("crypto_functions", "Crypto Functions", "Functions supported, e.g. keygen, encrypt, decrypt, tag."),
        Field("classical_security_level", "Classical security level", "Strength in bits against classical attacks."),
        Field("oid", "OID", "Object Identifier of the algorithm."),
    ),
    "key": (
        Field("name", "Name", "Name of the key."),
        Field("asset_type", "Asset Type", "'key' (CycloneDX related-crypto-material)."),
        Field("id", "id", "Unique identifier for the key (key ID / fingerprint)."),
        Field("state", "state", "Key state: active, revoked, expired..."),
        Field("size", "size", "Key size in bits."),
        Field("creation_date", "Creation Date", "Date the key was created."),
        Field("activation_date", "Activation Date", "Date the key became operational."),
    ),
    "protocol": (
        Field("name", "Name", "Protocol name: TLS, IPsec, SSH..."),
        Field("asset_type", "Asset Type", "'protocol'."),
        Field("version", "Version", "Protocol version, e.g. TLS 1.3."),
        Field("cipher_suites", "Cipher Suites", "Cipher suites supported/negotiated."),
        Field("oid", "OID", "OID associated with the protocol."),
    ),
    "certificate": (
        Field("name", "Name", "Certificate name (usually subject)."),
        Field("asset_type", "Asset Type", "'certificate'."),
        Field("subject_name", "Subject Name", "Distinguished Name of the subject."),
        Field("issuer_name", "Issuer Name", "Distinguished Name of the issuing CA."),
        Field("not_valid_before", "Not Valid Before", "Start of validity."),
        Field("not_valid_after", "Not Valid After", "Expiry."),
        Field("signature_algorithm_ref", "Signature Algorithm Reference", "Reference to the signing algorithm."),
        Field("subject_public_key_ref", "Subject Public Key Reference", "Reference to the subject public key."),
        Field("certificate_format", "Certificate Format", "e.g. X.509."),
        Field("certificate_extension", "Certificate Extension", "File extension, e.g. .crt."),
    ),
}

# Table 8 - Minimum Elements of QBOM (device/system level).
QBOM_FIELDS: tuple[Field, ...] = (
    Field("model_name", "Model Name", "Unique identifier of the quantum device or system."),
    Field("version", "Version", "Version numbers and updates."),
    Field("vendor_origin", "Vendor & Origin Information", "Manufacturer and origin."),
    Field("license", "License Information", "Licensing terms and conditions."),
    Field("cryptographic_asset", "Cryptographic Asset", "Crypto assets per Table 9."),
    Field("communication_protocol", "Communication Protocol", "Communication protocols used."),
    Field("hardware", "Hardware", "Processor, simulators, networking components, sensors."),
    Field("software_dependencies", "Software Dependencies", "Libraries, APIs, SDKs, firmware."),
    Field("environmental_impact", "Environmental Impact", "Energy consumption and sustainability."),
    Field("vulnerabilities", "Vulnerabilities", "Known vulnerabilities with severity and references."),
    Field("attestations", "Attestations", "Digital signature over the QBOM."),
)

# Table 10 - Minimum Elements of AIBOM.
AIBOM_FIELDS: tuple[Field, ...] = (
    Field("model_name", "Model Name", "Official name of the AI model."),
    Field("model_version", "Model Version", "Specific version of the model."),
    Field("model_type", "Model Type", "e.g. text-generation, image-classifier."),
    Field("model_developer", "Model Developer", "Developer or organisation responsible."),
    Field("model_licensing", "Model Licensing Information", "Licences for the model and its components."),
    Field("software_dependencies", "Software Dependencies", "Libraries, frameworks, OS and proprietary software required."),
    Field("ml_models_algorithms", "ML Models and Algorithms", "Models/algorithms used, decision and learning mechanisms."),
    Field("performance_metrics", "Model Performance Metrics", "Accuracy, precision, recall, F1..."),
    Field("data_source", "Data Source", "Origin of the training data."),
    Field("data_sets", "Data Sets", "Training datasets: names, versions, formats, limitations."),
    Field("hardware", "Hardware", "Compute required: GPUs/TPUs, storage, memory."),
    Field("security_requirements", "Security Requirements", "Encryption and access control protecting model and user data."),
    Field("input", "Input", "Type of input accepted."),
    Field("output", "Output", "Type of output generated."),
    Field("intended_usage", "Intended Usage", "Intended use cases."),
    Field("out_of_scope_usage", "Out of Scope Usage", "Uses to avoid."),
    Field("environmental_impact", "Environmental Impact", "Energy use, resources, carbon footprint."),
    Field("vulnerabilities", "Vulnerabilities", "Known vulnerabilities with severity and references."),
    Field("attestations", "Attestations", "Digital signature over the model or AIBOM."),
)

# Table 11 - Minimum Elements of HBOM. The table lists product-level elements
# followed by per-component elements (Supplier Information/Location appear in both).
HBOM_PRODUCT_FIELDS: tuple[Field, ...] = (
    Field("product_name", "Product Name", "Common or marketing name."),
    Field("product_version", "Product Version", "Iteration or release number."),
    Field("product_details", "Product Details", "Key specifications and features."),
    Field("warranty_amc", "Warranty/AMC", "Guarantee and annual maintenance contract."),
    Field("manufacturer_name", "Manufacturer Name", "Company producing the hardware."),
    Field("manufacturer_location", "Manufacturer Location", "Address of the manufacturer."),
    Field("manufacturing_date", "Manufacturing Date", "Date the product was produced."),
    Field("supplier_information", "Supplier Information", "Company that provided/sold the product."),
    Field("supplier_location", "Supplier Location", "Address of the supplier."),
    Field("model_number", "Model Number", "Alphanumeric identifier of the product design."),
    Field("serial_number", "Serial Number", "Unique identifier of the individual unit."),
)
HBOM_COMPONENT_FIELDS: tuple[Field, ...] = (
    Field("name", "Component Name", "Name of the hardware component."),
    Field("model_number", "Model Number", "Part / model number."),
    Field("serial_number", "Serial Number", "Unit serial number."),
    Field("technical_specification", "Technical Specification", "Voltage, frequency, capacity..."),
    Field("supplier_information", "Supplier Information", "Company that supplied the component to the manufacturer."),
    Field("supplier_location", "Supplier Location", "City, country of the direct supplier."),
    Field("technology_node", "Technology Node", "Semiconductor process node (integrated circuits)."),
    Field("compliance", "Compliance", "Declarations/certifications, e.g. RoHS, CE."),
    Field("power_supply", "Power supply", "Voltage, current, wattage."),
    Field("license", "License Information", "IP licences, esp. firmware/embedded software."),
    Field("test_result", "Test Result", "QA / functional test outcome."),
    Field("sub_component", "Sub-component", "Nested hardware parts (recursive)."),
)

# VEX statuses required by section 6(a), mapped to CycloneDX analysis.state
# and CSAF 2.0 product_status buckets.
VEX_STATUS = {
    "not_affected": {"label": "Not affected", "cdx": ("not_affected", "false_positive"), "csaf": "known_not_affected"},
    "affected": {"label": "Affected", "cdx": ("exploitable",), "csaf": "known_affected"},
    "fixed": {"label": "Fixed", "cdx": ("resolved", "resolved_with_pedigree"), "csaf": "fixed"},
    "under_investigation": {"label": "Under Investigation", "cdx": ("in_triage",), "csaf": "under_investigation"},
}


def cdx_state_to_certin(state: str | None) -> str:
    for key, spec in VEX_STATUS.items():
        if state in spec["cdx"]:
            return key
    return "under_investigation"


def labels(fields) -> dict[str, str]:
    return {f.key: f.label for f in fields}
