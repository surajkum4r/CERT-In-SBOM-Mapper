import React, { useState } from "react";
import "@testing-library/jest-dom";
import { fireEvent, render, screen } from "@testing-library/react";
import VexPanel from "./VexPanel";
import { setVulnerabilityAnalysis } from "../services/certInDocumentService";

const components = [{ "bom-ref": "log4j", name: "log4j-core", version: "2.14.1" }];
const initial = [
  { id: "CVE-2021-44228", ratings: [{ severity: "critical", score: 10 }], affects: [{ ref: "log4j" }],
    recommendation: "log4j-core 2.14.1: upgrade to 2.15.0",
    properties: [{ name: "cert-in:priority", value: "P0 - known exploited (CISA KEV)" }, { name: "cert-in:kev_date_added", value: "2021-12-10" },
      { name: "cert-in:epss", value: "0.94358" }] },
  { id: "CVE-2021-45046", ratings: [{ severity: "critical", score: 9 }], affects: [{ ref: "log4j" }] },
];

function Harness({ onExportVex = () => {}, onExportCsaf = () => {} }) {
  const [vulns, setVulns] = useState(initial);
  return (
    <VexPanel vulnerabilities={vulns} components={components}
      onChange={(i, a) => setVulns((prev) => setVulnerabilityAnalysis(prev, i, a))}
      onExportVex={onExportVex} onExportCsaf={onExportCsaf} onBack={() => {}} />
  );
}

test("shows vulnerabilities with KEV/EPSS and component names", () => {
  render(<Harness />);
  expect(screen.getByText("CVE-2021-44228")).toBeInTheDocument();
  expect(screen.getByText("CISA KEV")).toBeInTheDocument();
  expect(screen.getByText("EPSS 0.94")).toBeInTheDocument();
  expect(screen.getAllByText("log4j-core@2.14.1")).toHaveLength(2);
  expect(screen.getByText("Under Investigation (2)")).toBeInTheDocument();
});

test("setting Not affected reveals the justification and updates the counts", () => {
  render(<Harness />);
  expect(screen.queryByLabelText("Justification for CVE-2021-44228")).toBeNull();
  fireEvent.change(screen.getByLabelText("Status of CVE-2021-44228"), { target: { value: "not_affected" } });
  const justification = screen.getByLabelText("Justification for CVE-2021-44228");
  fireEvent.change(justification, { target: { value: "code_not_reachable" } });
  expect(justification.value).toBe("code_not_reachable");
  expect(screen.getByText("Not affected (1)")).toBeInTheDocument();
  expect(screen.getByText("Under Investigation (1)")).toBeInTheDocument();
});

test("CSAF export needs a publisher and namespace", () => {
  const onExportCsaf = jest.fn();
  render(<Harness onExportCsaf={onExportCsaf} />);
  const csaf = screen.getByText("Export CSAF 2.0 advisory");
  expect(csaf).toBeDisabled();
  fireEvent.change(screen.getByPlaceholderText("e.g. Example Org Pvt Ltd"), { target: { value: "Example Org" } });
  fireEvent.change(screen.getByPlaceholderText("e.g. https://example.in"), { target: { value: "https://example.in" } });
  expect(csaf).toBeEnabled();
  fireEvent.click(csaf);
  expect(onExportCsaf).toHaveBeenCalledWith({ publisher: "Example Org", namespace: "https://example.in" });
});

test("remediation details: response, workaround, restart, date", () => {
  render(<Harness />);
  fireEvent.click(screen.getByLabelText("Remediation details for CVE-2021-44228"));
  fireEvent.click(screen.getByLabelText("Workaround available"));
  fireEvent.change(screen.getByLabelText("Workaround for CVE-2021-44228"), { target: { value: "Disable JNDI lookups" } });
  fireEvent.change(screen.getByLabelText("Restart required for CVE-2021-44228"), { target: { value: "service" } });
  fireEvent.change(screen.getByLabelText("Remediation date for CVE-2021-44228"), { target: { value: "2021-12-14" } });
  expect(screen.getByLabelText("Workaround available")).toBeChecked();
  expect(screen.getByLabelText("Workaround for CVE-2021-44228")).toHaveValue("Disable JNDI lookups");
  expect(screen.getByLabelText("Restart required for CVE-2021-44228")).toHaveValue("service");
  expect(screen.getByLabelText("Remediation date for CVE-2021-44228")).toHaveValue("2021-12-14");
  // the status was not touched by these edits
  expect(screen.getByLabelText("Status of CVE-2021-44228")).toHaveValue("under_investigation");
});
