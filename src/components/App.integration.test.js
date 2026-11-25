import React from "react";
import "@testing-library/jest-dom";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { saveAs } from "file-saver";
import App from "./App";
import cacheService from "../services/cacheService";
import { resetKevCacheForTests } from "../services/vulnerabilityService";

jest.mock("file-saver", () => ({ saveAs: jest.fn() }));
// PDF/Excel generation is not under test (and jsPDF needs browser APIs jsdom lacks)
jest.mock("../services/pdfExportService", () => jest.fn());
jest.mock("exceljs", () => ({ Workbook: jest.fn() }));

const SBOM = {
  bomFormat: "CycloneDX", specVersion: "1.5", serialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", version: 1,
  metadata: { timestamp: "2026-11-10T09:30:00Z", authors: [{ name: "Example Org PSIRT" }],
    component: { "bom-ref": "app", name: "payments-service", version: "4.1.0" } },
  components: [{ type: "library", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20" }],
};

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const notFound = () => Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({}) });

beforeEach(() => {
  cacheService.forceClear();
  resetKevCacheForTests();
  saveAs.mockClear();
  global.fetch = jest.fn((url) => {
    if (url.includes("api.osv.dev")) {
      return ok({ vulns: [{ id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"], summary: "Command injection in lodash",
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
        affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] }] });
    }
    if (url.includes("registry.npmjs.org")) {
      return ok({ time: { "4.17.20": "2020-08-13T16:53:54Z" }, "dist-tags": { latest: "4.17.21" },
        versions: { "4.17.20": { description: "Lodash modular utilities.", license: "MIT", author: { name: "John-David Dalton" },
          dist: { shasum: "b58fd3c8b0db6ec1a6a8ac4c8f9d7a9b0e7a7f5e" } } } });
    }
    if (url.includes("kev-data")) return ok({ vulnerabilities: [] });
    if (url.includes("api.first.org")) return ok({ data: [{ cve: "CVE-2021-23337", epss: "0.012", percentile: "0.85" }] });
    if (url.includes("endoflife.date/api/all.json")) return ok([]);
    return notFound();
  });
});

const blobText = (blob) => new Promise((resolve) => {
  const r = new FileReader();
  r.onload = () => resolve(r.result);
  r.readAsText(blob);
});

test("upload -> enrich -> VEX panel -> private and public export with CERT-In document details", async () => {
  const { container } = render(<App />);
  const file = new File([JSON.stringify(SBOM)], "sbom.json", { type: "application/json" });
  await act(async () => {
    fireEvent.change(container.querySelector("#sbomUpload"), { target: { files: [file] } });
  });
  // processing finished: the VEX button shows the vulnerability count
  const vexButton = await screen.findByText(/Vulnerability Status \(VEX\) \(1\)/, {}, { timeout: 5000 });

  // VEX panel lists the merged CVE and lets the status be changed
  // actions stay disabled until the progress bar clears (~600 ms after processing)
  await waitFor(() => expect(vexButton).toBeEnabled(), { timeout: 3000 });
  fireEvent.click(vexButton);
  expect(await screen.findByText("CVE-2021-23337")).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Status of CVE-2021-23337"), { target: { value: "fixed" } });
  fireEvent.click(screen.getByText("Export CycloneDX VEX"));
  const [vexBlob, vexName] = saveAs.mock.calls[0];
  expect(vexName).toBe("cyclonedx-vex.json");
  const vex = JSON.parse(await blobText(vexBlob));
  expect(vex.vulnerabilities[0].analysis.state).toBe("resolved");
  expect(vex.vulnerabilities[0].affects[0].ref).toBe("urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#pkg:npm/lodash@4.17.20");
  fireEvent.click(screen.getByText("← Back to components"));

  // conformance panel: the fixture has no dependency graph, so Dependencies is missing
  fireEvent.click(screen.getByText(/CERT-In Conformance \(\d+(\.\d)?%\)/));
  expect(await screen.findByText("Not conformant")).toBeInTheDocument();
  const gapRow = screen.getByText("lodash@4.17.20").closest("tr");
  expect(within(gapRow).getByText(/Component Dependencies/)).toBeInTheDocument();
  fireEvent.click(within(gapRow).getByText("Edit")); // opens that component in the editor
  expect(await screen.findByText("← Back")).toBeInTheDocument();
  // the derived criticality is labelled for review; a manual choice replaces the basis
  expect(screen.getByText(/Basis: derived from the highest vulnerability severity/)).toBeInTheDocument();
  const criticality = screen.getAllByRole("combobox")
    .find((s) => s.tagName === "SELECT" && Array.from(s.options).some((o) => o.value === "Critical"));
  fireEvent.change(criticality, { target: { value: "Low" } });
  expect(screen.getByText("Basis: manual - set by a reviewer")).toBeInTheDocument();
  fireEvent.click(screen.getByText("← Back"));

  // export dialog: author prefilled from metadata, choose the public distribution
  fireEvent.click(screen.getByTitle("Export SBOM with optional digital signature"));
  const dialog = document.querySelector(".export-dialog");
  expect(within(dialog).getByPlaceholderText("e.g. Example Org Pvt Ltd - Product Security")).toHaveValue("Example Org PSIRT");
  fireEvent.click(within(dialog).getByText(/Declare Practices and Processes/));
  fireEvent.change(within(dialog).getByPlaceholderText(/regenerated on every release/), { target: { value: "Every release" } });
  fireEvent.click(within(dialog).getByLabelText(/Private - full SBOM/));
  const exportButton = within(dialog).getAllByText("Export SBOM").find((el) => el.tagName === "BUTTON");
  fireEvent.click(exportButton);
  await waitFor(() => expect(saveAs).toHaveBeenCalledTimes(2));
  const [sbomBlob, sbomName] = saveAs.mock.calls[1];
  expect(sbomName).toBe("cyclonedx-sbom-updated.json");
  const out = JSON.parse(await blobText(sbomBlob));
  const comp = out.components[0];
  const prop = (o, n) => (o.properties || []).find((p) => p.name === n)?.value;

  // fields written into the component (description, licence, hash) and CERT-In properties
  expect(comp.description).toBe("Lodash modular utilities.");
  expect(comp.licenses).toEqual([{ license: { id: "MIT" } }]);
  expect(comp.hashes).toEqual([{ alg: "SHA-1", content: "b58fd3c8b0db6ec1a6a8ac4c8f9d7a9b0e7a7f5e" }]);
  expect(prop(comp, "Author of SBOM Data")).toBe("Example Org PSIRT");
  expect(prop(comp, "Patch Status")).toBe("Update available (>= 4.17.21)");
  expect(prop(comp, "Release Date")).toBe("13-08-2020");
  expect(prop(comp, "Component Supplier")).toBe("John-David Dalton");
  // document details
  expect(out.metadata.timestamp).not.toBe("2026-11-10T09:30:00Z");
  expect(prop(out.metadata, "cert-in:source_timestamp")).toBe("2026-11-10T09:30:00Z");
  expect(prop(out.metadata, "cert-in:practice:frequency")).toBe("Every release");
  expect(prop(out.metadata, "cert-in:distribution")).toBe("private");
  expect(out.vulnerabilities[0]).toMatchObject({ id: "CVE-2021-23337", analysis: { state: "resolved" } });
  expect(out.vulnerabilities[0].ratings[0].score).toBe(7.2);

  // public copy (CERT-In 5.3.2): no vulnerability information
  fireEvent.click(screen.getByTitle("Export SBOM with optional digital signature"));
  const dialog2 = document.querySelector(".export-dialog");
  fireEvent.click(within(dialog2).getByLabelText(/Public - vulnerability data/));
  fireEvent.click(within(dialog2).getAllByText("Export SBOM").find((el) => el.tagName === "BUTTON"));
  await waitFor(() => expect(saveAs).toHaveBeenCalledTimes(3));
  const [pubBlob, pubName] = saveAs.mock.calls[2];
  expect(pubName).toBe("cyclonedx-sbom-public.json");
  const pub = JSON.parse(await blobText(pubBlob));
  expect(pub.vulnerabilities).toBeUndefined();
  expect(prop(pub.components[0], "Patch Status")).toBeUndefined();
  expect(prop(pub.metadata, "cert-in:distribution")).toBe("public");
  expect(prop(pub.metadata, "cert-in:practice:frequency")).toBe("Every release"); // practices remembered
});
