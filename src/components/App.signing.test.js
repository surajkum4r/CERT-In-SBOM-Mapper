import React from "react";
import "@testing-library/jest-dom";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { webcrypto } from "crypto";
import { TextEncoder, TextDecoder } from "util";
import { saveAs } from "file-saver";
import App from "./App";
import cacheService from "../services/cacheService";
import StandaloneSignatureService from "../services/standaloneSignatureService";

jest.mock("file-saver", () => ({ saveAs: jest.fn() }));
jest.mock("../services/pdfExportService", () => jest.fn());
jest.mock("exceljs", () => ({ Workbook: jest.fn() }));

// jsdom lacks WebCrypto and TextEncoder; use Node's implementations
beforeAll(() => {
  Object.defineProperty(window, "crypto", { value: webcrypto, configurable: true });
  global.TextEncoder = TextEncoder;
  global.TextDecoder = TextDecoder;
});

const blobText = (blob) => new Promise((resolve) => {
  const r = new FileReader();
  r.onload = () => resolve(r.result);
  r.readAsText(blob);
});

test("signing with a generated key pair also saves the keys, and the signature verifies", async () => {
  cacheService.forceClear();
  saveAs.mockClear();
  global.fetch = jest.fn(() => Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({}) }));
  const sbom = { bomFormat: "CycloneDX", specVersion: "1.5", version: 1, metadata: { authors: [{ name: "Org" }] },
    components: [{ type: "library", name: "internal-lib", version: "1.0.0" }] };
  const { container } = render(<App />);
  await act(async () => {
    fireEvent.change(container.querySelector("#sbomUpload"), { target: { files: [new File([JSON.stringify(sbom)], "s.json")] } });
  });
  const exportBtn = await screen.findByTitle("Export SBOM with optional digital signature", {}, { timeout: 5000 });
  await waitFor(() => expect(exportBtn).toBeEnabled(), { timeout: 5000 });
  fireEvent.click(exportBtn);
  const dialog = document.querySelector(".export-dialog");
  fireEvent.click(within(dialog).getByLabelText(/Export with digital signature/));
  fireEvent.click(within(dialog).getAllByText("Export SBOM").find((el) => el.tagName === "BUTTON"));
  await waitFor(() => expect(saveAs).toHaveBeenCalledTimes(4), { timeout: 5000 });

  const names = saveAs.mock.calls.map((c) => c[1]);
  expect(names).toEqual(["cyclonedx-sbom-updated.json", "cyclonedx-sbom-updated.json.sig",
    "sbom-signing-public.pem", "sbom-signing-private.pem"]);
  const [exported, sig, publicPem] = await Promise.all(saveAs.mock.calls.slice(0, 3).map((c) => blobText(c[0])));
  expect(publicPem).toMatch(/^-----BEGIN PUBLIC KEY-----/);
  expect(JSON.parse(sig).algorithm).toBe("RSA-PSS-SHA256");

  // a recipient with only the SBOM, the .sig file and the public key (no private key, fresh session) can verify it
  sessionStorage.clear();
  const verifier = new StandaloneSignatureService();
  const ok = await verifier.verifySBOM(JSON.parse(exported), JSON.parse(sig), publicPem);
  expect(ok.valid).toBe(true);
  // tampering is detected
  const tampered = JSON.parse(exported);
  tampered.components[0].version = "9.9.9";
  expect((await verifier.verifySBOM(tampered, JSON.parse(sig), publicPem)).valid).toBe(false);
  // without any public key the verifier says what is needed
  expect((await verifier.verifySBOM(JSON.parse(exported), JSON.parse(sig))).error).toMatch(/Upload the signer's public key/);
});

test("signature page: a recipient uploads SBOM, .sig and public key and gets a valid result", async () => {
  const SignatureManager = require("./SignatureManager").default;
  const signer = new StandaloneSignatureService();
  const keys = await signer.generateAndSaveKeys();
  const doc = { bomFormat: "CycloneDX", specVersion: "1.5", version: 1, components: [{ name: "a", version: "1" }] };
  const { sbom: signed, signatureFile } = await signer.signSBOM(doc, "s.json");
  sessionStorage.clear(); // the recipient's browser has no keys

  render(<SignatureManager sbom={null} onBackToTable={() => {}} />);
  const upload = async (id, content, name) => {
    await act(async () => {
      fireEvent.change(document.getElementById(id), { target: { files: [new File([content], name)] } });
      await new Promise((r) => setTimeout(r, 20)); // FileReader is async
    });
  };
  await upload("sbomFileInput", JSON.stringify(signed), "s.json");
  await upload("signatureFileInput", JSON.stringify(signatureFile.content), "s.json.sig");
  await upload("publicKeyFileInput", keys.publicKey, "sbom-signing-public.pem");
  await act(async () => {
    fireEvent.click(screen.getByText("✅ Verify Signature"));
  });
  expect(await screen.findByText("✅ Signature is valid!")).toBeInTheDocument();
});
