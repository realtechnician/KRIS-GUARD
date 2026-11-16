/**
 * Does each detector find what it should, and leave ordinary text alone?
 */
import { describe, expect, it } from "vitest";
import { BUILT_IN_DETECTORS, detectAll } from "../src/pii/detect.js";
import { createNameDetector } from "../src/pii/detectors/names.js";
import type { PiiType } from "../src/pii/types.js";

const names = createNameDetector(["Mugisha Jean", "Uwase", "Jean-Pierre Habimana", "Aimé"]);
const detectors = [...BUILT_IN_DETECTORS, names];

/** Returns what was found as [type, text] pairs. */
function found(text: string): Array<[PiiType, string]> {
  return detectAll(text, detectors).map((m) => [m.type, text.slice(m.start, m.end)]);
}

describe("national ID numbers", () => {
  it.each([
    ["Indangamuntu: 1199080012345678.", "1199080012345678"],
    ["ID 1 1990 8 0012345 0 67 yatanzwe i Kigali", "1 1990 8 0012345 0 67"],
    ["ID 1-1990-8-0012345-0-67", "1-1990-8-0012345-0-67"],
    ["ID 1.1990.8.0012345.0.67", "1.1990.8.0012345.0.67"],
    ["ref 2024 1199080012345678 9", "1199080012345678"],
    ["female, born 2001: 1200170012345012", "1200170012345012"],
    ["refugee 2198580012345099", "2198580012345099"],
  ])("finds the ID in %j", (text, expected) => {
    expect(found(text)).toContainEqual(["NATIONAL_ID", expected]);
  });

  it("does not call a 16-digit number without a believable birth year an ID", () => {
    const result = found("card 4111111111111111");
    expect(result.some(([type]) => type === "NATIONAL_ID")).toBe(false);
    // ...but a number that long is still hidden, as a possible account number
    expect(result).toEqual([["BANK_ACCOUNT", "4111111111111111"]]);
  });
});

describe("phone and MoMo numbers", () => {
  it.each([
    ["Call +250788123456 now", "+250788123456"],
    ["Tel: 0788 123 456", "0788 123 456"],
    ["078-812-3456", "078-812-3456"],
    ["0788.123.456", "0788.123.456"],
    ["250788123456", "250788123456"],
    ["+250 (0) 788 123 456", "+250 (0) 788 123 456"],
    ["00250 788 123 456", "00250 788 123 456"],
    ["MoMo: 0791234567", "0791234567"],
    ["Airtel Money 0731234567", "0731234567"],
    ["Ohereza kuri *182*1*1*0788123456*5000#", "0788123456"],
    ["landline 0252 584 562", "0252 584 562"],
    ["UK office +44 20 7946 0958", "+44 20 7946 0958"],
    ["phone_0788123456_end", "0788123456"],
  ])("finds the number in %j", (text, expected) => {
    expect(found(text)).toContainEqual(["PHONE", expected]);
  });

  it("catches +250 numbers written with brackets", () => {
    const result = found("(+250) 788 123 456");
    expect(result).toHaveLength(1);
    expect(result[0]![0]).toBe("PHONE");
    expect(result[0]![1]).toContain("788 123 456");
  });
});

describe("email addresses", () => {
  it.each([
    ["email jean.mugisha@example.rw.", "jean.mugisha@example.rw"],
    ["contact: A.B+tag@mail.co.rw, thanks", "A.B+tag@mail.co.rw"],
    ["<uwase_k@kris.studio>", "uwase_k@kris.studio"],
    ["mailto:info@bk.rw?subject=x", "info@bk.rw"],
  ])("finds the email in %j", (text, expected) => {
    expect(found(text)).toContainEqual(["EMAIL", expected]);
  });

  it("ignores things that only look a bit like emails", () => {
    expect(found("not an email: a@b")).toEqual([]);
    expect(found("price @ 500 each")).toEqual([]);
  });
});

describe("TIN numbers", () => {
  it.each([
    ["TIN: 102345678", "102345678"],
    ["TIN 102 345 678", "102 345 678"],
    ["T.I.N. 102345678", "102345678"],
    ["Nimero iranga usora (TIN) ni 102345678", "102345678"],
    ["NIF 123456789", "123456789"],
    ["Tax identification number: 102345678", "102345678"],
    ["VAT number 102345678", "102345678"],
  ])("finds the TIN in %j", (text, expected) => {
    expect(found(text)).toContainEqual(["TIN", expected]);
  });

  it("does not treat a bare 9-digit number as a TIN", () => {
    expect(found("amount 150000000 RWF")).toEqual([]);
    expect(found("VAT 18% = 150000000")).toEqual([]);
    expect(found("a tin roof costs 5")).toEqual([]);
  });
});

describe("bank account numbers", () => {
  it.each([
    ["konti ya BK 100012345678", "100012345678"],
    ["A/C 00040-06945754-07", "00040-06945754-07"],
    ["account number 4002 1234 5678 90", "4002 1234 5678 90"],
    ["Compte Equity: 4002123456789", "4002123456789"],
    ["IBAN GB82 WEST 1234 5698 7654 32", "GB82 WEST 1234 5698 7654 32"],
    ["pay to 00040-06945754-07 today", "00040-06945754-07"],
    ["order 12345678901234", "12345678901234"],
  ])("finds the account in %j", (text, expected) => {
    expect(found(text)).toContainEqual(["BANK_ACCOUNT", expected]);
  });

  it("does not mistake dates or amounts for accounts", () => {
    expect(found("Bank transfer on 2021-03-12 14:30")).toEqual([]);
    expect(found("bank balance 150000000")).toEqual([]);
    expect(found("account credited 250000000 RWF")).toEqual([]);
    expect(found("invoice 2024-11-16 total 1,250,000")).toEqual([]);
  });

  it("rejects an IBAN-shaped string with a wrong checksum", () => {
    expect(found("code GB00 WEST 1234 5698 7654 32")).toEqual([]);
  });
});

describe("names from the client's list", () => {
  it("matches whatever the capitals, accents or spacing", () => {
    expect(found("Mwaramutse Mugisha Jean, na UWASE bazaza ejo")).toEqual([
      ["NAME", "Mugisha Jean"],
      ["NAME", "UWASE"],
    ]);
    expect(found("Jean Pierre Habimana and aime")).toEqual([
      ["NAME", "Jean Pierre Habimana"],
      ["NAME", "aime"],
    ]);
    expect(found("jean-pierre  habimana")).toEqual([["NAME", "jean-pierre  habimana"]]);
  });

  it("matches whole words only", () => {
    expect(found("Mukauwase ntabwo ari Uwase's sister")).toEqual([["NAME", "Uwase"]]);
    expect(found("Uwasenga")).toEqual([]);
  });

  it("does not hide names that are not on the list", () => {
    expect(found("Kalisa yahamagaye")).toEqual([]);
  });

  it("an empty list finds nothing", () => {
    expect(createNameDetector([])("Mugisha Jean")).toEqual([]);
  });
});

describe("mixed Kinyarwanda and English text", () => {
  it("finds every kind of data in one passage", () => {
    const text =
      "Mwaramutse! Umukiriya Mugisha Jean (indangamuntu 1 1990 8 0012345 0 67) yahamagaye kuri 0788 123 456. " +
      "Please send the invoice to jean.mugisha@example.rw. TIN ye ni 102345678, " +
      "kandi yishyura kuri konti ya BK 00040-06945754-07. Murakoze cyane.";
    const result = found(text);
    expect(result).toEqual([
      ["NAME", "Mugisha Jean"],
      ["NATIONAL_ID", "1 1990 8 0012345 0 67"],
      ["PHONE", "0788 123 456"],
      ["EMAIL", "jean.mugisha@example.rw"],
      ["TIN", "102345678"],
      ["BANK_ACCOUNT", "00040-06945754-07"],
    ]);
  });
});

describe("ordinary business text is left alone", () => {
  it.each([
    "Our Q3 revenue grew 12% to 4,500,000 RWF across 3 branches.",
    "Meeting moved to 14:30 on 2026-11-20 in room 204.",
    "Order #48213 ships in 5 days. Version 2.10.3 is out.",
    "Umusaruro wiyongereyeho 15% muri uyu mwaka wa 2026.",
    "The price is 0.788123456 per unit.",
  ])("%j", (text) => {
    expect(found(text)).toEqual([]);
  });
});

describe("combining detectors", () => {
  it("ignores our own placeholders, even if a listed name appears inside one", () => {
    const tricky = createNameDetector(["Phone", "KG"]);
    const text = "see [[KG-PHONE-ABCDEFGHIJKLMNOP]] and call 0788123456";
    const result = detectAll(text, [...BUILT_IN_DETECTORS, tricky]);
    expect(result.map((m) => text.slice(m.start, m.end))).toEqual(["0788123456"]);
  });

  it("merges overlapping findings so nothing is left half-hidden", () => {
    // "account" makes the whole run a bank account; the first part also looks like a phone number.
    const text = "account 0788 123 456 7890";
    const result = detectAll(text, detectors);
    expect(result).toHaveLength(1);
    expect(text.slice(result[0]!.start, result[0]!.end)).toBe("0788 123 456 7890");
  });

  it("stays fast on a large hostile input", () => {
    const hostile = `${"0".repeat(50_000)} ${"a@".repeat(20_000)} ${"1 ".repeat(30_000)} ${"[".repeat(20_000)}`;
    const start = performance.now();
    detectAll(hostile, detectors);
    expect(performance.now() - start).toBeLessThan(2000);
  });
});
