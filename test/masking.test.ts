/**
 * Hiding and restoring: placeholders, the masker, and streamed restoring.
 */
import { describe, expect, it } from "vitest";
import { BUILT_IN_DETECTORS } from "../src/pii/detect.js";
import { createNameDetector } from "../src/pii/detectors/names.js";
import { Masker, ResidualPiiError } from "../src/pii/masker.js";
import { PLACEHOLDER_RE, PlaceholderMap, countPlaceholders } from "../src/pii/placeholders.js";
import { StreamRestorer } from "../src/pii/stream-restorer.js";
import type { Detector } from "../src/pii/types.js";
import { ALL_SAMPLE_VALUES, SAMPLE } from "./helpers/gateway.js";

const detectors = [...BUILT_IN_DETECTORS, createNameDetector([SAMPLE.name])];
const newMasker = (requestText = "") => new Masker(detectors, { kind: "random" }, requestText);

const PASSAGE =
  `Umukiriya ${SAMPLE.name} (ID ${SAMPLE.idSpaced}) yahamagaye kuri ${SAMPLE.phoneLocal}. ` +
  `Email: ${SAMPLE.email}, TIN: ${SAMPLE.tin}, konti ${SAMPLE.account}, MoMo ${SAMPLE.momo}.`;

describe("masking a text", () => {
  it("hides every kind of personal data and can restore all of it", () => {
    const masker = newMasker();
    const masked = masker.mask(PASSAGE);

    for (const value of [SAMPLE.name, SAMPLE.idSpaced, SAMPLE.phoneLocal, SAMPLE.email, SAMPLE.tin, SAMPLE.account, SAMPLE.momo]) {
      expect(masked).not.toContain(value);
    }
    expect(countPlaceholders(masked)).toBe(7);
    expect(masker.hidden).toEqual({ NAME: 1, NATIONAL_ID: 1, PHONE: 2, EMAIL: 1, TIN: 1, BANK_ACCOUNT: 1 });
    expect(masker.restore(masked)).toBe(PASSAGE);
  });

  it("leaves text without personal data exactly as it was", () => {
    const text = "Raporo y'ukwezi: sales grew 12% to 4,500,000 RWF.";
    expect(newMasker().mask(text)).toBe(text);
  });

  it("gives the same value the same placeholder within one request", () => {
    const masker = newMasker();
    const a = masker.mask(`call ${SAMPLE.phone}`);
    const b = masker.mask(`again ${SAMPLE.phone}`);
    expect(a.match(PLACEHOLDER_RE)![0]).toBe(b.match(PLACEHOLDER_RE)![0]);
  });

  it("gives a different placeholder in a different request (random mode)", () => {
    const a = newMasker().mask(SAMPLE.phone);
    const b = newMasker().mask(SAMPLE.phone);
    expect(a).not.toBe(b);
  });

  it("keeps the exact way a value was written", () => {
    const masker = newMasker();
    const text = "0788 123 456 and 0788123456 and 0788-123-456";
    const masked = masker.mask(text);
    expect(countPlaceholders(masked)).toBe(3);
    expect(masker.restore(masked)).toBe(text);
  });

  it("refuses to continue if something is still detectable after masking", () => {
    // A faulty detector that only ever reports the FIRST secret it sees. After
    // masking, the second one is still there. The masker must notice and refuse.
    const faulty: Detector = (text) => {
      const i = text.indexOf("SECRET");
      return i >= 0 ? [{ type: "PHONE", start: i, end: i + 6, priority: 1 }] : [];
    };
    const leaky = new Masker([faulty], { kind: "random" }, "");
    expect(() => leaky.mask("SECRET and SECRET")).toThrow(ResidualPiiError);
  });
});

describe("placeholders", () => {
  it("contain no digits and nothing a detector would react to", () => {
    const masker = newMasker();
    const masked = masker.mask(PASSAGE);
    for (const ph of masked.match(PLACEHOLDER_RE)!) {
      expect(ph).toMatch(/^\[\[KG-[A-Z]+-[A-Z]{16}\]\]$/);
      expect(masker.find(ph)).toEqual([]);
    }
  });

  it("never reuse text that is already in the request", () => {
    // The request already contains placeholder-shaped text. New placeholders must differ from it.
    const existing = "[[KG-PHONE-AAAAAAAAAAAAAAAA]]";
    const masker = newMasker(`history: ${existing}`);
    const masked = masker.mask(`history: ${existing} new: ${SAMPLE.phone}`);
    const all = masked.match(PLACEHOLDER_RE)!;
    expect(all).toHaveLength(2);
    expect(all[0]).toBe(existing);
    expect(all[1]).not.toBe(existing);
    // The one we did not create is left exactly as it is.
    expect(masker.restore(masked)).toBe(`history: ${existing} new: ${SAMPLE.phone}`);
  });

  it("stable mode: same value, same placeholder, every request, but different per client", () => {
    const keyA = Buffer.alloc(32, 1);
    const keyB = Buffer.alloc(32, 2);
    const one = new PlaceholderMap({ kind: "stable", key: keyA }, "").placeholderFor("PHONE", SAMPLE.phone);
    const two = new PlaceholderMap({ kind: "stable", key: keyA }, "").placeholderFor("PHONE", SAMPLE.phone);
    const other = new PlaceholderMap({ kind: "stable", key: keyB }, "").placeholderFor("PHONE", SAMPLE.phone);
    expect(one).toBe(two);
    expect(one).not.toBe(other);
    expect(one).toMatch(/^\[\[KG-PHONE-[A-Z]{16}\]\]$/);
  });
});

describe("restoring when the AI damaged a placeholder", () => {
  const masker = newMasker();
  const masked = masker.mask(`call ${SAMPLE.phone}`);
  const ph = masked.match(PLACEHOLDER_RE)![0];

  it.each([
    ["a bracket dropped", ph.slice(1)],
    ["a letter changed", ph.replace(/[A-Z]\]\]$/, (m) => (m[0] === "X" ? "Y]]" : "X]]"))],
    ["lower-cased", ph.toLowerCase()],
    ["a space inserted", ph.replace("-PHONE-", "- PHONE -")],
    ["the wrong kind", ph.replace("PHONE", "EMAIL")],
  ])("%s: stays hidden, nothing is guessed", (_label, damaged) => {
    const answer = `Your number is ${damaged}.`;
    const restored = masker.restore(answer);
    expect(restored).toBe(answer);
    expect(restored).not.toContain(SAMPLE.phone);
  });

  it("a placeholder from another request restores nothing", () => {
    const other = newMasker();
    const foreign = other.mask(`call ${SAMPLE.email}`).match(PLACEHOLDER_RE)![0];
    expect(masker.restore(`leak ${foreign}`)).toBe(`leak ${foreign}`);
  });
});

describe("restoring a streamed answer", () => {
  it("gives the same result however the text is cut into pieces", () => {
    const masker = newMasker();
    const masked = masker.mask(PASSAGE) + " [not a placeholder] [[KG-nope and [[ trailing";
    const expected = masker.restore(masked);
    const known = masker.map.placeholders();

    // Every possible single cut...
    for (let cut = 0; cut <= masked.length; cut++) {
      const r = new StreamRestorer(masker.map, known);
      const out = r.push(masked.slice(0, cut)) + r.push(masked.slice(cut)) + r.flush();
      expect(out).toBe(expected);
    }
    // ...and every fixed piece size from 1 character up.
    for (let size = 1; size <= 40; size++) {
      const r = new StreamRestorer(masker.map, known);
      let out = "";
      for (let i = 0; i < masked.length; i += size) out += r.push(masked.slice(i, i + size));
      out += r.flush();
      expect(out).toBe(expected);
    }
  });

  it("never lets part of a placeholder out early", () => {
    const masker = newMasker();
    const masked = masker.mask(`call ${SAMPLE.phone} now`);
    const r = new StreamRestorer(masker.map, masker.map.placeholders());
    let seen = "";
    for (const ch of masked) {
      seen += r.push(ch);
      expect(seen).not.toContain("[[KG");
    }
    seen += r.flush();
    expect(seen).toBe(`call ${SAMPLE.phone} now`);
  });

  it("does not hold back ordinary text that merely starts like a placeholder", () => {
    const masker = newMasker();
    masker.mask(SAMPLE.phone);
    const r = new StreamRestorer(masker.map, masker.map.placeholders());
    // "[[KG-ZZZ" cannot become any placeholder this request created, so it flows straight through.
    expect(r.push("see [[KG-ZZZ")).toBe("see [[KG-ZZZ");
  });

  it("a damaged placeholder cut across pieces is released unchanged", () => {
    const masker = newMasker();
    const ph = masker.mask(SAMPLE.phone);
    const damaged = ph.slice(0, -3) + "!]]";
    const r = new StreamRestorer(masker.map, masker.map.placeholders());
    const out = r.push(damaged.slice(0, 12)) + r.push(damaged.slice(12)) + r.flush();
    expect(out).toBe(damaged);
  });

  it("escapes restored values inside streamed JSON", () => {
    // A listed name containing a quote must not break the JSON of a tool call.
    const quoteName = 'Jean "JP" Habimana';
    const m = new Masker([createNameDetector([quoteName])], { kind: "random" }, "");
    const masked = m.mask(quoteName);
    const json = JSON.stringify({ to: masked });
    const r = new StreamRestorer(m.map, m.map.placeholders(), true);
    let out = "";
    for (let i = 0; i < json.length; i += 4) out += r.push(json.slice(i, i + 4));
    out += r.flush();
    expect(JSON.parse(out)).toEqual({ to: quoteName });
  });

  it("holds nothing back when the request had no personal data", () => {
    const masker = newMasker();
    const r = new StreamRestorer(masker.map, masker.map.placeholders());
    expect(r.push("text with [[ brackets")).toBe("text with [[ brackets");
  });
});

describe("sample data sanity", () => {
  it("every sample value is detected by the masker", () => {
    for (const value of ALL_SAMPLE_VALUES) {
      const context = value === SAMPLE.tin ? `TIN ${value}` : value;
      expect(newMasker().mask(context)).not.toContain(value);
    }
  });
});
