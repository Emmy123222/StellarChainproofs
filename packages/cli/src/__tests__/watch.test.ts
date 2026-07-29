import { createDebouncer, formatWatchSummary } from "../commands/watch";
import type { ScanResult } from "@chainproof/core";

describe("watch debouncer", () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("collapses rapid successive saves into one invocation", () => {
    const fn = jest.fn();
    const debouncer = createDebouncer(300, fn);

    debouncer.schedule("a");
    debouncer.schedule("b");
    debouncer.schedule("c");

    expect(fn).not.toHaveBeenCalled();

    jest.advanceTimersByTime(299);
    expect(fn).not.toHaveBeenCalled();

    jest.advanceTimersByTime(1);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("flush runs pending work immediately", () => {
    const fn = jest.fn();
    const debouncer = createDebouncer(300, fn);

    debouncer.schedule("change");
    debouncer.flush();

    expect(fn).toHaveBeenCalledTimes(1);
  });
});

describe("formatWatchSummary", () => {
  it("includes severity counts and recent findings", () => {
    const result: ScanResult = {
      version: "0.1.0",
      timestamp: "2026-01-01T00:00:00.000Z",
      files: [
        {
          file: "contracts/Vault.sol",
          findings: [
            {
              id: "CP-107",
              title: "Reentrancy",
              description: "d",
              recommendation: "r",
              severity: "high",
              file: "contracts/Vault.sol",
              line: 12,
            },
          ],
          gasHints: [],
          slitherRan: false,
        },
      ],
      summary: {
        critical: 0,
        high: 1,
        medium: 0,
        low: 0,
        info: 0,
        gas: 0,
        total: 1,
      },
    };

    const output = formatWatchSummary(result, {
      targets: ["contracts/"],
      cacheStats: { hits: 3, misses: 1 },
      rescannedFiles: ["contracts/Vault.sol"],
    });

    expect(output).toContain("High");
    expect(output).toContain("Reentrancy");
    expect(output).toContain("3 hit(s), 1 miss(es)");
  });
});
