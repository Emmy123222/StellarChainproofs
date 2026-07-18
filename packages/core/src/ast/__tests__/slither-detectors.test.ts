import { DETECTOR_MAP, getDetectorInfo } from "../slither-detectors";

describe("DETECTOR_MAP", () => {
  it("has comprehensive coverage of Slither's major detectors", () => {
    expect(Object.keys(DETECTOR_MAP).length).toBeGreaterThanOrEqual(90);
  });

  it("every entry has a category and a title", () => {
    for (const [check, info] of Object.entries(DETECTOR_MAP)) {
      expect([check, info.category]).toEqual([check, expect.any(String)]);
      expect([check, info.title]).toEqual([check, expect.any(String)]);
      expect(info.category.length).toBeGreaterThan(0);
      expect(info.title.length).toBeGreaterThan(0);
    }
  });

  it("maps reentrancy detectors onto the built-in CP-107 category", () => {
    expect(DETECTOR_MAP["reentrancy-eth"].category).toBe("CP-107");
    expect(DETECTOR_MAP["reentrancy-no-eth"].category).toBe("CP-107");
    expect(DETECTOR_MAP["reentrancy-eth"].swcId).toBe("SWC-107");
  });

  it("maps tx-origin onto the built-in CP-115 category", () => {
    expect(DETECTOR_MAP["tx-origin"].category).toBe("CP-115");
  });

  it("maps unprotected-upgrade onto the built-in CP-116 category", () => {
    expect(DETECTOR_MAP["unprotected-upgrade"].category).toBe("CP-116");
  });
});

describe("getDetectorInfo", () => {
  it("looks up a known detector", () => {
    expect(getDetectorInfo("arbitrary-send-eth")?.category).toBe(
      "CP-SL-ARBITRARY-SEND-ETH",
    );
  });

  it("is case-insensitive", () => {
    expect(getDetectorInfo("ARBITRARY-SEND-ETH")?.category).toBe(
      "CP-SL-ARBITRARY-SEND-ETH",
    );
  });

  it("returns undefined for an unknown detector", () => {
    expect(getDetectorInfo("not-a-real-detector")).toBeUndefined();
  });
});
