import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { buildImportGraph, computeRescanSet } from "../ast/import-graph";

describe("computeRescanSet", () => {
  const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-rescan-"));

  const shared = path.join(fixtureDir, "Shared.sol");
  const importerA = path.join(fixtureDir, "ImporterA.sol");
  const importerB = path.join(fixtureDir, "ImporterB.sol");
  const unrelated = path.join(fixtureDir, "Unrelated.sol");

  beforeAll(() => {
    fs.writeFileSync(
      shared,
      `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Shared { uint256 public value; }`,
      "utf-8"
    );
    fs.writeFileSync(
      importerA,
      `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./Shared.sol";
contract ImporterA is Shared {}`,
      "utf-8"
    );
    fs.writeFileSync(
      importerB,
      `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./Shared.sol";
contract ImporterB is Shared {}`,
      "utf-8"
    );
    fs.writeFileSync(
      unrelated,
      `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Unrelated { uint256 public x; }`,
      "utf-8"
    );
  });

  afterAll(() => {
    fs.rmSync(fixtureDir, { recursive: true, force: true });
  });

  it("includes changed file and both direct importers", () => {
    const graph = buildImportGraph([shared, importerA, importerB, unrelated]);
    const rescan = computeRescanSet([shared], graph);

    expect(rescan.has(path.resolve(shared))).toBe(true);
    expect(rescan.has(path.resolve(importerA))).toBe(true);
    expect(rescan.has(path.resolve(importerB))).toBe(true);
    expect(rescan.has(path.resolve(unrelated))).toBe(false);
  });

  it("includes imported dependencies of the changed file", () => {
    const graph = buildImportGraph([importerA, shared]);
    const rescan = computeRescanSet([importerA], graph);

    expect(rescan.has(path.resolve(importerA))).toBe(true);
    expect(rescan.has(path.resolve(shared))).toBe(true);
  });
});
