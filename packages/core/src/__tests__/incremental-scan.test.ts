import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { clearCache, resetCacheStats, getCacheStats } from "../ast/cache";
import {
  createWatchScanState,
  scanIncremental,
} from "../scanner";

describe("scanIncremental", () => {
  const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-incr-"));

  const shared = path.join(fixtureDir, "Shared.sol");
  const importerA = path.join(fixtureDir, "ImporterA.sol");
  const importerB = path.join(fixtureDir, "ImporterB.sol");
  const unrelated = path.join(fixtureDir, "Unrelated.sol");

  const scanConfig = {
    targets: [fixtureDir],
    useSlither: false,
    useLLM: false,
    useMetrics: false,
  };

  beforeAll(() => {
    writeFixture();
  });

  afterEach(() => {
    clearCache();
    writeFixture();
  });

  afterAll(() => {
    fs.rmSync(fixtureDir, { recursive: true, force: true });
  });

  function writeFixture() {
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
  }

  it("re-scans only changed file and direct dependents", async () => {
    const state = await createWatchScanState(scanConfig);

    fs.writeFileSync(
      shared,
      `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Shared { uint256 public value; uint256 public updated; }`,
      "utf-8"
    );

    resetCacheStats();
    const outcome = await scanIncremental(scanConfig, state, [shared]);
    const rescanned = outcome.rescannedFiles.map((f) => path.resolve(f));

    expect(rescanned).toContain(path.resolve(shared));
    expect(rescanned).toContain(path.resolve(importerA));
    expect(rescanned).toContain(path.resolve(importerB));
    expect(rescanned).not.toContain(path.resolve(unrelated));
  });

  it("uses AST cache hits for unchanged files during incremental re-scan", async () => {
    const state = await createWatchScanState(scanConfig);

    fs.writeFileSync(
      shared,
      `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Shared { uint256 public value; uint256 public touched; }`,
      "utf-8"
    );

    resetCacheStats();
    await scanIncremental(scanConfig, state, [shared]);
    const stats = getCacheStats();

    expect(stats.misses).toBeGreaterThanOrEqual(1);
    expect(stats.hits).toBeGreaterThanOrEqual(2);
  });
});
