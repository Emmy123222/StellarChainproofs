import { ASTCache, clearCache, astCache } from "../cache";
import type { ASTNode } from "../../types";

function makeEntry(filePath: string, content: string): { hash: string; entry: import("../cache").ASTCacheEntry } {
  const hash = ASTCache.hashContent(content);
  return {
    hash,
    entry: {
      contentHash: hash,
      ast: { type: "SourceUnit", children: [] } as unknown as ASTNode,
      parsedAt: Date.now(),
      filePath,
    },
  };
}

describe("ASTCache", () => {
  afterEach(() => clearCache());

  test("returns undefined on cache miss", () => {
    const cache = new ASTCache();
    expect(cache.get("nonexistent")).toBeUndefined();
  });

  test("returns entry on cache hit", () => {
    const cache = new ASTCache();
    const { hash, entry } = makeEntry("Foo.sol", "contract Foo {}");
    cache.set(hash, entry);
    expect(cache.get(hash)).toEqual(entry);
  });

  test("size reflects stored entries", () => {
    const cache = new ASTCache();
    expect(cache.size).toBe(0);
    const { hash, entry } = makeEntry("A.sol", "contract A {}");
    cache.set(hash, entry);
    expect(cache.size).toBe(1);
  });

  test("clear removes all entries", () => {
    const cache = new ASTCache();
    const { hash, entry } = makeEntry("B.sol", "contract B {}");
    cache.set(hash, entry);
    cache.clear();
    expect(cache.size).toBe(0);
    expect(cache.get(hash)).toBeUndefined();
  });

  test("LRU eviction removes oldest entry when maxSize is reached", () => {
    const cache = new ASTCache(3);
    const a = makeEntry("A.sol", "contract A {}");
    const b = makeEntry("B.sol", "contract B {}");
    const c = makeEntry("C.sol", "contract C {}");
    const d = makeEntry("D.sol", "contract D {}");

    cache.set(a.hash, a.entry);
    cache.set(b.hash, b.entry);
    cache.set(c.hash, c.entry);
    // Adding a 4th entry should evict 'a' (LRU)
    cache.set(d.hash, d.entry);

    expect(cache.size).toBe(3);
    expect(cache.get(a.hash)).toBeUndefined();
    expect(cache.get(b.hash)).toBeDefined();
    expect(cache.get(c.hash)).toBeDefined();
    expect(cache.get(d.hash)).toBeDefined();
  });

  test("get promotes entry to most-recently-used", () => {
    const cache = new ASTCache(2);
    const a = makeEntry("A.sol", "contract A {}");
    const b = makeEntry("B.sol", "contract B {}");
    const c = makeEntry("C.sol", "contract C {}");

    cache.set(a.hash, a.entry);
    cache.set(b.hash, b.entry);
    // Access 'a' to make it recently used
    cache.get(a.hash);
    // Adding 'c' should evict 'b' (now LRU), not 'a'
    cache.set(c.hash, c.entry);

    expect(cache.get(a.hash)).toBeDefined();
    expect(cache.get(b.hash)).toBeUndefined();
    expect(cache.get(c.hash)).toBeDefined();
  });

  test("serialize returns all entries", () => {
    const cache = new ASTCache();
    const { hash, entry } = makeEntry("X.sol", "contract X {}");
    cache.set(hash, entry);
    const serialized = cache.serialize();
    expect(serialized).toHaveLength(1);
    expect(serialized[0].contentHash).toBe(hash);
  });

  test("hydrate restores entries from snapshot", () => {
    const cache = new ASTCache();
    const { hash, entry } = makeEntry("Y.sol", "contract Y {}");
    cache.hydrate([entry]);
    expect(cache.get(hash)).toEqual(entry);
  });

  test("hashContent produces consistent SHA-256 hex string", () => {
    const h1 = ASTCache.hashContent("contract Foo {}");
    const h2 = ASTCache.hashContent("contract Foo {}");
    const h3 = ASTCache.hashContent("contract Bar {}");
    expect(h1).toBe(h2);
    expect(h1).not.toBe(h3);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  test("clearCache() resets the shared singleton", () => {
    const { hash, entry } = makeEntry("Z.sol", "contract Z {}");
    astCache.set(hash, entry);
    expect(astCache.size).toBeGreaterThan(0);
    clearCache();
    expect(astCache.size).toBe(0);
  });
});
