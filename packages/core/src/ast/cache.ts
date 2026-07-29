import { createHash } from "crypto";
import type { ASTNode } from "../types";

export interface ASTCacheEntry {
  contentHash: string;
  ast: ASTNode;
  parsedAt: number;
  filePath: string;
}

/**
 * LRU cache for parsed Solidity ASTs, keyed by SHA-256 of file content.
 * Unchanged files return their cached AST instantly, skipping the parser.
 */
export interface ASTCacheStats {
  hits: number;
  misses: number;
}

export class ASTCache {
  private readonly maxSize: number;
  // Map insertion order = LRU order; oldest key is first.
  private readonly cache = new Map<string, ASTCacheEntry>();
  private hits = 0;
  private misses = 0;

  constructor(maxSize = 200) {
    this.maxSize = maxSize;
  }

  static hashContent(content: string): string {
    return createHash("sha256").update(content).digest("hex");
  }

  get(hash: string): ASTCacheEntry | undefined {
    const entry = this.cache.get(hash);
    if (!entry) {
      this.misses++;
      return undefined;
    }
    this.hits++;
    // Bump to most-recently-used position.
    this.cache.delete(hash);
    this.cache.set(hash, entry);
    return entry;
  }

  resetStats(): void {
    this.hits = 0;
    this.misses = 0;
  }

  getStats(): ASTCacheStats {
    return { hits: this.hits, misses: this.misses };
  }

  set(hash: string, entry: ASTCacheEntry): void {
    if (this.cache.has(hash)) {
      this.cache.delete(hash);
    } else if (this.cache.size >= this.maxSize) {
      // Evict least-recently-used (first key in insertion order).
      const lruKey = this.cache.keys().next().value;
      if (lruKey !== undefined) this.cache.delete(lruKey);
    }
    this.cache.set(hash, entry);
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }

  /** Serialize entries for cross-session persistence (e.g. VS Code globalStorageUri). */
  serialize(): ASTCacheEntry[] {
    return [...this.cache.values()];
  }

  /** Restore cache from a previously serialized snapshot. */
  hydrate(entries: ASTCacheEntry[]): void {
    this.clear();
    for (const entry of entries) {
      this.set(entry.contentHash, entry);
    }
  }
}

export const astCache = new ASTCache();

/** Remove all cached ASTs. Useful after a full workspace clean. */
export function clearCache(): void {
  astCache.clear();
}

/** Reset hit/miss counters on the shared AST cache singleton. */
export function resetCacheStats(): void {
  astCache.resetStats();
}

/** Read current hit/miss counters from the shared AST cache singleton. */
export function getCacheStats(): ASTCacheStats {
  return astCache.getStats();
}
