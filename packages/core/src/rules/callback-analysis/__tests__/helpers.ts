import * as path from "path";
import { buildImportGraph, buildMergedContractViews } from "../../../ast/import-graph";
import type { MergedContractView } from "../../../ast/import-graph";
import { detectCallbackReentrancy } from "../rule";
import type { Finding } from "../../../types";

export const FIXTURES_DIR = path.resolve(__dirname, "../../../../../../examples/contracts/callbacks");

export function buildViewsForFixture(fileName: string): { views: MergedContractView[]; filePath: string } {
  const filePath = path.join(FIXTURES_DIR, fileName);
  const graph = buildImportGraph([filePath]);
  const views = buildMergedContractViews(graph);
  return { views, filePath };
}

export function findViewByContractName(views: MergedContractView[], name: string): MergedContractView {
  const view = views.find((v) => v.name === name);
  if (!view) {
    throw new Error(
      `contract "${name}" not found; available contracts: ${views.map((v) => v.name).join(", ")}`,
    );
  }
  return view;
}

export function viewFromFixture(fileName: string, contractName: string): MergedContractView {
  const { views } = buildViewsForFixture(fileName);
  return findViewByContractName(views, contractName);
}

export function detectInFixture(fileName: string, contractName: string): Finding[] {
  const view = viewFromFixture(fileName, contractName);
  return detectCallbackReentrancy(view.node, view.source, view.file, { contractView: view });
}
