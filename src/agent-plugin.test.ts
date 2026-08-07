// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/**
 * Agent Plugins 1.0 packaging and launch-contract tests.
 *
 * These assertions intentionally mirror the closed 1.0.0 schemas. They remain
 * offline and deterministic while protecting the security-sensitive launch
 * defaults that a plugin client will execute.
 */
import { execSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
const MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json";
const PINNED_PACKAGE = "@microsoft/spe-mcp@0.2.0-alpha.1";
const PLUGIN_KEYS = new Set([
  "$schema",
  "name",
  "version",
  "description",
  "author",
  "homepage",
  "repository",
  "license",
  "keywords",
  "extensions",
]);
const STDIO_KEYS = new Set(["type", "command", "args", "env", "cwd"]);

interface PluginManifest {
  [key: string]: unknown;
  $schema: string;
  name: string;
  version: string;
  author: Record<string, string>;
}

interface StdioServerConfig {
  [key: string]: unknown;
  type: string;
  command: string;
  args: string[];
}

interface McpManifest {
  [key: string]: unknown;
  $schema: string;
  mcpServers: Record<string, StdioServerConfig>;
}

interface PackageManifest {
  version: string;
  files: string[];
}

interface PackageLock {
  version: string;
  packages: Record<string, { version: string }>;
}

function readJson<T>(relativePath: string): T {
  return JSON.parse(readFileSync(join(REPO_ROOT, relativePath), "utf8")) as T;
}

const plugin = readJson<PluginManifest>("plugin.json");
const mcp = readJson<McpManifest>("mcp.json");
const pkg = readJson<PackageManifest>("package.json");
const lock = readJson<PackageLock>("package-lock.json");
const server = mcp.mcpServers?.["sharepoint-embedded"];

describe("Agent Plugins 1.0 manifest schema", () => {
  it("uses the canonical closed plugin.json schema", () => {
    expect(plugin.$schema).toBe(PLUGIN_SCHEMA);
    expect(Object.keys(plugin).filter((key) => !PLUGIN_KEYS.has(key))).toEqual([]);
    expect(plugin.name).toMatch(/^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/);
    expect(plugin.name.length).toBeLessThanOrEqual(64);
    expect(plugin.version).toBe(pkg.version);
    expect(plugin.author).toEqual(
      expect.objectContaining({ name: expect.any(String) }),
    );
    expect(Object.keys(plugin.author).every((key) => ["name", "email", "url"].includes(key))).toBe(true);
  });

  it("uses the canonical closed mcp.json stdio schema", () => {
    expect(Object.keys(mcp).sort()).toEqual(["$schema", "mcpServers"]);
    expect(mcp.$schema).toBe(MCP_SCHEMA);
    expect(Object.keys(mcp.mcpServers)).toEqual(["sharepoint-embedded"]);
    expect(Object.keys(server).filter((key) => !STDIO_KEYS.has(key))).toEqual([]);
    expect(server.type).toBe("stdio");
    expect(server.command).toBe("npx");
    expect(server.args).toEqual(expect.arrayContaining(["${PLUGIN_DATA}"]));
    expect(server).not.toHaveProperty("url");
    expect(server).not.toHaveProperty("headers");
  });
});

describe("Agent Plugins 1.0 packaging contract", () => {
  it("ships both manifests and the dedicated documentation", () => {
    for (const file of ["plugin.json", "mcp.json", "docs/AGENT-PLUGIN.md"]) {
      expect(pkg.files).toContain(file);
      expect(existsSync(join(REPO_ROOT, file))).toBe(true);
    }
  });

  it("pins the verified published server version without a range or tag", () => {
    expect(server.args).toEqual([
      "-y",
      PINNED_PACKAGE,
      "start",
      "--read-only",
      "--data-dir",
      "${PLUGIN_DATA}",
    ]);
    expect(PINNED_PACKAGE).toBe(`@microsoft/spe-mcp@${pkg.version}`);
    expect(lock.version).toBe(pkg.version);
    expect(lock.packages[""].version).toBe(pkg.version);
  });

  it("is MCP-only with a read-only local stdio default and persistent state", () => {
    expect(server.type).toBe("stdio");
    expect(server.args).toContain("--read-only");
    expect(server.args.slice(server.args.indexOf("--data-dir"))).toEqual([
      "--data-dir",
      "${PLUGIN_DATA}",
    ]);
    expect(plugin).not.toHaveProperty("skills");
    expect(plugin).not.toHaveProperty("agents");
    expect(plugin).not.toHaveProperty("hooks");
    expect(plugin).not.toHaveProperty("oauth");
  });
});

describe("Agent Plugins 1.0 local stdio launch", () => {
  let client: Client;
  let transport: StdioClientTransport;
  let pluginData: string;

  beforeAll(async () => {
    const cliEntry = join(REPO_ROOT, "dist", "cli.js");
    if (!existsSync(cliEntry)) {
      execSync("npm run build", { cwd: REPO_ROOT, stdio: "ignore" });
    }

    pluginData = mkdtempSync(join(tmpdir(), "spe-agent-plugin-data-"));
    const launchArgs = server.args
      .slice(2)
      .map((arg: string) => arg.replaceAll("${PLUGIN_DATA}", pluginData));

    transport = new StdioClientTransport({
      command: process.execPath,
      args: [cliEntry, ...launchArgs],
      cwd: REPO_ROOT,
      stderr: "ignore",
    });
    client = new Client({ name: "spe-agent-plugin-contract", version: "1.0.0" }, {});
    await client.connect(transport);
  }, 90000);

  afterAll(async () => {
    await client?.close().catch(() => undefined);
    await transport?.close().catch(() => undefined);
    if (pluginData) rmSync(pluginData, { recursive: true, force: true });
  });

  it("starts over stdio and advertises only read-only tools", async () => {
    expect(client.getServerVersion()?.name).toBe("spe-mcp-server");
    const { tools } = await client.listTools(undefined, { timeout: 8000 });
    expect(tools.length).toBeGreaterThan(0);
    expect(tools.every((tool) => tool.annotations?.readOnlyHint === true)).toBe(true);
    expect(tools.map((tool) => tool.name)).not.toContain("container_delete");
  });
});
