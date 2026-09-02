// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { afterEach, describe, expect, it } from "vitest";
import {
  USER_AGENT,
  __testing,
  applyProductUserAgent,
  appendUserAgent,
  classifyAgentHost,
  configureAzureUserAgentEnvironment,
  getUserAgent,
  isProductUserAgent,
  productUserAgent,
  resolveAgentHostAttribution,
  resolveInstallAttribution,
  setAgentHostAttribution,
  setInstallAttribution,
  telemetryEnabled,
} from "./user-agent.js";

const saved = process.env.SPE_MCP_COLLECT_TELEMETRY;

describe("install attribution User-Agent", () => {
  afterEach(() => {
    __testing.reset();
    if (saved === undefined) {
      delete process.env.SPE_MCP_COLLECT_TELEMETRY;
    } else {
      process.env.SPE_MCP_COLLECT_TELEMETRY = saved;
    }
  });

  it("keeps the historical product-only value when attribution is absent", () => {
    expect(resolveInstallAttribution({})).toBeUndefined();
    expect(getUserAgent()).toBe(USER_AGENT);
  });

  it("adds bounded source, content, and campaign tokens", () => {
    const attribution = resolveInstallAttribution({
      source: "microsoft-learn",
      content: "sharepoint-embedded-mcp-server",
      campaign: "docs-install-buttons",
    });

    setInstallAttribution(attribution);

    expect(getUserAgent()).toBe(
      `${USER_AGENT} spe-install-source/microsoft-learn ` +
        "spe-install-content/sharepoint-embedded-mcp-server " +
        "spe-install-campaign/docs-install-buttons",
    );
  });

  it.each([
    ["Visual Studio Code", "vscode"],
    ["Visual Studio Code - Insiders", "vscode"],
    ["Code - OSS", "vscode"],
    ["Code - OSS Dev", "vscode"],
    ["Cursor", "cursor"],
    ["claude-code", "claude-code"],
    ["Claude Code", "claude-code"],
    ["Claude", "claude-desktop"],
    ["Claude Desktop", "claude-desktop"],
    ["claude-ai", "claude-desktop"],
    ["local-agent-mode-spe", "claude-desktop"],
    ["OpenAI Codex CLI", "codex"],
    ["GitHub Copilot CLI", "github-copilot-cli"],
    ["copilot-cli", "github-copilot-cli"],
    ["github-copilot-developer", "github-copilot-cli"],
    ["Microsoft Visual Studio", "visual-studio"],
    ["Azure AI Foundry", "azure-ai-foundry"],
    ["mcp", "unknown"],
    ["", "unknown"],
    ["Future MCP Host", "other"],
  ])("classifies MCP clientInfo name %j as %s", (clientName, expected) => {
    expect(classifyAgentHost(clientName)).toBe(expected);
  });

  it("adds only the bounded host classification, not raw clientInfo", () => {
    setAgentHostAttribution(classifyAgentHost("Future MCP Host with user text"));
    expect(getUserAgent()).toBe(`${USER_AGENT} spe-agent-host/other`);
    expect(getUserAgent()).not.toContain("future");
  });

  it("omits agent-host attribution when attribution is disabled", () => {
    expect(resolveAgentHostAttribution("Visual Studio Code", false)).toBeUndefined();
  });

  it("normalizes identifiers and rejects unbounded or unsupported values", () => {
    expect(
      resolveInstallAttribution({
        source: " Microsoft-Learn ",
        content: " QuickStart-VSCode ",
      }),
    ).toEqual({ source: "microsoft-learn", content: "quickstart-vscode" });
    expect(() => resolveInstallAttribution({ source: "reddit" })).toThrow(
      /must be one of/i,
    );
    expect(() =>
      resolveInstallAttribution({ source: "microsoft-learn", content: "contains spaces" }),
    ).toThrow(/1-64 character/i);
    expect(() =>
      resolveInstallAttribution({ source: "microsoft-learn", content: "unpublished-doc" }),
    ).toThrow(/must be one of/i);
    expect(() =>
      resolveInstallAttribution({
        source: "microsoft-learn",
        campaign: "unreviewed-campaign",
      }),
    ).toThrow(/must be one of/i);
    expect(() => resolveInstallAttribution({ content: "mcp-server" })).toThrow(
      /require --install-source/i,
    );
  });

  it("honors the explicit opt-out before validating configured values", () => {
    expect(
      resolveInstallAttribution({
        source: "not-supported",
        content: "contains spaces",
        enabled: false,
      }),
    ).toBeUndefined();
  });

  it("preserves an existing Azure CLI User-Agent while avoiding duplicates", () => {
    expect(appendUserAgent(undefined, USER_AGENT)).toBe(USER_AGENT);
    expect(appendUserAgent("caller/1.0", USER_AGENT)).toBe(`caller/1.0 ${USER_AGENT}`);
    expect(appendUserAgent(`caller/1.0 ${USER_AGENT}`, USER_AGENT)).toBe(
      `caller/1.0 ${USER_AGENT}`,
    );
    expect(
      appendUserAgent(
        `caller/1.0 ${USER_AGENT} spe-install-source/microsoft-learn`,
        `${USER_AGENT} spe-install-source/github-readme`,
      ),
    ).toBe(`caller/1.0 ${USER_AGENT} spe-install-source/github-readme`);
  });

  it("configures both az and azd User-Agent environment variables", () => {
    setInstallAttribution(
      resolveInstallAttribution({
        source: "github-readme",
        content: "readme-install",
        campaign: "docs-install-buttons",
      }),
    );
    setAgentHostAttribution("vscode");
    const env: NodeJS.ProcessEnv = {
      AZURE_HTTP_USER_AGENT: "existing-az/1.0",
      AZURE_DEV_USER_AGENT: "existing-azd/1.0",
    };

    configureAzureUserAgentEnvironment(env);

    expect(env.AZURE_HTTP_USER_AGENT).toMatch(
      /^existing-az\/1\.0 spe-mcp-server\/\S+ spe-install-source\/github-readme.*spe-agent-host\/vscode/,
    );
    expect(env.AZURE_DEV_USER_AGENT).toMatch(
      /^existing-azd\/1\.0 spe-mcp-server\/\S+ spe-install-source\/github-readme.*spe-agent-host\/vscode/,
    );
  });

  it("suppresses all attribution tokens on telemetry opt-out", () => {
    setInstallAttribution(
      resolveInstallAttribution({ source: "github-readme", content: "readme-install" }),
    );
    setAgentHostAttribution("vscode");
    process.env.SPE_MCP_COLLECT_TELEMETRY = "false";
    const env: NodeJS.ProcessEnv = {
      AZURE_HTTP_USER_AGENT:
        "caller/1.0 spe-mcp-server/old spe-install-source/microsoft-learn spe-agent-host/cursor",
      AZURE_DEV_USER_AGENT: "spe-mcp-server/old spe-install-campaign/docs-install-buttons",
    };

    expect(getUserAgent()).toBeUndefined();
    configureAzureUserAgentEnvironment(env);

    expect(env.AZURE_HTTP_USER_AGENT).toBe("caller/1.0");
    expect(env.AZURE_DEV_USER_AGENT).toBeUndefined();
  });
});

/**
 * Telemetry opt-out tests.
 *
 * All attribution tokens are gated behind `SPE_MCP_COLLECT_TELEMETRY`. They are
 * on by default and suppressed only when the variable is explicitly falsy.
 */

afterEach(() => {
  __testing.reset();
  if (saved === undefined) {
    delete process.env.SPE_MCP_COLLECT_TELEMETRY;
  } else {
    process.env.SPE_MCP_COLLECT_TELEMETRY = saved;
  }
});

describe("telemetry opt-out (SPE_MCP_COLLECT_TELEMETRY)", () => {
  it("is on by default when the variable is unset", () => {
    delete process.env.SPE_MCP_COLLECT_TELEMETRY;
    expect(telemetryEnabled()).toBe(true);
    expect(productUserAgent()).toBe(USER_AGENT);
  });

  it.each(["false", "0", "no", "off", "FALSE", " Off "])(
    "opts out when set to %j (drops the product token)",
    (value) => {
      process.env.SPE_MCP_COLLECT_TELEMETRY = value;
      expect(telemetryEnabled()).toBe(false);
      expect(productUserAgent()).toBeUndefined();
    },
  );

  it.each(["true", "1", "yes", "on", ""])(
    "stays on for non-falsy value %j",
    (value) => {
      process.env.SPE_MCP_COLLECT_TELEMETRY = value;
      expect(telemetryEnabled()).toBe(true);
      expect(productUserAgent()).toBe(USER_AGENT);
    },
  );
});

describe("isProductUserAgent", () => {
  it("recognizes this tool's product token for any version", () => {
    expect(isProductUserAgent(USER_AGENT)).toBe(true);
    expect(isProductUserAgent("spe-mcp-server/9.9.9-test")).toBe(true);
  });

  it("does not match unrelated or empty values", () => {
    expect(isProductUserAgent(undefined)).toBe(false);
    expect(isProductUserAgent("")).toBe(false);
    expect(isProductUserAgent("azsdk-js-arm/1.0.0")).toBe(false);
    expect(isProductUserAgent("my-own-tool/2.0")).toBe(false);
  });
});

describe("applyProductUserAgent (opt-out enforcement)", () => {
  it("stamps the product token when telemetry is on", () => {
    delete process.env.SPE_MCP_COLLECT_TELEMETRY;
    const headers = applyProductUserAgent({ "Content-Type": "application/json" });
    expect(headers["User-Agent"]).toBe(USER_AGENT);
  });

  it("preserves a caller-supplied User-Agent and appends attribution when on", () => {
    delete process.env.SPE_MCP_COLLECT_TELEMETRY;
    const headers = applyProductUserAgent({ "User-Agent": "caller/1.0" });
    expect(headers["User-Agent"]).toBe(`caller/1.0 ${USER_AGENT}`);
  });

  it("replaces stale owned tokens without duplicating them", () => {
    setInstallAttribution(resolveInstallAttribution({ source: "github-readme" }));
    const headers = applyProductUserAgent({
      "User-agent": `caller/1.0 ${USER_AGENT} spe-install-source/microsoft-learn`,
      "USER-AGENT": "caller/1.0 extension/2.0",
    });

    expect(headers["User-Agent"]).toBe(
      `caller/1.0 extension/2.0 ${USER_AGENT} spe-install-source/github-readme`,
    );
    expect(headers["User-agent"]).toBeUndefined();
    expect(headers["USER-AGENT"]).toBeUndefined();
  });

  it("strips owned tokens but preserves unrelated User-Agent content when opted out", () => {
    process.env.SPE_MCP_COLLECT_TELEMETRY = "false";
    const headers = applyProductUserAgent({
      Authorization: "Bearer x",
      "user-agent": `caller/1.0 ${USER_AGENT} spe-agent-host/vscode`,
    });
    expect(headers["User-Agent"]).toBe("caller/1.0");
    expect(headers["user-agent"]).toBeUndefined();
    // Unrelated headers are left intact.
    expect(headers.Authorization).toBe("Bearer x");
  });
});
