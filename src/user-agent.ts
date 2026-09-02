// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/**
 * Product and optional bounded attribution identifiers stamped on outbound
 * Microsoft Graph and Azure CLI (`az` / `azd`) requests.
 *
 * They carry no per-user, per-tenant, or personal data, open no separate
 * telemetry channel, and ride only on calls the tool already makes. All tokens
 * are suppressed by the `SPE_MCP_COLLECT_TELEMETRY` opt-out.
 */
import { ValidationError } from "./errors.js";
import { PACKAGE_VERSION } from "./version.js";

const PRODUCT_NAME = "spe-mcp-server";

export const USER_AGENT = `${PRODUCT_NAME}/${PACKAGE_VERSION}`;

export const INSTALL_SOURCES = [
  "microsoft-learn",
  "github-readme",
  "github-release",
  "mcp-registry",
  "npm",
  "other",
] as const;

export type InstallSource = (typeof INSTALL_SOURCES)[number];

export const INSTALL_CONTENTS = [
  "readme-install",
  "sharepoint-embedded-mcp-server",
  "quickstart-vscode",
  "create-container-type",
  "create-manage-containers",
] as const;

export const INSTALL_CAMPAIGNS = ["docs-install-buttons"] as const;

export const AGENT_HOSTS = [
  "vscode",
  "visual-studio",
  "cursor",
  "claude-code",
  "claude-desktop",
  "codex",
  "github-copilot-cli",
  "azure-ai-foundry",
  "other",
  "unknown",
] as const;

export type AgentHost = (typeof AGENT_HOSTS)[number];

export interface InstallAttribution {
  source: InstallSource;
  content?: (typeof INSTALL_CONTENTS)[number];
  campaign?: (typeof INSTALL_CAMPAIGNS)[number];
}

export interface InstallAttributionInput {
  source?: string;
  content?: string;
  campaign?: string;
  enabled?: boolean;
}

const ATTRIBUTION_ID_PATTERN = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;
let activeAttribution: InstallAttribution | undefined;
let activeAgentHost: AgentHost | undefined;

function normalizeOptionalId(value: string | undefined, field: string): string | undefined {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) return undefined;
  if (!ATTRIBUTION_ID_PATTERN.test(normalized)) {
    throw new ValidationError(
      `${field} must be a 1-64 character lowercase identifier using only letters, numbers, '.', '_' or '-'.`,
    );
  }
  return normalized;
}

export function resolveInstallAttribution(
  input: InstallAttributionInput,
): InstallAttribution | undefined {
  if (input.enabled === false) return undefined;

  const source = normalizeOptionalId(input.source, "install source");
  const content = normalizeOptionalId(input.content, "install content");
  const campaign = normalizeOptionalId(input.campaign, "install campaign");

  if (!source) {
    if (content || campaign) {
      throw new ValidationError(
        "--install-content and --install-campaign require --install-source.",
      );
    }
    return undefined;
  }

  if (!INSTALL_SOURCES.includes(source as InstallSource)) {
    throw new ValidationError(
      `install source must be one of: ${INSTALL_SOURCES.join(", ")}.`,
    );
  }
  if (
    content &&
    !INSTALL_CONTENTS.includes(content as (typeof INSTALL_CONTENTS)[number])
  ) {
    throw new ValidationError(
      `install content must be one of: ${INSTALL_CONTENTS.join(", ")}.`,
    );
  }
  if (
    campaign &&
    !INSTALL_CAMPAIGNS.includes(campaign as (typeof INSTALL_CAMPAIGNS)[number])
  ) {
    throw new ValidationError(
      `install campaign must be one of: ${INSTALL_CAMPAIGNS.join(", ")}.`,
    );
  }

  return {
    source: source as InstallSource,
    ...(content
      ? { content: content as (typeof INSTALL_CONTENTS)[number] }
      : {}),
    ...(campaign
      ? { campaign: campaign as (typeof INSTALL_CAMPAIGNS)[number] }
      : {}),
  };
}

export function setInstallAttribution(attribution: InstallAttribution | undefined): void {
  activeAttribution = attribution;
}

/**
 * Classify the self-reported MCP `initialize.params.clientInfo.name` into a
 * bounded analytics dimension. This is advisory attribution only, never a
 * security signal. Unknown raw values are not transmitted.
 */
export function classifyAgentHost(clientName: string | undefined): AgentHost {
  const name = clientName?.trim().toLowerCase() ?? "";
  if (!name || name === "mcp") return "unknown";
  if (
    name.includes("visual studio code") ||
    name.startsWith("code - oss")
  ) {
    return "vscode";
  }
  if (name.includes("cursor")) return "cursor";
  if (name === "claude-code" || name.includes("claude code")) {
    return "claude-code";
  }
  if (
    name === "claude" ||
    name === "claude-ai" ||
    name.includes("claude desktop") ||
    name.startsWith("local-agent-mode-")
  ) {
    return "claude-desktop";
  }
  if (
    name.includes("github copilot cli") ||
    name.includes("copilot-cli") ||
    name === "github-copilot-developer"
  ) {
    return "github-copilot-cli";
  }
  if (name.includes("codex")) return "codex";
  if (name.includes("visual studio")) return "visual-studio";
  if (name.includes("foundry")) return "azure-ai-foundry";
  return "other";
}

export function resolveAgentHostAttribution(
  clientName: string | undefined,
  enabled: boolean,
): AgentHost | undefined {
  return enabled ? classifyAgentHost(clientName) : undefined;
}

export function setAgentHostAttribution(agentHost: AgentHost | undefined): void {
  activeAgentHost = agentHost;
}

export function telemetryEnabled(
  value: string | undefined = process.env.SPE_MCP_COLLECT_TELEMETRY,
): boolean {
  if (value === undefined) return true;
  return !["0", "false", "no", "off"].includes(value.trim().toLowerCase());
}

export function productUserAgent(): string | undefined {
  return telemetryEnabled() ? USER_AGENT : undefined;
}

export function isProductUserAgent(value: string | undefined): boolean {
  return typeof value === "string" && value.startsWith(`${PRODUCT_NAME}/`);
}

export function getUserAgent(): string | undefined {
  if (!telemetryEnabled()) return undefined;

  const tokens: string[] = [];
  if (activeAttribution) {
    tokens.push(`spe-install-source/${activeAttribution.source}`);
    if (activeAttribution.content) {
      tokens.push(`spe-install-content/${activeAttribution.content}`);
    }
    if (activeAttribution.campaign) {
      tokens.push(`spe-install-campaign/${activeAttribution.campaign}`);
    }
  }
  if (activeAgentHost) {
    tokens.push(`spe-agent-host/${activeAgentHost}`);
  }
  return tokens.length > 0 ? `${USER_AGENT} ${tokens.join(" ")}` : USER_AGENT;
}

function isOwnedUserAgentToken(token: string): boolean {
  return (
    isProductUserAgent(token) ||
    token.startsWith("spe-install-source/") ||
    token.startsWith("spe-install-content/") ||
    token.startsWith("spe-install-campaign/") ||
    token.startsWith("spe-agent-host/")
  );
}

export function appendUserAgent(
  existing: string | undefined,
  value: string | undefined,
): string | undefined {
  const currentTokens = existing?.trim().split(/\s+/).filter(Boolean) ?? [];
  const preserved = currentTokens.filter((token) => !isOwnedUserAgentToken(token));
  const combined = [
    ...new Set([...preserved, ...(value ? value.split(/\s+/) : [])]),
  ].join(" ");
  return combined || undefined;
}

export function applyProductUserAgent(
  headers: Record<string, string>,
): Record<string, string> {
  const userAgentKeys = Object.keys(headers).filter(
    (key) => key.toLowerCase() === "user-agent",
  );
  const existing =
    userAgentKeys.map((key) => headers[key]).filter(Boolean).join(" ") || undefined;
  const userAgent = appendUserAgent(existing, getUserAgent());
  for (const key of userAgentKeys) delete headers[key];
  if (userAgent) headers["User-Agent"] = userAgent;
  return headers;
}

export function configureAzureUserAgentEnvironment(
  env: NodeJS.ProcessEnv = process.env,
): void {
  const userAgent = getUserAgent();
  const azureUserAgent = appendUserAgent(env.AZURE_HTTP_USER_AGENT, userAgent);
  const azureDevUserAgent = appendUserAgent(env.AZURE_DEV_USER_AGENT, userAgent);
  if (azureUserAgent) env.AZURE_HTTP_USER_AGENT = azureUserAgent;
  else delete env.AZURE_HTTP_USER_AGENT;
  if (azureDevUserAgent) env.AZURE_DEV_USER_AGENT = azureDevUserAgent;
  else delete env.AZURE_DEV_USER_AGENT;
}

export const __testing = {
  reset(): void {
    activeAttribution = undefined;
    activeAgentHost = undefined;
  },
};
