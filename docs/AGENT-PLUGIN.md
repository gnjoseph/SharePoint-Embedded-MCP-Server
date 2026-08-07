# Agent Plugins 1.0 MCP-only pilot

This repository is an [Agent Plugins 1.0](https://agent-plugins.org/) package
that provides one local SharePoint Embedded MCP server. The pilot is additive:
it does not change the server, add skills, agents, hooks, OAuth, or a remote
transport.

## Install and use

Prerequisites:

- Node.js 22, 24, or 26
- `npx` on `PATH`
- Azure CLI authentication as described in the main [README](../README.md)
- an Agent Plugins 1.0 client, such as a current VS Code release with
  `chat.plugins.enabled`

In VS Code, run **Chat: Install Plugin From Source** and enter:

```text
https://github.com/microsoft/SharePoint-Embedded-MCP-Server
```

For local development, register the repository root with
`chat.pluginLocations`:

```json
{
  "chat.pluginLocations": {
    "/absolute/path/to/SharePoint-Embedded-MCP-Server": true
  }
}
```

When enabled, the client reads `mcp.json` and starts:

```text
npx -y @microsoft/spe-mcp@0.2.0-alpha.1 start --read-only --data-dir ${PLUGIN_DATA}
```

The exact npm version was verified as published on August 7, 2026. It is
intentionally pinned: plugin updates, not npm dist-tag movement, control server
updates.

## Security boundaries

- **Read-only by default:** `--read-only` hides and rejects every tool not
  annotated read-only. Installing this pilot does not enable tenant writes.
- **Local process only:** the plugin uses MCP `stdio`; it defines no remote URL.
- **User credentials:** read operations still act with the signed-in user's
  permissions. Review the tenant and account before using a tool.
- **Executable trust:** enabling the plugin allows the client to run the pinned
  public npm package through `npx`. Review the repository and package publisher
  before installation.
- **No autonomous extensions:** the package contains no skills, custom agents,
  hooks, or OAuth configuration.

See [Security controls](SECURITY-CONTROLS.md) for the server's complete controls
and limitations.

## Persistent plugin data

Agent Plugins 1.0 clients create a private, writable `${PLUGIN_DATA}` directory
for each installed plugin and preserve it across plugin updates. The standard
expands `${PLUGIN_DATA}` in `args`; it does not expand placeholders in
`command`. Accordingly, `mcp.json` keeps `command` as the single executable
token `npx` and passes `${PLUGIN_DATA}` as the separate value for `--data-dir`.

The SPE MCP server stores its token cache and provisioning state under that
directory. Disabling the plugin stops the MCP process but preserves this state.
Uninstalling/removing the plugin may remove client-managed plugin data; sign in
again if the client removes it.

## Limitations

- This pilot does not expose provisioning, upload, permission, delete, or other
  mutating tools.
- There is no remote MCP transport or plugin-provided OAuth flow.
- `npx` may need network access on first launch to retrieve the exact package.
- Agent Plugins 1.0 client support and organization policy determine whether
  the plugin can be enabled.

## Validate

```bash
npm install
npm run test -- src/agent-plugin.test.ts
npm run ci
```

The contract tests validate the closed 1.0.0 manifest fields, exact npm pin,
package/lockfile alignment, local stdio startup, read-only tool exposure, and
`${PLUGIN_DATA}` configuration.

## Disable, remove, or roll back

Disable or uninstall **sharepoint-embedded-mcp** from the client's Agent
Plugins view. In VS Code, remove a local `chat.pluginLocations` entry if one was
used. For a repository rollback, revert `plugin.json`, `mcp.json`, and the
associated package/docs/test changes; the standalone SPE MCP server remains
unchanged.

## Standards references

- [Agent Plugins 1.0 specification](https://github.com/agentplugins/agent-plugins-spec/blob/main/spec/1.0.0.md)
- [`plugin.json` schema](https://agent-plugins.org/schemas/1.0.0/plugin.schema.json)
- [`mcp.json` schema](https://agent-plugins.org/schemas/1.0.0/mcp.schema.json)
- [Agent plugins in VS Code](https://code.visualstudio.com/docs/agent-customization/agent-plugins)
