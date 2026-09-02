# Privacy

`@microsoft/spe-mcp` ("the tool") is an open-source Model Context Protocol (MCP)
server that you run **locally** to manage **your own** SharePoint Embedded, Microsoft Graph,
and Azure resources. This notice explains what the tool does and does not do with data. It is
provided for transparency and does not replace the
[Microsoft Privacy Statement](https://privacy.microsoft.com/privacystatement) or your
organization's agreements with Microsoft.

## What the tool collects and sends

**The tool opens no dedicated usage-analytics channel and sends no personal, tenant, or
per-user data to Microsoft.** Its Microsoft-bound attribution signals are bounded `User-Agent`
tokens, which are on by default and can be turned off (see
[Turning it off](#turning-it-off)). Specifically:

- **No telemetry channel.** The tool does not implement application telemetry and does not
  "phone home." Diagnostic logs are written to the local process's **stderr only**, with
  tokens and secrets redacted (`src/logging.ts`), and are never transmitted by the tool.
- **Authentication against your tenant.** You sign in with your own Microsoft Entra identity
  via [MSAL](https://learn.microsoft.com/entra/identity-platform/msal-overview). Access and
  refresh tokens are cached **locally** with owner-only file permissions (control
  **SEC-003**). The tool does not send your tokens anywhere other than the standard Microsoft
  authentication and API calls you initiate.
- **API calls you initiate.** When you invoke a tool, the server calls Microsoft first-party
  endpoints — Microsoft Graph and Azure Resource Manager — **on your behalf**, in **your**
  tenant and subscription. The content and directory data involved flow between your machine
  and those Microsoft services; the tool adds no additional recipients.
- **Product and install-source `User-Agent`.** Outbound Graph/ARM requests are stamped
  with `spe-mcp-server/<version>` (`src/user-agent.ts`). Install links can also configure
  bounded source, content, and campaign labels such as `microsoft-learn` and an article
  slug. The MCP handshake's self-reported client name is mapped to a bounded agent-host
  label; the raw name and client version are not transmitted in the request metadata.
  These labels contain **no personal or tenant identifiers**, but they accompany each
  authenticated request and Microsoft services can associate them with that request in
  normal service logs. They exist so the service can measure aggregate traffic driven by
  published install surfaces and agent hosts; they are not a separate data feed. Attribution
  is **on by default**; set `SPE_MCP_COLLECT_TELEMETRY=false` to omit all of these tokens.

See [docs/DATA-FLOW.md](docs/DATA-FLOW.md) for the full list of network endpoints and what
travels to each.

> **Standard Microsoft data-collection notice.** Microsoft's standard notice states that
> software "may collect information about you and your use of the software and send it to
> Microsoft" (full text in [NOTICE.md](NOTICE.md#data-collection)). It is reproduced for
> completeness; **this build opens no usage-analytics channel** — the only Microsoft-bound
> signals are the bounded `User-Agent` attribution tokens described above, which are on by default
> and can be turned off (see [Turning it off](#turning-it-off) and the
> [Telemetry configuration](NOTICE.md#telemetry-configuration) note).

## Service-side data handling

Microsoft Graph, Azure, and SharePoint Embedded are Microsoft Online Services. Any data you
create or access through them is handled under the
[Microsoft Product Terms](https://www.microsoft.com/licensing/terms/), the
[Microsoft Products and Services Data Protection Addendum (DPA)](https://www.microsoft.com/licensing/docs/view/Microsoft-Products-and-Services-Data-Protection-Addendum-DPA),
and the [Microsoft Privacy Statement](https://privacy.microsoft.com/privacystatement),
according to your tenant's configuration (including any **EU Data Boundary** commitments).
This tool does not change that handling.

## Third-party MCP clients

You connect the tool to an MCP client (for example VS Code, Claude Desktop, or Cursor). The
prompts you type and the data the client displays are handled under **that client's** privacy
terms, which are outside the control of this project.

## Turning it off

Because the tool has no telemetry channel, there is no separate telemetry stream to opt out
of. To omit install-source labels while retaining the product token, remove the
`--install-source`, `--install-content`, and `--install-campaign` arguments from the MCP
client configuration. To omit both install-source and agent-host labels, add
`--no-install-attribution`. All attribution is **on by default**. To opt out, set
`SPE_MCP_COLLECT_TELEMETRY=false` in your environment; the tool then omits the product,
install-source, content, campaign, and agent-host tokens from all outbound Graph and Azure
Resource Manager requests. Those requests still go out — they simply
carry the underlying tool's default `User-Agent` instead (e.g. the Azure CLI's own token for
`az`/`azd`, or the Node runtime default for direct Graph calls), whose logging is governed by
those services' own terms. To further limit
outbound calls you can run with `--read-only` (no mutating operations) or `--tools` (restrict
the exposed tool set, including the optional Microsoft Learn documentation lookup). See
[docs/DATA-FLOW.md](docs/DATA-FLOW.md), [docs/SECURITY-CONTROLS.md](docs/SECURITY-CONTROLS.md),
and the consolidated [NOTICE.md](NOTICE.md).
