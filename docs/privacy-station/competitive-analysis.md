# Competitive analysis (research notes, 2026-10-09)

One problem we solve better for solo developers using AI agents: **using a
credential in an automated workflow without the credential ever entering
the agent's context** — enforced by deterministic local code, not by
asking the model to behave.

| Tool / approach | What it does | Where Sagitarrius-broker differs (honest) |
|---|---|---|
| pass / age / sops | Excellent local encryption; age has no agent story | They encrypt; none brokers credential *use*. sops fits GitOps better than interactive agents. |
| Cloud secret managers (Vault, AWS SM) | Full-featured brokering + audit | Require accounts, network, daemons, teams — opposite of local-first solo-dev. Operationally heavier by an order of magnitude. |
| MCP OAuth (spec 2026-07-28) | Standard auth for HTTP MCP servers; STDIO told to use env vars | Env-var retrieval is exactly the leak vector we remove. Our broker is complementary: it could sit behind a future MCP adapter. We do NOT implement OAuth in v1 (rightly — no remote parties involved). |
| Agent `.env` injection / `run` | Simple, zero-setup | Secret lands in agent context permanently. Our `run --secret` already scopes this; the broker goes one step further (no secret at all). |
| OS keychains | Good at-rest storage, per-app ACLs | No scoped-use brokering, no audit trail, awkward in headless/CI use. |
| `direnv` / `mise` | Auto-load env per directory | Convenient — and maximally exposed (every child + the agent sees all). Integrates *after* the broker proves value, not before. |

Where others are better today: sops for repo-committed config, OS keychains
for GUI-app secrets, cloud managers for teams/audit-at-scale, MCP OAuth
for remote multi-user servers. We do not compete there in v1.

Sources: modelcontextprotocol.io/specification/2026-07-28 (authorization:
OAuth 2.1 for HTTP, env retrieval for STDIO, per-tool auth as extension);
OWASP Top 10 for LLM Applications 2025 (LLM01 prompt injection, LLM02
sensitive disclosure, LLM06 excessive agency — minimize functionality,
permissions, autonomy); genai.owasp.org.
