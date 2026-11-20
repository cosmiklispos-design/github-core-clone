[![make.fun](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01)
[![Rank](https://make.fun/badge/github-core-clone-01/cosmiklispos-design/github-core-clone/rank.svg)](https://make.fun/bounty/github-core-clone-01)
[![Reward](https://make.fun/badge/github-core-clone-01/cosmiklispos-design/github-core-clone/reward.svg)](https://make.fun/bounty/github-core-clone-01)

# github-core-clone

A standalone GitHub-compatible git forge in one Node 22 process, no dependencies,
no git binary, no UI, no outside service. Built for make.fun
[bounty github-core-clone-01](https://make.fun/bounty/github-core-clone-01).

One process serves all four surfaces the suite drives:

- **git smart HTTP** at `/{owner}/{repo}.git` — `info/refs`, `git-upload-pack`
  (protocol v2 with `ls-refs`/`fetch`, plus v0), `git-receive-pack` (v0 with
  `report-status` / `side-band-64k` / `delete-refs`), own object store
  (blob/tree/commit/tag), pack reading (plain + OFS/REF deltas) and writing.
- **REST v3** under `/api/v3` — repos, branches, commits, contents, issues,
  comments, labels, pull requests, merges; pagination via `Link` headers.
- **GraphQL v4** at `/api/graphql` — the documents `gh` sends (`viewer`,
  `repository`, `issues`, `pullRequests`, `node`, `__type` introspection,
  `createIssue` / `closeIssue` / `createPullRequest` / `mergePullRequest` /
  `addComment`, batched operations).
- **MCP** at `/mcp` — Streamable HTTP, `server/discover` (2026-07-28) with a
  legacy `initialize` fallback, `tools/list` / `tools/call` for
  `create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request`, `merge_pull_request`.

## Run

```sh
node --experimental-strip-types main.ts
```

`MAKEFUN_ENV_URL` names the env to register with (the trial); without it the
server just listens locally (`PORT` or an ephemeral port). The suite's bearer
token comes from `MAKEFUN_SHOP_TOKEN`; `MAKEFUN_TRIAL_NOW` and
`MAKEFUN_TRIAL_SEED` fix the clock and every deterministic choice, so a replay
behaves byte-identically.

## Layout

- `main.ts` — lifecycle: bind an ephemeral port, register it, poll `/done`.
- `app.ts` — the whole forge: object store, smart HTTP, REST, GraphQL, MCP.
