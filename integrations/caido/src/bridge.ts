import { Client, type RequestResponseOpt } from "@caido/sdk-client";
import { readFile } from "node:fs/promises";

type BridgeInput =
  | { action: "health"; url: string }
  | {
      action: "search";
      url: string;
      filters?: { host?: string; path?: string; method?: string; status?: number };
      count?: number;
    }
  | { action: "get"; url: string; id: string }
  | { action: "replay"; url: string; id: string };

function validateControlUrl(value: string): string {
  const url = new URL(value);
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1";
  if (!local && process.env.BUDOBUGS_CAIDO_ALLOW_REMOTE !== "1") {
    throw new Error("Caido control URL must be loopback unless BUDOBUGS_CAIDO_ALLOW_REMOTE=1");
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error("Caido URL must be credential-free HTTP(S)");
  }
  return url.toString().replace(/\/$/, "");
}

function escapeHttpql(value: string): string {
  return JSON.stringify(value);
}

function filterExpression(filters: Extract<BridgeInput, { action: "search" }>["filters"]): string | undefined {
  if (!filters) return undefined;
  const clauses: string[] = [];
  if (filters.host) clauses.push(`req.host.eq:${escapeHttpql(filters.host)}`);
  if (filters.path) clauses.push(`req.path.cont:${escapeHttpql(filters.path)}`);
  if (filters.method) clauses.push(`req.method.eq:${escapeHttpql(filters.method.toUpperCase())}`);
  if (filters.status !== undefined) clauses.push(`resp.code.eq:${filters.status}`);
  return clauses.length ? clauses.join(" AND ") : undefined;
}

function serialize(item: RequestResponseOpt | undefined): unknown {
  if (!item) return null;
  const encoder = (value?: Uint8Array): string | undefined =>
    value === undefined ? undefined : Buffer.from(value).toString("base64");
  return {
    request: { ...item.request, createdAt: item.request.createdAt.toISOString(), rawBase64: encoder(item.request.raw), raw: undefined },
    response: item.response
      ? { ...item.response, createdAt: item.response.createdAt.toISOString(), rawBase64: encoder(item.response.raw), raw: undefined }
      : undefined,
  };
}

async function readInput(): Promise<BridgeInput> {
  const file = process.argv[2];
  if (!file) throw new Error("expected a JSON input file path");
  return JSON.parse(await readFile(file, "utf8")) as BridgeInput;
}

async function main(): Promise<void> {
  const input = await readInput();
  const pat = process.env.CAIDO_PAT;
  if (!pat) throw new Error("CAIDO_PAT is required and is read only from the process environment");
  const client = new Client({ url: validateControlUrl(input.url), auth: { pat } });
  await client.connect();
  let result: unknown;
  if (input.action === "health") {
    result = await client.health();
  } else if (input.action === "get") {
    result = serialize(await client.request.get(input.id, { requestRaw: true, responseRaw: true }));
  } else if (input.action === "search") {
    let builder = client.request.list().includeRaw({ request: true, response: true });
    const expression = filterExpression(input.filters);
    if (expression) builder = builder.filter(expression);
    const page = await builder.first(Math.min(Math.max(input.count ?? 100, 1), 500));
    result = page.edges.map((edge) => serialize(edge.node));
  } else {
    const item = await client.request.get(input.id, { requestRaw: true, responseRaw: true });
    if (!item?.request.raw) throw new Error("Caido request does not have replayable raw bytes");
    const session = await client.replay.sessions.create({ requestSource: { id: input.id } });
    const sent = await client.replay.send(session.id, {
      raw: item.request.raw,
      connection: { host: item.request.host, port: item.request.port, isTLS: item.request.isTls },
      settings: { connectionClose: true, updateContentLength: true },
    });
    result = {
      status: sent.status,
      error: sent.error,
      entryId: sent.entry.id,
      exchange: sent.entry.request
        ? serialize({ request: sent.entry.request, response: sent.entry.response })
        : undefined,
    };
  }
  process.stdout.write(`${JSON.stringify({ status: "PASS", result })}\n`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${JSON.stringify({ status: "FAIL", error: message })}\n`);
  process.exitCode = 1;
});
