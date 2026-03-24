#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { request as httpsRequest } from "node:https";
import { z } from "zod";

const ARTICLE_IOCS_PATH = "/rest/v1/article_iocs";

const DEFAULT_THREATNOIR_URL = "https://threatnoir.com";
const THREATNOIR_IOCS_PATH = "/api/v1/iocs";

const IocTypeEnum = z.enum([
  "ip",
  "domain",
  "hash_md5",
  "hash_sha1",
  "hash_sha256",
  "url",
  "cve",
  "mitre_attack",
  "email",
  "malware",
]);

type IocType = z.infer<typeof IocTypeEnum>;

type Article = {
  id: string | number;
  title: string | null;
  url: string | null;
  published_at: string | null;
};

type ArticleIocRow = {
  type: string;
  value: string;
  context: string | null;
  created_at: string;
  article?: Article | null;
};

type ThreatNoirIocItem = {
  type: string;
  value: string;
  context?: string | null;
  article?: Article | null;
};

type ThreatNoirIocResponse = {
  items: ThreatNoirIocItem[];
  hasMore?: boolean;
  nextOffset?: number;
};

type NormalizedIoc = {
  type: string;
  value: string;
  context: string | null;
  article: Article | null;
  threatnoirArticleUrl: string | null;
};

function getSupabaseUrl(): string | null {
  return process.env.SUPABASE_URL ?? null;
}

function getServiceKeyOrNull(): string | null {
  const key = process.env.SUPABASE_SERVICE_KEY;
  if (!key) return null;
  return key;
}

function getThreatNoirBaseUrl(): string {
  return process.env.THREATNOIR_URL ?? DEFAULT_THREATNOIR_URL;
}

function getThreatNoirApiKeyOrNull(): string | null {
  const key = process.env.THREATNOIR_API_KEY;
  if (!key) return null;
  return key;
}

async function httpsGetText(url: URL, headers: Record<string, string>): Promise<{ status: number; bodyText: string }> {
  return await new Promise((resolve, reject) => {
    const req = httpsRequest(
      url,
      {
        method: "GET",
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const status = res.statusCode ?? 0;
          const bodyText = Buffer.concat(chunks).toString("utf8");
          resolve({ status, bodyText });
        });
      },
    );

    req.on("error", (err) => reject(err));
    req.end();
  });
}

async function httpsGetJson<T>(url: URL, headers: Record<string, string>): Promise<T> {
  const { status, bodyText } = await httpsGetText(url, headers);

  if (status < 200 || status >= 300) {
    let detail = bodyText;
    try {
      const parsed = JSON.parse(bodyText) as { message?: string; error?: string; details?: string; hint?: string };
      detail = [parsed.message, parsed.error, parsed.details, parsed.hint].filter(Boolean).join(" | ") || bodyText;
    } catch {
      // keep bodyText
    }
    throw new Error(`HTTP error (${status}): ${detail}`);
  }

  try {
    return JSON.parse(bodyText) as T;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to parse JSON response: ${msg}`);
  }
}

const SELECT_CLAUSE =
  "type,value,context,created_at,article:articles!article_iocs_article_id_fkey!inner(id,title,url,published_at)";

async function fetchArticleIocs(params: {
  serviceKey: string;
  valueFilter?: string;
  type?: IocType;
  limit: number;
}): Promise<ArticleIocRow[]> {
  const { serviceKey, valueFilter, type, limit } = params;

  const supabaseUrl = getSupabaseUrl();
  if (!supabaseUrl) throw new Error("SUPABASE_URL is required for direct mode");
  const url = new URL(`${supabaseUrl}${ARTICLE_IOCS_PATH}`);
  url.searchParams.set("select", SELECT_CLAUSE);
  url.searchParams.set("articles.status", "eq.approved");
  url.searchParams.set("order", "created_at.desc");
  url.searchParams.set("limit", String(limit));

  if (type) {
    url.searchParams.set("type", `eq.${type}`);
  }
  if (valueFilter) {
    url.searchParams.set("value", valueFilter);
  }

  const json = await httpsGetJson<unknown>(url, {
    apikey: serviceKey,
    Authorization: `Bearer ${serviceKey}`,
    Accept: "application/json",
  });

  if (!Array.isArray(json)) {
    throw new Error("Unexpected Supabase response shape (expected JSON array)");
  }
  return json as ArticleIocRow[];
}

async function fetchThreatNoirIocs(params: {
  apiKey: string | null;
  q?: string;
  type?: IocType;
  limit: number;
}): Promise<ThreatNoirIocItem[]> {
  const { apiKey, q, type, limit } = params;

  const url = new URL(THREATNOIR_IOCS_PATH, getThreatNoirBaseUrl());
  url.searchParams.set("limit", String(limit));
  if (q) url.searchParams.set("q", q);
  if (type) url.searchParams.set("type", type);

  const headers: Record<string, string> = { Accept: "application/json" };
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;

  const json = await httpsGetJson<ThreatNoirIocResponse>(url, headers);
  if (!json || !Array.isArray(json.items)) {
    throw new Error("Unexpected ThreatNoir API response shape (expected { items: [] })");
  }
  return json.items;
}

function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return "unknown date";
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return "unknown date";
  return d.toISOString().slice(0, 10);
}

function getThreatNoirArticleUrl(articleId: string | number | null | undefined): string | null {
  if (!articleId) return null;
  try {
    const url = new URL("/iocs", getThreatNoirBaseUrl());
    url.searchParams.set("article", String(articleId));
    return url.toString();
  } catch {
    return null;
  }
}

function normalizeFromSupabase(row: ArticleIocRow): NormalizedIoc {
  const article = row.article ?? null;
  return {
    type: row.type,
    value: row.value,
    context: row.context ?? null,
    article,
    threatnoirArticleUrl: getThreatNoirArticleUrl(article?.id),
  };
}

function normalizeFromThreatNoir(item: ThreatNoirIocItem): NormalizedIoc {
  const article = item.article ?? null;
  return {
    type: item.type,
    value: item.value,
    context: item.context ?? null,
    article,
    threatnoirArticleUrl: getThreatNoirArticleUrl(article?.id),
  };
}

function formatResults(opts: {
  header: string;
  rows: NormalizedIoc[];
  emptyMessage: string;
}): string {
  const { header, rows, emptyMessage } = opts;
  if (rows.length === 0) return emptyMessage;

  const lines: string[] = [];
  lines.push(header);
  lines.push("");

  rows.forEach((row, idx) => {
    const type = (row.type || "unknown").toUpperCase();
    lines.push(`${idx + 1}. [${type}] ${row.value}`);

    if (row.context) {
      lines.push(`   Context: ${row.context}`);
    }

    const articleTitle = row.article?.title ?? "(untitled)";
    lines.push(`   Article: "${articleTitle}"`);
    lines.push(`   Published: ${formatDate(row.article?.published_at)}`);

    if (row.article?.url) {
      lines.push(`   Source: ${row.article.url}`);
    }
    if (row.threatnoirArticleUrl) {
      lines.push(`   ThreatNoir: ${row.threatnoirArticleUrl}`);
    }
    lines.push("");
  });

  return lines.join("\n");
}

const server = new McpServer({
  name: "threatnoir-mcp-iocs",
  version: "1.0.0",
});

server.registerTool(
  "search_iocs",
  {
    description:
      "Search ThreatNoir's IOC database by keyword. Finds IPs, domains, hashes, CVEs, and more. Requires API key.",
    inputSchema: {
      query: z.string().min(1).describe("Search term (IP, domain, hash, CVE, etc.)"),
      type: IocTypeEnum.optional().describe("Optional IOC type filter"),
      limit: z.number().int().min(1).max(50).optional().describe("Max results (default 20, max 50)"),
    },
  },
  async ({ query, type, limit }) => {
    const serviceKey = getServiceKeyOrNull();
    const apiKey = getThreatNoirApiKeyOrNull();

    if (!serviceKey && !apiKey) {
      return {
        content: [
          {
            type: "text",
            text: "Set THREATNOIR_API_KEY to search IOCs",
          },
        ],
        isError: true,
      };
    }

    try {
      const maxLimit = Math.min(limit ?? 20, 50);

      const normalized: NormalizedIoc[] = serviceKey
        ? (await fetchArticleIocs({
            serviceKey,
            valueFilter: `ilike.*${query}*`,
            type,
            limit: maxLimit,
          })).map(normalizeFromSupabase)
        : (await fetchThreatNoirIocs({
            apiKey,
            q: query,
            type,
            limit: maxLimit,
          })).map(normalizeFromThreatNoir);

      const text = formatResults({
        header: `Found ${normalized.length} IOCs matching "${query}":`,
        rows: normalized,
        emptyMessage: `No IOCs found matching your query.`,
      });

      return { content: [{ type: "text", text }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: `Error searching IOCs: ${msg}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "list_iocs",
  {
    description:
      "List the most recent IOCs from ThreatNoir, optionally filtered by type (ip, domain, cve, hash_md5, hash_sha256, malware, etc.)",
    inputSchema: {
      type: IocTypeEnum.optional().describe("Optional IOC type filter"),
      limit: z.number().int().min(1).max(50).optional().describe("Max results (default 20, max 50)"),
    },
  },
  async ({ type, limit }) => {
    const serviceKey = getServiceKeyOrNull();
    const apiKey = getThreatNoirApiKeyOrNull();

    try {
      const maxLimit = Math.min(limit ?? 20, 50);
      const normalized: NormalizedIoc[] = serviceKey
        ? (await fetchArticleIocs({
            serviceKey,
            type,
            limit: maxLimit,
          })).map(normalizeFromSupabase)
        : (await fetchThreatNoirIocs({
            apiKey,
            type,
            limit: maxLimit,
          })).map(normalizeFromThreatNoir);

      const suffix = type ? ` (type=${type})` : "";
      const text = formatResults({
        header: `Recent IOCs${suffix}:`,
        rows: normalized,
        emptyMessage: "No IOCs found.",
      });
      return { content: [{ type: "text", text }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: `Error listing IOCs: ${msg}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  "lookup_ioc",
  {
    description: "Look up a specific IOC value (exact match) and get all associated articles and context.",
    inputSchema: {
      value: z.string().min(1).describe("Exact IOC value (IP, domain, hash, CVE, etc.)"),
    },
  },
  async ({ value }) => {
    const serviceKey = getServiceKeyOrNull();
    const apiKey = getThreatNoirApiKeyOrNull();

    if (!serviceKey && !apiKey) {
      return {
        content: [
          {
            type: "text",
            text: "Set THREATNOIR_API_KEY to search IOCs",
          },
        ],
        isError: true,
      };
    }

    try {
      const needle = value.trim();

      const normalized: NormalizedIoc[] = serviceKey
        ? (await fetchArticleIocs({
            serviceKey,
            valueFilter: `eq.${needle}`,
            limit: 50,
          })).map(normalizeFromSupabase)
        : (await fetchThreatNoirIocs({
            apiKey,
            q: needle,
            limit: 50,
          }))
            .filter((item) => item.value === needle || item.value.toLowerCase() === needle.toLowerCase())
            .map(normalizeFromThreatNoir);

      const text = formatResults({
        header: `Found ${normalized.length} IOCs matching "${needle}":`,
        rows: normalized,
        emptyMessage: "No IOCs found matching your query.",
      });

      return { content: [{ type: "text", text }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: `Error looking up IOC: ${msg}` }],
        isError: true,
      };
    }
  },
);

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error: unknown) => {
  console.error("Server error:", error);
  process.exit(1);
});
