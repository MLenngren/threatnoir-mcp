import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const DEFAULT_SUPABASE_URL = "https://zbqafrnxsxwbarztrtqp.supabase.co";
const ARTICLE_IOCS_PATH = "/rest/v1/article_iocs";

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

function getSupabaseUrl(): string {
  return process.env.SUPABASE_URL ?? DEFAULT_SUPABASE_URL;
}

function getServiceKeyOrNull(): string | null {
  const key = process.env.SUPABASE_SERVICE_KEY;
  if (!key) return null;
  return key;
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

  const url = new URL(`${getSupabaseUrl()}${ARTICLE_IOCS_PATH}`);
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

  const res = await fetch(url, {
    method: "GET",
    headers: {
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
      Accept: "application/json",
    },
  });

  const bodyText = await res.text();
  if (!res.ok) {
    let detail = bodyText;
    try {
      const parsed = JSON.parse(bodyText) as { message?: string; details?: string; hint?: string };
      detail = [parsed.message, parsed.details, parsed.hint].filter(Boolean).join(" | ") || bodyText;
    } catch {
      // keep bodyText
    }

    throw new Error(`Supabase REST API error (${res.status}): ${detail}`);
  }

  try {
    const json = JSON.parse(bodyText) as unknown;
    if (!Array.isArray(json)) {
      throw new Error("Unexpected response shape (expected JSON array)");
    }
    return json as ArticleIocRow[];
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to parse Supabase response: ${msg}`);
  }
}

function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return "unknown date";
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return "unknown date";
  return d.toISOString().slice(0, 10);
}

function formatResults(opts: {
  header: string;
  rows: ArticleIocRow[];
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
    const published = formatDate(row.article?.published_at);
    lines.push(`   Article: "${articleTitle}" (${published})`);
    if (row.article?.url) {
      lines.push(`   Source: ${row.article.url}`);
    }
    lines.push("");
  });

  return lines.join("\n");
}

const server = new McpServer({
  name: "threatnoir-ioc-mcp",
  version: "1.0.0",
});

server.registerTool(
  "search_iocs",
  {
    description: "Free-text search ThreatNoir IOCs by value (IP, domain, hash, CVE, etc.)",
    inputSchema: {
      query: z.string().min(1).describe("Search term (IP, domain, hash, CVE, etc.)"),
      type: IocTypeEnum.optional().describe("Optional IOC type filter"),
      limit: z.number().int().min(1).max(50).optional().describe("Max results (default 20, max 50)"),
    },
  },
  async ({ query, type, limit }) => {
    const serviceKey = getServiceKeyOrNull();
    if (!serviceKey) {
      return {
        content: [
          {
            type: "text",
            text: "Error: SUPABASE_SERVICE_KEY is not set. Configure it via your MCP settings (recommended: 1Password op:// reference).",
          },
        ],
        isError: true,
      };
    }

    try {
      const rows = await fetchArticleIocs({
        serviceKey,
        valueFilter: `ilike.*${query}*`,
        type,
        limit: Math.min(limit ?? 20, 50),
      });

      const text = formatResults({
        header: `Found ${rows.length} IOCs matching "${query}":`,
        rows,
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
    description: "List recent ThreatNoir IOCs (optionally filtered by type)",
    inputSchema: {
      type: IocTypeEnum.optional().describe("Optional IOC type filter"),
      limit: z.number().int().min(1).max(50).optional().describe("Max results (default 20, max 50)"),
    },
  },
  async ({ type, limit }) => {
    const serviceKey = getServiceKeyOrNull();
    if (!serviceKey) {
      return {
        content: [
          {
            type: "text",
            text: "Error: SUPABASE_SERVICE_KEY is not set. Configure it via your MCP settings (recommended: 1Password op:// reference).",
          },
        ],
        isError: true,
      };
    }

    try {
      const rows = await fetchArticleIocs({
        serviceKey,
        type,
        limit: Math.min(limit ?? 20, 50),
      });

      const suffix = type ? ` (type=${type})` : "";
      const text = formatResults({
        header: `Recent IOCs${suffix}:`,
        rows,
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
    description: "Exact-match lookup for a ThreatNoir IOC value",
    inputSchema: {
      value: z.string().min(1).describe("Exact IOC value (IP, domain, hash, CVE, etc.)"),
    },
  },
  async ({ value }) => {
    const serviceKey = getServiceKeyOrNull();
    if (!serviceKey) {
      return {
        content: [
          {
            type: "text",
            text: "Error: SUPABASE_SERVICE_KEY is not set. Configure it via your MCP settings (recommended: 1Password op:// reference).",
          },
        ],
        isError: true,
      };
    }

    try {
      const rows = await fetchArticleIocs({
        serviceKey,
        valueFilter: `eq.${value}`,
        limit: 50,
      });

      const text = formatResults({
        header: `Found ${rows.length} IOCs matching "${value}":`,
        rows,
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
