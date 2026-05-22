import dotenv from "dotenv";
dotenv.config();

import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { executeQueryTool } from "./tools/executeQuery.js";
import { WorkOS } from "@workos-inc/node";

const workos = new WorkOS(process.env.WORKOS_API_KEY);

const AUTHKIT_DOMAIN = process.env.AUTHKIT_DOMAIN;
const MCP_SERVER_URL = process.env.MCP_SERVER_URL;

const JWKS = createRemoteJWKSet(
  new URL(`https://${AUTHKIT_DOMAIN}/oauth2/jwks`)
);

const MCP_RESOURCE_METADATA_URL = `${MCP_SERVER_URL}/.well-known/oauth-protected-resource/mcp`;

const WWW_AUTHENTICATE_HEADER = [
  'Bearer error="invalid_token"',
  'error_description="Authentication required for this tool"',
  `resource_metadata="${MCP_RESOURCE_METADATA_URL}"`,
].join(", ");

const PUBLIC_MCP_METHODS = new Set([
  "initialize",
  "notifications/initialized",
  "ping",
  "tools/list",
]);

const TOOL_SECURITY_SCHEMES = [
  {
    type: "oauth2",
    scopes: [],
  },
];

function callsProtectedMethod(body) {
  const messages = Array.isArray(body) ? body : [body];

  for (const msg of messages) {
    if (!msg || typeof msg !== "object") continue;

    const method = msg.method;
    if (typeof method !== "string") continue;

    if (PUBLIC_MCP_METHODS.has(method)) continue;

    return true;
  }

  return false;
}

function callsProtectedNonToolMethod(body) {
  const messages = Array.isArray(body) ? body : [body];

  for (const msg of messages) {
    if (!msg || typeof msg !== "object") continue;

    const method = msg.method;
    if (typeof method !== "string") continue;

    if (PUBLIC_MCP_METHODS.has(method)) continue;
    if (method === "tools/call") continue;

    return true;
  }

  return false;
}

function chatgptAuthRequiredResult() {
  return {
    content: [
      {
        type: "text",
        text: "Authentication required for this tool.",
      },
    ],
    isError: true,
    _meta: {
      "mcp/www_authenticate": [WWW_AUTHENTICATE_HEADER],
    },
  };
}

function forbiddenToolResult(message = "Usuario no autorizado.") {
  return {
    content: [
      {
        type: "text",
        text: message,
      },
    ],
    isError: true,
  };
}

async function verifyToken(req) {
  const token = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];
  if (!token) return null;

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://${AUTHKIT_DOMAIN}`,
    });

    return payload;
  } catch {
    return null;
  }
}

async function getEmailFromUserId(userId) {
  try {
    const user = await workos.userManagement.getUser(userId);
    return user.email;
  } catch (err) {
    return null;
  }
}

async function isUserAllowed(userId, email) {
  const userDomain = email?.split("@")[1];

  try {
    const organization = await workos.organizations.getOrganization(
      process.env.WORKOS_ALLOWED_ORG_ID
    );

    const orgDomains = organization.domains.map((d) => d.domain);

    if (orgDomains.includes(userDomain)) {
      return true;
    }

    const memberships =
      await workos.userManagement.listOrganizationMemberships({
        userId,
        organizationId: process.env.WORKOS_ALLOWED_ORG_ID,
        statuses: ["active"],
      });

    if (memberships.data.length > 0) {
      return true;
    }
  } catch (err) {}

  return false;
}

async function getAuthContext(req) {
  const payload = await verifyToken(req);

  if (!payload) {
    return {
      authenticated: false,
      forbidden: false,
      payload: null,
      email: null,
      reason: "missing_or_invalid_token",
    };
  }

  const email = await getEmailFromUserId(payload.sub);

  if (!email) {
    return {
      authenticated: false,
      forbidden: true,
      payload,
      email: null,
      reason: "email_not_found",
    };
  }

  const allowed = await isUserAllowed(payload.sub, email);

  if (!allowed) {
    return {
      authenticated: false,
      forbidden: true,
      payload,
      email,
      reason: "user_not_allowed",
    };
  }

  return {
    authenticated: true,
    forbidden: false,
    payload,
    email,
    reason: null,
  };
}

function createMcpServer(authContext) {
  const server = new Server(
    { name: "postgres-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: executeQueryTool.name,
        description: "Ejecuta consultas SQL SELECT en PostgreSQL",
        inputSchema: {
          type: "object",
          properties: {
            query: {
              type: "string",
            },
          },
          required: ["query"],
        },

        securitySchemes: TOOL_SECURITY_SCHEMES,

        _meta: {
          securitySchemes: TOOL_SECURITY_SCHEMES,
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (!authContext.authenticated) {
      if (authContext.forbidden) {
        return forbiddenToolResult(
          "Usuario autenticado, pero no autorizado para usar esta herramienta."
        );
      }

      return chatgptAuthRequiredResult();
    }

    if (request.params.name === executeQueryTool.name) {
      return await executeQueryTool.handler(request.params.arguments);
    }

    throw new Error("Tool no encontrada");
  });

  return server;
}

const app = express();
app.use(express.json());

app.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => {
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  });
});

app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  });
});

app.get("/.well-known/oauth-authorization-server", async (_req, res) => {
  const response = await fetch(
    `https://${AUTHKIT_DOMAIN}/.well-known/oauth-authorization-server`
  );

  res.json(await response.json());
});

app.post("/mcp", async (req, res) => {
  try {
    const authContext = await getAuthContext(req);

    if (callsProtectedNonToolMethod(req.body) && !authContext.authenticated) {
      if (authContext.forbidden) {
        return res
          .status(403)
          .set(
            "WWW-Authenticate",
            `Bearer error="insufficient_scope", resource_metadata="${MCP_RESOURCE_METADATA_URL}"`
          )
          .json({
            error: "Usuario no autorizado.",
          });
      }

      return res
        .status(401)
        .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
        .json({
          error: "invalid_token",
          error_description: "Authentication required for this method",
        });
    }

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    const server = createMcpServer(authContext);
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: "Internal error",
        },
        id: null,
      });
    }
  }
});

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "postgres-mcp",
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`MCP server running on port ${PORT}`);
});