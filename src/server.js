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
  `Bearer resource_metadata="${MCP_RESOURCE_METADATA_URL}"`,
  'error="invalid_token"',
  'error_description="Authentication required for this tool"',
].join(", ");

const TOOL_SECURITY_SCHEMES = [
  {
    type: "oauth2",
    scopes: [],
  },
];

const PUBLIC_MCP_METHODS = new Set([
  "initialize",
  "notifications/initialized",
  "ping",
  "tools/list",
]);

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

function authRequiredToolResult(message = "Authentication required for this tool.") {
  return {
    content: [
      {
        type: "text",
        text: message,
      },
    ],
    _meta: {
      "mcp/www_authenticate": [WWW_AUTHENTICATE_HEADER],
    },
    isError: true,
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
  } catch (err) {
  }

  return false;
}

function createMcpServer(authContext = { ok: false, reason: "missing_token" }) {
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
    if (request.params.name === executeQueryTool.name) {
      if (!authContext.ok) {
        if (authContext.reason === "forbidden") {
          return forbiddenToolResult("Usuario no autorizado.");
        }

        if (authContext.reason === "missing_email") {
          return authRequiredToolResult(
            "Authentication failed: no se pudo obtener el email del usuario."
          );
        }

        return authRequiredToolResult("Authentication required for this tool.");
      }

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
    let authContext = {
      ok: false,
      reason: "missing_token",
      payload: null,
      email: null,
    };

    if (callsProtectedMethod(req.body)) {
      const payload = await verifyToken(req);

      if (!payload) {
        authContext = {
          ok: false,
          reason: "missing_token",
          payload: null,
          email: null,
        };
      } else {
        const email = await getEmailFromUserId(payload.sub);

        if (!email) {
          authContext = {
            ok: false,
            reason: "missing_email",
            payload,
            email: null,
          };
        } else {
          const allowed = await isUserAllowed(payload.sub, email);

          authContext = {
            ok: allowed,
            reason: allowed ? null : "forbidden",
            payload,
            email,
          };
        }
      }
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
        error: { code: -32603, message: "Internal error" },
        id: null,
      });
    }
  }
});

app.get("/", (_req, res) => res.json({ ok: true, service: "postgres-mcp" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MCP server running on port ${PORT}`));