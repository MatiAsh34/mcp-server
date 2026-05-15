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

const AUTHKIT_DOMAIN = process.env.AUTHKIT_DOMAIN;
const MCP_SERVER_URL = process.env.MCP_SERVER_URL;

const JWKS = createRemoteJWKSet(
  new URL(`https://${AUTHKIT_DOMAIN}/oauth2/jwks`)
);

const MCP_RESOURCE_METADATA_URL = `${MCP_SERVER_URL}/.well-known/oauth-protected-resource/mcp`;

const WWW_AUTHENTICATE_HEADER = [
  'Bearer error="unauthorized"',
  'error_description="Authorization needed"',
  `resource_metadata="${MCP_RESOURCE_METADATA_URL}"`,
].join(', ');

const app = express();

app.use(express.json());

app.get("/.well-known/oauth-protected-resource/mcp", (req, res) => {
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  });
});

app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  });
});

app.get('/.well-known/oauth-authorization-server', async (req, res) => {
  const response = await fetch(
    'https://seamless-ice-72-staging.authkit.app/.well-known/oauth-authorization-server',
  );
  const metadata = await response.json();

  res.json(metadata);
});

function checkAllowedDomain(email) {
  const domain = email?.split("@")[1];
  const ALLOWED_DOMAINS = (process.env.ALLOWED_DOMAINS || "").split(",");

  if (!domain || !ALLOWED_DOMAINS.includes(domain)) {
    return { allowed: false, domain };
  }

  return { allowed: true, domain };
}

async function getEmailFromToken(token) {
  const response = await fetch(`https://${AUTHKIT_DOMAIN}/oauth2/userinfo`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  console.log("userinfo status:", response.status); 

  if (!response.ok) return null;

  const data = await response.json();

  console.log("userinfo data:", JSON.stringify(data));

  return data.email;
}

async function bearerTokenMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.match(/^Bearer (.+)$/)?.[1];

  if (!token) {
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "No token provided." });
  }

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://${AUTHKIT_DOMAIN}`,
    });

    console.log("JWT ok, sub:", payload.sub);

    const email = await getEmailFromToken(token);

    console.log("email obtenido:", email);

    if (!email) {
      return res
        .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
        .status(401)
        .json({ error: "No se pudo obtener el email del usuario." });
    }

    const { allowed, domain } = checkAllowedDomain(email);

    console.log("dominio:", domain, "| permitido:", allowed);

    if (!allowed) {
      return res
        .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
        .status(403)
        .json({ error: `Dominio no autorizado: ${domain}` });
    }

    req.userId = payload.sub;
    req.userEmail = email;

    next();
  } catch (err) {
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "Invalid bearer token." });
  }
}

function createMcpServer() {
  const server = new Server(
    { name: "postgres-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: executeQueryTool.name,
          description: "Ejecuta consultas SQL SELECT en PostgreSQL",
          inputSchema: {
            type: "object",
            properties: {
              query: { type: "string" },
            },
            required: ["query"],
          },
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name === executeQueryTool.name) {
      return await executeQueryTool.handler(request.params.arguments);
    }

    throw new Error("Tool no encontrada");
  });

  return server;
}

app.post("/mcp", bearerTokenMiddleware, async (req, res) => {
  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    const server = createMcpServer();

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/", (req, res) => {
  res.json({ ok: true, service: "postgres-mcp" });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`MCP server running on port ${PORT}`);
});