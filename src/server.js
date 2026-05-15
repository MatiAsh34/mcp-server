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
import { WorkOS } from "@workos-inc/node";

import { executeQueryTool } from "./tools/executeQuery.js";

const AUTHKIT_DOMAIN = process.env.AUTHKIT_DOMAIN;
const MCP_SERVER_URL = process.env.MCP_SERVER_URL;
const WORKOS_API_KEY = process.env.WORKOS_API_KEY;
const WORKOS_ORG_ID = process.env.WORKOS_ORG_ID;

const workos = new WorkOS(WORKOS_API_KEY);

const JWKS = createRemoteJWKSet(
  new URL(`https://${AUTHKIT_DOMAIN}/oauth2/jwks`)
);

const MCP_RESOURCE_METADATA_URL = `${MCP_SERVER_URL}/.well-known/oauth-protected-resource/mcp`;

const WWW_AUTHENTICATE_HEADER = [
  'Bearer error="unauthorized"',
  'error_description="Authorization needed"',
  `resource_metadata="${MCP_RESOURCE_METADATA_URL}"`,
].join(", ");

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

app.get("/.well-known/oauth-authorization-server", async (req, res) => {
  try {
    const response = await fetch(
      `https://${AUTHKIT_DOMAIN}/.well-known/oauth-authorization-server`
    );

    if (!response.ok) {
      return res.status(502).json({
        error: "Could not fetch OAuth authorization server metadata",
      });
    }

    const metadata = await response.json();
    res.json(metadata);
  } catch (err) {
    console.error("OAuth metadata error:", err);

    res.status(500).json({
      error: "Internal server error",
    });
  }
});

function extractDomainsFromOrganization(organization) {
  const rawDomains =
    organization.domainData ||
    organization.domains ||
    organization.verifiedDomains ||
    [];

  return rawDomains
    .map((item) => {
      if (typeof item === "string") {
        return item;
      }

      return item.domain || item.name;
    })
    .filter(Boolean)
    .map((domain) => domain.toLowerCase());
}

async function getAllowedOrganizationDomains() {
  const organization = await workos.organizations.getOrganization(WORKOS_ORG_ID);

  const domains = extractDomainsFromOrganization(organization);

  if (!domains.length) {
    throw new Error(
      `Organization ${WORKOS_ORG_ID} does not have any configured domains`
    );
  }

  return domains;
}

async function getWorkOSUserEmail(userId) {
  const user = await workos.userManagement.getUser(userId);

  if (!user?.email) {
    return null;
  }

  return user.email.toLowerCase();
}

async function isUserActiveMemberOfOrganization(userId) {
  const memberships = await workos.userManagement.listOrganizationMemberships({
    organizationId: WORKOS_ORG_ID,
    userId,
    statuses: ["active"],
    limit: 1,
  });

  return memberships.data.length > 0;
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

    const userId = payload.sub;

    if (!userId) {
      return res.status(403).json({
        error: "Missing user id in bearer token.",
      });
    }

    const isActiveMember = await isUserActiveMemberOfOrganization(userId);

    if (!isActiveMember) {
      return res.status(403).json({
        error: "User is not an active member of the allowed organization.",
      });
    }

    const emailFromToken = payload.email
      ? String(payload.email).toLowerCase()
      : null;

    const email = emailFromToken || (await getWorkOSUserEmail(userId));

    if (!email) {
      return res.status(403).json({
        error: "Could not resolve user email.",
      });
    }

    const emailDomain = email.split("@")[1]?.toLowerCase();

    if (!emailDomain) {
      return res.status(403).json({
        error: "Invalid user email.",
      });
    }

    const allowedDomains = await getAllowedOrganizationDomains();

    if (!allowedDomains.includes(emailDomain)) {
      return res.status(403).json({
        error: "User email domain is not allowed for this organization.",
      });
    }

    req.userId = userId;
    req.userEmail = email;
    req.organizationId = WORKOS_ORG_ID;

    return next();
  } catch (err) {
    console.error("Auth error:", err);

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
    console.error("MCP error:", err);

    res.status(500).json({
      error: "Internal server error",
    });
  }
});

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "postgres-mcp",
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`MCP server running on port ${PORT}`);
});