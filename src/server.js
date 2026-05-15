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
  const response = await fetch(
    "https://seamless-ice-72-staging.authkit.app/.well-known/oauth-authorization-server"
  );
  const metadata = await response.json();
  res.json(metadata);
});

async function getEmailFromUserId(userId) {
  try {
    const user = await workos.userManagement.getUser(userId);
    return user.email;
  } catch (err) {
    console.error("Error obteniendo usuario de WorkOS:", err.message);
    return null;
  }
}

// FIX 2: auto-enrola al usuario en la org si aún no es miembro
async function ensureOrgMembership(userId) {
  try {
    const existing = await workos.userManagement.listOrganizationMemberships({
      userId,
      organizationId: process.env.WORKOS_ALLOWED_ORG_ID,
    });

    if (existing.data.length === 0) {
      await workos.userManagement.createOrganizationMembership({
        userId,
        organizationId: process.env.WORKOS_ALLOWED_ORG_ID,
        roleSlug: "member",
      });
      console.log(`Membresía creada automáticamente para userId: ${userId}`);
    }
  } catch (err) {
    // No es fatal: el acceso por dominio ya fue aprobado
    console.warn("No se pudo crear membresía automática:", err.message);
  }
}

async function isUserAllowed(userId, email) {
  const userDomain = email?.split("@")[1];

  try {
    const organization = await workos.organizations.getOrganization(
      process.env.WORKOS_ALLOWED_ORG_ID
    );

    // FIX 1: solo dominios con state "verified", ignorar pendientes
    const orgDomains = organization.domains
      .filter((d) => d.state === "verified")
      .map((d) => d.domain);

    console.log("Dominios verificados de la org:", orgDomains);

    // Regla 1: dominio verificado → acceso + auto-enrolamiento
    if (orgDomains.includes(userDomain)) {
      console.log(`Acceso por dominio verificado: ${userDomain}`);
      await ensureOrgMembership(userId); // FIX 2
      return true;
    }

    // Regla 2: miembro directo activo de la organización
    const memberships = await workos.userManagement.listOrganizationMemberships(
      {
        userId,
        organizationId: process.env.WORKOS_ALLOWED_ORG_ID,
        statuses: ["active"],
      }
    );

    if (memberships.data.length > 0) {
      console.log(`Acceso por membresía WorkOS: ${email}`);
      return true;
    }
  } catch (err) {
    console.error("Error verificando acceso:", err.message);
  }

  return false;
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

    // FIX 3: log del payload para detectar si sub tiene el formato correcto
    console.log("JWT payload:", JSON.stringify(payload, null, 2));

    // FIX 3: asegurar que sub sea el userId en formato user_XXXX
    const userId = payload.sub?.startsWith("user_")
      ? payload.sub
      : (payload.sid ?? payload["workos_user_id"] ?? payload.sub);

    if (!userId) {
      return res
        .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
        .status(401)
        .json({ error: "No se pudo extraer el userId del token." });
    }

    const email = await getEmailFromUserId(userId);

    if (!email) {
      return res
        .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
        .status(401)
        .json({ error: "No se pudo obtener el email del usuario." });
    }

    const allowed = await isUserAllowed(userId, email);
    if (!allowed) {
      return res
        .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
        .status(403)
        .json({ error: "Usuario no autorizado." });
    }

    next();
  } catch (err) {
    console.error("Error verificando token:", err.message);
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
    console.error("Error en /mcp:", err.message);
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