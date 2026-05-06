import { WorkOS } from "@workos-inc/node";
import { createRemoteJWKSet, jwtVerify } from "jose";

export async function authMiddleware(req, res, next) {
  const workos = new WorkOS(process.env.WORKOS_API_KEY);

  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token requerido" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const jwksUrl = workos.userManagement.getJwksUrl(process.env.WORKOS_CLIENT_ID);
    const JWKS = createRemoteJWKSet(new URL(jwksUrl));

    const { payload } = await jwtVerify(token, JWKS);

    req.user = payload;
    next();
  } catch (error) {
    console.log("Error verificando token:", error.message);
    return res.status(401).json({ error: "Token inválido o expirado: " + error.message });
  }
}