import { WorkOS } from "@workos-inc/node";

export function setupAuthRoutes(app) {
  const workos = new WorkOS(process.env.WORKOS_API_KEY);
  const clientId = process.env.WORKOS_CLIENT_ID;
  const redirectUri = process.env.WORKOS_REDIRECT_URI;

  app.get("/auth/login", (req, res) => {
    const authorizationUrl = workos.userManagement.getAuthorizationUrl({
      provider: "GoogleOAuth",
      redirectUri,
      clientId,
    });
    res.redirect(authorizationUrl);
  });

  app.get("/auth/callback", async (req, res) => {
    const { code } = req.query;

    try {
      const { user, accessToken } = await workos.userManagement.authenticateWithCode({
        code,
        clientId,
      });

      res.json({
        message: "Login exitoso",
        user: {
          email: user.email,
          firstName: user.firstName,
        },
        accessToken,
      });
    } catch (error) {
      res.status(401).json({ error: "Autenticación fallida: " + error.message });
    }
  });
}