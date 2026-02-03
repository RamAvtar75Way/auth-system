import { Router } from "express";
import * as c from "./auth.controller";
import { authMiddleware } from "../../middleware/auth.middleware";
import { rateLimit } from "../../middleware/rateLimit.middleware";

const r = Router();

const loginLimit = rateLimit(10 * 60 * 1000, 100);
const limit = rateLimit(15 * 60 * 1000, 100);

r.post("/signup", limit, c.signup);
r.post("/login", loginLimit, c.login);
r.post("/verify-email", limit, c.verifyEmail);
r.post("/verify-2fa", limit, c.verify2fa);
r.post("/refresh", c.refresh);
r.post("/logout", c.logout);
r.post("/forgot-password", limit, c.forgot);
r.post("/reset-password", limit, c.reset);
r.post("/google-login", loginLimit, c.googleLogin);

r.get("/me", authMiddleware, c.getMe);
r.post("/2fa/enable", authMiddleware, c.enable2fa);
r.post("/2fa/disable", authMiddleware, c.disable2fa);

export default r;
