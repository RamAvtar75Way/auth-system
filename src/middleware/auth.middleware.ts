import { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "../modules/token/jwt.service";
import { JwtAccessPayload } from "../types/jwt.types";

export interface AuthRequest extends Request {
    user?: JwtAccessPayload;
}

export function authMiddleware(
    req: AuthRequest,
    res: Response,
    next: NextFunction
) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        res.status(401).json({ success: false, error: "Missing authorization header" });
        return;
    }

    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") {
        res.status(401).json({ success: false, error: "Invalid authorization header format" });
        return;
    }

    const token = parts[1];

    try {
        const payload = verifyAccessToken(token);
        req.user = payload;
        next();
    } catch (err) {
        res.status(401).json({ success: false, error: "Invalid access token" });
    }
}
