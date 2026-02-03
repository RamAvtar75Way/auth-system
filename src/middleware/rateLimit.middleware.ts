import { Request, Response, NextFunction } from "express";
import { checkRateLimit } from "../utils/rate-limit";
import { getClientIp } from "../utils/ip";

export function rateLimit(windowMs: number, max: number) {
    return (req: Request, res: Response, next: NextFunction) => {
        const ip = getClientIp(req);
        const result = checkRateLimit(ip, { windowMs, max });

        if (!result.allowed) {
            res.status(429).json({
                success: false,
                error: "Too many requests, please try again later.",
            });
            return;
        }

        next();
    };
}
