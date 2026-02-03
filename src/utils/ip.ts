import { Request } from "express";

export function getClientIp(req: Request): string {
  const xForwardedFor = req.headers["x-forwarded-for"];
  if (Array.isArray(xForwardedFor)) {
    return xForwardedFor[0];
  }
  if (typeof xForwardedFor === "string") {
    return xForwardedFor.split(",")[0].trim();
  }
  return req.ip || "unknown";
}
