import { NextRequest } from "next/server"

export function getClientIp(req: NextRequest): string {
  const forwarded = req.headers.get("x-forwarded-for")

  if (forwarded) {
    const first = forwarded.split(",")[0]
    if (first) {
      return first.trim()
    }
  }

  return "unknown"
}
