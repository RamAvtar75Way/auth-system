import jwt from "jsonwebtoken"
import { getEnv } from "@/utils/env"
import type { JwtAccessPayload, JwtRefreshPayload } from "@/types/jwt"

const ACCESS_SECRET = getEnv("JWT_ACCESS_SECRET")
const REFRESH_SECRET = getEnv("JWT_REFRESH_SECRET")

const ACCESS_TTL = "15m"
const REFRESH_TTL = "7d"

export function signAccessToken(payload: JwtAccessPayload): string {
  return jwt.sign(payload, ACCESS_SECRET, {
    expiresIn: ACCESS_TTL,
  })
}

export function signRefreshToken(payload: JwtRefreshPayload): string {
  return jwt.sign(payload, REFRESH_SECRET, {
    expiresIn: REFRESH_TTL,
  })
}

export function verifyAccessToken(token: string): JwtAccessPayload {
  return jwt.verify(token, ACCESS_SECRET) as JwtAccessPayload
}

export function verifyRefreshToken(token: string): JwtRefreshPayload {
  return jwt.verify(token, REFRESH_SECRET) as JwtRefreshPayload
}
