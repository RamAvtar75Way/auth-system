export interface JwtAccessPayload {
  userId: string
  tokenVersion: number
  type: "access"
}

export interface JwtRefreshPayload {
  userId: string
  tokenVersion: number
  type: "refresh"
}
