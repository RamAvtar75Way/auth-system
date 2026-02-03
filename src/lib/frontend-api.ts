"use client"

let accessToken: string | null = null

export function setAccessToken(token: string | null): void {
  accessToken = token
}

async function refreshAccessToken(): Promise<string | null> {
  const res = await fetch("/api/auth/refresh", {
    method: "POST",
    credentials: "include",
  })

  if (!res.ok) return null

  const json: unknown = await res.json()

  if (
    typeof json === "object" &&
    json !== null &&
    "success" in json &&
    json.success === true &&
    "data" in json &&
    typeof json.data === "object" &&
    json.data !== null &&
    "accessToken" in json.data &&
    typeof (json.data as { accessToken: unknown }).accessToken === "string"
  ) {
    return (json.data as { accessToken: string }).accessToken
  }

  return null
}

export async function apiFetch(
  input: RequestInfo,
  init: RequestInit = {}
): Promise<Response> {
  const headers = new Headers(init.headers)

  if (accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`)
  }

  const res = await fetch(input, {
    ...init,
    headers,
    credentials: "include",
  })

  if (res.status !== 401) {
    return res
  }

  const newToken = await refreshAccessToken()

  if (!newToken) {
    return res
  }

  accessToken = newToken

  headers.set("Authorization", `Bearer ${newToken}`)

  return fetch(input, {
    ...init,
    headers,
    credentials: "include",
  })
}
