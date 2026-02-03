import { NextResponse } from "next/server"

export function setRefreshCookie(
  res: NextResponse,
  token: string
): void {
  res.cookies.set({
    name: "refresh_token",
    value: token,
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: 60 * 60 * 24 * 7,
  })
}

export function clearRefreshCookie(res: NextResponse): void {
  res.cookies.set({
    name: "refresh_token",
    value: "",
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: 0,
  })
}
