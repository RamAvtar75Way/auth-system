import { Response } from "express";

export function setRefreshCookie(res: Response, token: string): void {
  res.cookie("refresh_token", token, {
    httpOnly: true,
    secure: true, // Should be true in prod, maybe process.env.NODE_ENV === 'production'
    sameSite: "strict",
    path: "/",
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  });
}

export function clearRefreshCookie(res: Response): void {
  res.cookie("refresh_token", "", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: 0,
  });
}
