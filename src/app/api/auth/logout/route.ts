import { NextRequest, NextResponse } from "next/server"
import { connectDB } from "@/lib/db"
import { User } from "@/models/User"
import { verifyRefreshToken } from "@/lib/jwt"
import { clearRefreshCookie } from "@/utils/cookies"
import type { ApiResponse } from "@/types/api"
import type { MessageData } from "@/types/auth"

export async function POST(
  req: NextRequest
): Promise<NextResponse<ApiResponse<MessageData>>> {
  try {
    const refreshToken = req.cookies.get("refresh_token")?.value

    if (!refreshToken) {
      const res = NextResponse.json({
        success: true,
        data: { message: "Logged out" },
      } as const)

      clearRefreshCookie(res)
      return res
    }

    const payload = verifyRefreshToken(refreshToken)

    await connectDB()

    const user = await User.findById(payload.userId)

    if (user) {
      // evoke current refresh token
      user.refreshTokenHash = undefined

      // optional global logout switch:
      // user.tokenVersion += 1

      await user.save()
    }

    const res = NextResponse.json({
      success: true,
      data: { message: "Logged out" },
    } as const)

    clearRefreshCookie(res)

    return res
  } catch {
    const res = NextResponse.json({
      success: true,
      data: { message: "Logged out" },
    } as const)

    clearRefreshCookie(res)
    return res
  }
}
