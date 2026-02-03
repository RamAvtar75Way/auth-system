import { NextRequest, NextResponse } from "next/server"
import { connectDB } from "@/lib/db"
import { User } from "@/models/User"
import { verifyRefreshToken, signAccessToken, signRefreshToken } from "@/lib/jwt"
import { sha256 } from "@/utils/hash"
import { setRefreshCookie } from "@/utils/cookies"
import type { ApiResponse } from "@/types/api"
import type { LoginSuccessData } from "@/types/auth"

export async function POST(
  req: NextRequest
): Promise<NextResponse<ApiResponse<LoginSuccessData>>> {
  try {
    const refreshToken = req.cookies.get("refresh_token")?.value

    if (!refreshToken) {
      return NextResponse.json(
        { success: false, error: "Missing refresh token" } as const,
        { status: 401 }
      )
    }

    const payload = verifyRefreshToken(refreshToken)

    if (payload.type !== "refresh") {
      return NextResponse.json(
        { success: false, error: "Invalid token type" } as const,
        { status: 401 }
      )
    }

    await connectDB()

    const user = await User.findById(payload.userId)

    if (!user) {
      return NextResponse.json(
        { success: false, error: "User not found" } as const,
        { status: 404 }
      )
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return NextResponse.json(
        { success: false, error: "Token revoked" } as const,
        { status: 401 }
      )
    }

    const incomingHash = sha256(refreshToken)

    if (!user.refreshTokenHash || incomingHash !== user.refreshTokenHash) {
      return NextResponse.json(
        { success: false, error: "Invalid refresh token" } as const,
        { status: 401 }
      )
    }

    const newAccessToken = signAccessToken({
      userId: user._id.toString(),
      tokenVersion: user.tokenVersion,
      type: "access",
    })

    const newRefreshToken = signRefreshToken({
      userId: user._id.toString(),
      tokenVersion: user.tokenVersion,
      type: "refresh",
    })

    user.refreshTokenHash = sha256(newRefreshToken)
    await user.save()

    const res = NextResponse.json({
      success: true,
      data: {
        accessToken: newAccessToken,
        requiresTwoFactor: false,
      },
    } as const)

    setRefreshCookie(res, newRefreshToken)

    return res
  } catch {
    return NextResponse.json(
      { success: false, error: "Refresh failed" } as const,
      { status: 401 }
    )
  }
}
