import { NextRequest, NextResponse } from "next/server"
import { connectDB } from "@/lib/db"
import { User } from "@/models/User"
import { TwoFactorSchema, TwoFactorInput } from "@/lib/validators/auth"
import { sha256 } from "@/utils/hash"
import { signAccessToken, signRefreshToken } from "@/lib/jwt"
import { setRefreshCookie } from "@/utils/cookies"
import type { ApiResponse } from "@/types/api"
import type { TwoFactorVerifyData } from "@/types/auth"
import { checkRateLimit } from "@/lib/rete-limit"


export async function POST(
  req: NextRequest
): Promise<NextResponse<ApiResponse<TwoFactorVerifyData>>> {
  try {
    const json: unknown = await req.json()
    const parsed: TwoFactorInput = TwoFactorSchema.parse(json)
    const rl = checkRateLimit(parsed.userId + ":2fa", {
      windowMs: 10 * 60 * 1000,
      max: 5,
    })

    if (!rl.allowed) {
      return NextResponse.json(
        { success: false, error: "Too many OTP attempts" } as const,
        { status: 429 }
      )
    }


    await connectDB()

    const user = await User.findById(parsed.userId)

    if (!user || !user.twoFactorEnabled) {
      return NextResponse.json(
        { success: false, error: "Invalid request" } as const,
        { status: 400 }
      )
    }

    if (!user.twoFactorCodeHash || !user.twoFactorExpiry) {
      return NextResponse.json(
        { success: false, error: "No 2FA code set" } as const,
        { status: 400 }
      )
    }

    if (user.twoFactorExpiry.getTime() < Date.now()) {
      return NextResponse.json(
        { success: false, error: "2FA code expired" } as const,
        { status: 400 }
      )
    }

    const codeHash = sha256(parsed.code)

    if (codeHash !== user.twoFactorCodeHash) {
      return NextResponse.json(
        { success: false, error: "Invalid code" } as const,
        { status: 401 }
      )
    }

    // ✅ clear OTP so it cannot be reused
    user.twoFactorCodeHash = undefined
    user.twoFactorExpiry = undefined

    const accessToken = signAccessToken({
      userId: user._id.toString(),
      tokenVersion: user.tokenVersion,
      type: "access",
    })

    const refreshToken = signRefreshToken({
      userId: user._id.toString(),
      tokenVersion: user.tokenVersion,
      type: "refresh",
    })

    user.refreshTokenHash = sha256(refreshToken)

    await user.save()

    const res = NextResponse.json({
      success: true,
      data: {
        accessToken,
      },
    } as const)

    setRefreshCookie(res, refreshToken)

    return res
  } catch (error) {
    if (error instanceof Error) {
      return NextResponse.json(
        { success: false, error: error.message } as const,
        { status: 400 }
      )
    }

    return NextResponse.json(
      { success: false, error: "2FA verification failed" } as const,
      { status: 500 }
    )
  }
}
