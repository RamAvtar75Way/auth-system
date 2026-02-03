import { NextRequest, NextResponse } from "next/server"
import { OAuth2Client } from "google-auth-library"
import { connectDB } from "@/lib/db"
import { User } from "@/models/User"
import { signAccessToken, signRefreshToken } from "@/lib/jwt"
import { sha256 } from "@/utils/hash"
import { setRefreshCookie } from "@/utils/cookies"
import { generateOtpCode, otpExpiry } from "@/lib/otp"
import { sendMail } from "@/lib/mail"
import { otpEmailTemplate } from "@/lib/mail-templates"
import { getEnv } from "@/utils/env"
import type { ApiResponse } from "@/types/api"
import type { LoginSuccessData } from "@/types/auth"

interface GoogleBody {
  idToken: string
}

const client = new OAuth2Client(getEnv("GOOGLE_CLIENT_ID"))

export async function POST(
  req: NextRequest
): Promise<NextResponse<ApiResponse<LoginSuccessData>>> {
  try {
    const body: unknown = await req.json()

    if (
      typeof body !== "object" ||
      body === null ||
      !("idToken" in body) ||
      typeof (body as GoogleBody).idToken !== "string"
    ) {
      return NextResponse.json(
        { success: false, error: "Invalid body" } as const,
        { status: 400 }
      )
    }

    const { idToken } = body as GoogleBody

    const ticket = await client.verifyIdToken({
      idToken,
      audience: getEnv("GOOGLE_CLIENT_ID"),
    })

    const payload = ticket.getPayload()

    if (!payload || !payload.email || !payload.sub) {
      return NextResponse.json(
        { success: false, error: "Invalid Google token" } as const,
        { status: 401 }
      )
    }

    await connectDB()

    let user = await User.findOne({ email: payload.email })

    if (!user) {
      user = await User.create({
        email: payload.email,
        googleId: payload.sub,
        isEmailVerified: true,
      })
    } else if (!user.googleId) {
      user.googleId = payload.sub
    }

    // 2FA if enabled
    if (user.twoFactorEnabled) {
      const otp = generateOtpCode()
      user.twoFactorCodeHash = sha256(otp)
      user.twoFactorExpiry = otpExpiry(10)

      await user.save()

      await sendMail(
        user.email,
        "Your login verification code",
        otpEmailTemplate(otp)
      )

      return NextResponse.json({
        success: true,
        data: {
          accessToken: "",
          requiresTwoFactor: true,
          userId: user._id.toString(),
        },
      } as const)
    }

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
        requiresTwoFactor: false,
      },
    } as const)

    setRefreshCookie(res, refreshToken)

    return res
  } catch {
    return NextResponse.json(
      { success: false, error: "Google login failed" } as const,
      { status: 401 }
    )
  }
}
