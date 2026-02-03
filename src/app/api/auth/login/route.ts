import { NextRequest, NextResponse } from "next/server"
import { connectDB } from "@/lib/db"
import { User } from "@/models/User"
import { LoginSchema, LoginInput } from "@/lib/validators/auth"
import { verifyPassword, sha256 } from "@/utils/hash"
import { generateOtpCode, otpExpiry } from "@/lib/otp"
import { sendMail } from "@/lib/mail"
import { otpEmailTemplate } from "@/lib/mail-templates"
import type { ApiResponse } from "@/types/api"
import type { LoginSuccessData } from "@/types/auth"
import { signAccessToken, signRefreshToken } from "@/lib/jwt"
import { setRefreshCookie } from "@/utils/cookies"
import { checkRateLimit } from "@/lib/rete-limit"
import { getClientIp } from "@/utils/ip"



const MAX_FAILED = 5
const LOCK_MINUTES = 15

export async function POST(
  req: NextRequest
): Promise<NextResponse<ApiResponse<LoginSuccessData>>> {
  try {

    const ip = getClientIp(req)

    const rl = checkRateLimit(ip + ":login", {
      windowMs: 10 * 60 * 1000,
      max: 5,
    })

    if (!rl.allowed) {
      return NextResponse.json(
        { success: false, error: "Too many login attempts" } as const,
        { status: 429 }
      )
    }

    const json: unknown = await req.json()
    const parsed: LoginInput = LoginSchema.parse(json)

    await connectDB()

    const user = await User.findOne({ email: parsed.email })

    if (!user || !user.passwordHash) {
      return NextResponse.json(
        { success: false, error: "Invalid credentials" },
        { status: 401 }
      )
    }

    if (!user.isEmailVerified) {
      return NextResponse.json(
        { success: false, error: "Email not verified" },
        { status: 403 }
      )
    }

    if (user.lockUntil && user.lockUntil.getTime() > Date.now()) {
      return NextResponse.json(
        { success: false, error: "Account temporarily locked" },
        { status: 423 }
      )
    }

    const ok = await verifyPassword(parsed.password, user.passwordHash)

    if (!ok) {
      user.failedLoginAttempts += 1

      if (user.failedLoginAttempts >= MAX_FAILED) {
        user.lockUntil = otpExpiry(LOCK_MINUTES)
        user.failedLoginAttempts = 0
      }

      await user.save()

      return NextResponse.json(
        { success: false, error: "Invalid credentials" },
        { status: 401 }
      )
    }

    user.failedLoginAttempts = 0
    user.lockUntil = undefined


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
      })
    }

    await user.save()

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

  } catch (error) {
    if (error instanceof Error) {
      return NextResponse.json(
        { success: false, error: error.message },
        { status: 400 }
      )
    }

    return NextResponse.json(
      { success: false, error: "Login failed" },
      { status: 500 }
    )
  }
}
