import { NextRequest, NextResponse } from "next/server"
import { connectDB } from "@/lib/db"
import { User } from "@/models/User"
import { ResetPasswordSchema, ResetPasswordInput } from "@/lib/validators/auth"
import { hashPassword, sha256 } from "@/utils/hash"
import type { ApiResponse } from "@/types/api"
import type { MessageData } from "@/types/auth"
import { checkRateLimit } from "@/lib/rete-limit"
import { getClientIp } from "@/utils/ip"


export async function POST(
  req: NextRequest
): Promise<NextResponse<ApiResponse<MessageData>>> {
  try {
    const ip = getClientIp(req)

    const rl = checkRateLimit(ip + ":forgot", {
      windowMs: 15 * 60 * 1000,
      max: 3,
    })

    if (!rl.allowed) {
      return NextResponse.json(
        { success: false, error: "Too many reset requests" } as const,
        { status: 429 }
      )
    }

    const json: unknown = await req.json()
    const parsed: ResetPasswordInput = ResetPasswordSchema.parse(json)

    await connectDB()

    const tokenHash = sha256(parsed.token)

    const user = await User.findOne({
      resetPasswordTokenHash: tokenHash,
    })

    if (!user || !user.resetPasswordExpiry) {
      return NextResponse.json(
        { success: false, error: "Invalid reset token" } as const,
        { status: 400 }
      )
    }

    if (user.resetPasswordExpiry.getTime() < Date.now()) {
      return NextResponse.json(
        { success: false, error: "Reset token expired" } as const,
        { status: 400 }
      )
    }

    // set new password
    user.passwordHash = await hashPassword(parsed.password)

    // clear reset fields
    user.resetPasswordTokenHash = undefined
    user.resetPasswordExpiry = undefined

    // revoke all sessions
    user.tokenVersion += 1
    user.refreshTokenHash = undefined

    // unlock account if locked
    user.failedLoginAttempts = 0
    user.lockUntil = undefined

    await user.save()

    return NextResponse.json({
      success: true,
      data: { message: "Password reset successful" },
    } as const)
  } catch (error) {
    if (error instanceof Error) {
      return NextResponse.json(
        { success: false, error: error.message } as const,
        { status: 400 }
      )
    }

    return NextResponse.json(
      { success: false, error: "Reset failed" } as const,
      { status: 500 }
    )
  }
}
