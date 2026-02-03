import { NextRequest, NextResponse } from "next/server"
import crypto from "crypto"
import { connectDB } from "@/lib/db"
import { User } from "@/models/User"
import { ForgotPasswordSchema, ForgotPasswordInput } from "@/lib/validators/auth"
import { sha256 } from "@/utils/hash"
import { sendMail } from "@/lib/mail"
import type { ApiResponse } from "@/types/api"
import type { MessageData } from "@/types/auth"

function resetEmailTemplate(link: string): string {
  return `
    <div style="font-family:sans-serif">
      <h2>Password Reset</h2>
      <p>Click the link below to reset your password:</p>
      <a href="${link}">${link}</a>
      <p>This link expires in 30 minutes.</p>
    </div>
  `
}

export async function POST(
  req: NextRequest
): Promise<NextResponse<ApiResponse<MessageData>>> {
  try {
    const json: unknown = await req.json()
    const parsed: ForgotPasswordInput = ForgotPasswordSchema.parse(json)

    await connectDB()

    const user = await User.findOne({ email: parsed.email })

    // always return success — prevent email enumeration
    if (!user) {
      return NextResponse.json({
        success: true,
        data: { message: "If the email exists, a reset link was sent" },
      } as const)
    }

    const rawToken = crypto.randomBytes(32).toString("hex")
    const tokenHash = sha256(rawToken)

    user.resetPasswordTokenHash = tokenHash
    user.resetPasswordExpiry = new Date(Date.now() + 30 * 60 * 1000)

    await user.save()

    const link = `${process.env.APP_URL}/reset-password?token=${rawToken}`

    await sendMail(
      user.email,
      "Reset your password",
      resetEmailTemplate(link)
    )

    return NextResponse.json({
      success: true,
      data: { message: "If the email exists, a reset link was sent" },
    } as const)
  } catch (error) {
    if (error instanceof Error) {
      return NextResponse.json(
        { success: false, error: error.message } as const,
        { status: 400 }
      )
    }

    return NextResponse.json(
      { success: false, error: "Request failed" } as const,
      { status: 500 }
    )
  }
}
