import { NextRequest, NextResponse } from "next/server"
import { connectDB } from "@/lib/db"
import { User } from "@/models/User"
import { VerifyEmailSchema, VerifyEmailInput } from "@/lib/validators/auth"
import { sha256 } from "@/utils/hash"
import type { ApiResponse } from "@/types/api"
import type { MessageData } from "@/types/auth"

export async function POST(
  req: NextRequest
): Promise<NextResponse<ApiResponse<MessageData>>> {
  try {
    const json: unknown = await req.json()
    const parsed: VerifyEmailInput = VerifyEmailSchema.parse(json)

    await connectDB()

    const user = await User.findOne({ email: parsed.email })

    if (!user) {
      return NextResponse.json(
        { success: false, error: "User not found" },
        { status: 404 }
      )
    }

    if (user.isEmailVerified) {
      return NextResponse.json({
        success: true,
        data: { message: "Email already verified" },
      })
    }

    if (!user.emailVerifyCodeHash || !user.emailVerifyExpiry) {
      return NextResponse.json(
        { success: false, error: "No verification code set" },
        { status: 400 }
      )
    }

    if (user.emailVerifyExpiry.getTime() < Date.now()) {
      return NextResponse.json(
        { success: false, error: "Verification code expired" },
        { status: 400 }
      )
    }

    const codeHash = sha256(parsed.code)

    if (codeHash !== user.emailVerifyCodeHash) {
      return NextResponse.json(
        { success: false, error: "Invalid verification code" },
        { status: 400 }
      )
    }

    user.isEmailVerified = true
    user.emailVerifyCodeHash = undefined
    user.emailVerifyExpiry = undefined

    await user.save()

    return NextResponse.json({
      success: true,
      data: { message: "Email verified successfully" },
    })
  } catch (error) {
    if (error instanceof Error) {
      return NextResponse.json(
        { success: false, error: error.message },
        { status: 400 }
      )
    }

    return NextResponse.json(
      { success: false, error: "Verification failed" },
      { status: 500 }
    )
  }
}
