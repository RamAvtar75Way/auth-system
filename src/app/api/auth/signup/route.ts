import { NextRequest, NextResponse } from "next/server"
import { connectDB } from "@/lib/db"
import { User } from "@/models/User"
import { SignupSchema, SignupInput } from "@/lib/validators/auth"
import { hashPassword, sha256 } from "@/utils/hash"
import { generateOtpCode, otpExpiry } from "@/lib/otp"
import type { ApiResponse } from "@/types/api"
import type { SignupSuccessData } from "@/types/auth"

export async function POST(
  req: NextRequest
): Promise<NextResponse<ApiResponse<SignupSuccessData>>> {
  try {
    const json: unknown = await req.json()

    const parsed: SignupInput = SignupSchema.parse(json)

    await connectDB()

    const existing = await User.findOne({ email: parsed.email }).lean()

    if (existing) {
      return NextResponse.json(
        { success: false, error: "Email already registered" },
        { status: 400 }
      )
    }

    const passwordHash = await hashPassword(parsed.password)

    const otp = generateOtpCode()
    const otpHash = sha256(otp)

    const user = await User.create({
      email: parsed.email,
      passwordHash,
      isEmailVerified: false,
      emailVerifyCodeHash: otpHash,
      emailVerifyExpiry: otpExpiry(10),
    })

    console.log("EMAIL OTP:", otp)

    return NextResponse.json({
      success: true,
      data: {
        userId: user._id.toString(),
        email: user.email,
      },
    })
  } catch (error) {
    if (error instanceof Error) {
      return NextResponse.json(
        { success: false, error: error.message },
        { status: 400 }
      )
    }

    return NextResponse.json(
      { success: false, error: "Signup failed" },
      { status: 500 }
    )
  }
}
