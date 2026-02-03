import { NextResponse } from "next/server"
import { connectDB } from "@/lib/db"

export async function GET(): Promise<NextResponse> {
  await connectDB()

  return NextResponse.json({
    success: true,
    message: "Database connected",
  })
}
