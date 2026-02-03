import { NextRequest, NextResponse } from "next/server"
import { verifyAccessToken } from "@/lib/jwt"

function getBearerToken(req: NextRequest): string | null {
    const header = req.headers.get("authorization")
    if (!header) return null

    const parts = header.split(" ")

    if (parts.length !== 2) return null
    if (parts[0] !== "Bearer") return null

    const token = parts[1]

    if (!token) return null

    return token
}


export function proxy(req: NextRequest): NextResponse {
    const token = getBearerToken(req)

    if (!token) {
        return NextResponse.json(
            { success: false, error: "Missing access token" },
            { status: 401 }
        )
    }

    try {
        verifyAccessToken(token)
        return NextResponse.next()
    } catch {
        return NextResponse.json(
            { success: false, error: "Invalid access token" },
            { status: 401 }
        )
    }
}

export const config = {
    matcher: [
        "/api/private/:path*",
        "/dashboard/:path*",
        "/settings/:path*",
    ],
}
