import bcrypt from "bcryptjs"
import crypto from "crypto"

const BCRYPT_ROUNDS = 12

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS)
}

export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  return bcrypt.compare(password, hash)
}


export function sha256(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex")
}
