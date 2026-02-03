export interface LoginSuccessData {
  accessToken: string
  requiresTwoFactor: boolean
  userId?: string
}

export interface TwoFactorVerifyData {
  accessToken: string
}

export interface SignupSuccessData {
  userId: string
  email: string
}

export interface MessageData {
  message: string
}
