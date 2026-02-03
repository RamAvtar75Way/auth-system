import { Schema, model, models, InferSchemaType, HydratedDocument } from "mongoose"

const userSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    passwordHash: {
      type: String,
      required: false, 
    },

    googleId: {
      type: String,
      required: false,
      index: true,
    },


    isEmailVerified: {
      type: Boolean,
      default: false,
    },

    emailVerifyCodeHash: {
      type: String,
    },

    emailVerifyExpiry: {
      type: Date,
    },


    twoFactorEnabled: {
      type: Boolean,
      default: false,
    },

    twoFactorCodeHash: {
      type: String,
    },

    twoFactorExpiry: {
      type: Date,
    },

    twoFactorSecret: {
      type: String, 
    },


    resetPasswordTokenHash: {
      type: String,
    },

    resetPasswordExpiry: {
      type: Date,
    },


    refreshTokenHash: {
      type: String,
    },

    tokenVersion: {
      type: Number,
      default: 0,
    },

    failedLoginAttempts: {
      type: Number,
      default: 0,
    },

    lockUntil: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
)

export type UserSchemaType = InferSchemaType<typeof userSchema>
export type UserDocument = HydratedDocument<UserSchemaType>

export const User =
  models.User || model<UserSchemaType>("User", userSchema)
