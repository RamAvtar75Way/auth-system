import mongoose, { Schema, Document, InferSchemaType } from "mongoose";

const UserSchema = new Schema(
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
);

export type IUser = InferSchemaType<typeof UserSchema> & Document;

export const User =
    mongoose.models.User || mongoose.model<IUser>("User", UserSchema);
