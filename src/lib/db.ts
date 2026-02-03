import mongoose, { Mongoose } from "mongoose";

interface MongooseCache {
    conn: Mongoose | null;
    promise: Promise<Mongoose> | null;
}

declare global {
    var mongooseCache: MongooseCache | undefined;
}

const globalCache: MongooseCache = global.mongooseCache || { conn: null, promise: null };


export async function connectDB(): Promise<Mongoose> {
  const mongoUri = process.env.MONGO_URI

  if (!mongoUri) {
    throw new Error("MONGO_URI is not defined in environment variables")
  }

  if (globalCache.conn) {
    return globalCache.conn
  }

  if (!globalCache.promise) {
    globalCache.promise = mongoose.connect(mongoUri, {
      dbName: "auth_system",
      bufferCommands: false,
    })
  }

  globalCache.conn = await globalCache.promise
  globalThis.mongooseCache = globalCache

  return globalCache.conn
}

