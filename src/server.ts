import "dotenv/config"; // Must be first
import app from "./app";
import { connectDB } from "./config/db";
import { getEnv } from "./config/env";


async function start() {
    try {
        await connectDB();
        const port = getEnv("PORT") || 4000;
        app.listen(port, () => {
            console.log(`🚀 Server running on port \${port}`);
        });
    } catch (err) {
        console.error("Failed to start server:", err);
        process.exit(1);
    }
}

start();
