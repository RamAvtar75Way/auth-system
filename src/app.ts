import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import authRoutes from "./modules/auth/auth.routes";
import { errorMiddleware } from "./middleware/error.middleware";

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: true,
    credentials: true
}));

app.use("/auth", authRoutes);

app.get("/health", (req, res) => {
    res.status(200).json({ status: "ok" });
});

app.use(errorMiddleware);

export default app;
