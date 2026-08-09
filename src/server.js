import dotenv from "dotenv";
dotenv.config({ path: "config.env" });

import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import authRoutes from "./routes/auth.js";
import { globalLimiter } from "./middleware/rateLimit.js";

const app = express();
const PORT = Number(process.env.PORT || 5000);

const allowedOrigins = (process.env.CLIENT_ORIGIN || "")
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("CORS origin not allowed"));
  }
}));

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));
app.use(globalLimiter);

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "STARIZION Auth Server" });
});

app.use("/api/auth", authRoutes);

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === "production"
      ? "Something went wrong."
      : (err.message || "Internal server error.")
  });
});

async function start() {
  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI is missing from config.env");
  }
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.includes("CHANGE_THIS")) {
    throw new Error("Set a strong JWT_SECRET in config.env");
  }

  await mongoose.connect(process.env.MONGODB_URI);
  console.log("STARIZION MongoDB connected");

  app.listen(PORT, () => {
    console.log(`STARIZION Auth Server running on port ${PORT}`);
  });
}

start().catch(error => {
  console.error("Server startup failed:", error.message);
  process.exit(1);
});
