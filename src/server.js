import dotenv from "dotenv";

// Load config.env locally.
// Render environment variables will override these values.
dotenv.config({ path: "config.env" });
dotenv.config();

import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import authRoutes from "./routes/auth.js";
import { globalLimiter } from "./middleware/rateLimit.js";

const app = express();
const PORT = Number(process.env.PORT || 5000);

const allowedOrigins = (process.env.CLIENT_ORIGIN || "")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      // Allow requests with no origin (Postman, server-to-server, etc.)
      if (!origin) {
        return callback(null, true);
      }

      // If CLIENT_ORIGIN isn't configured, allow temporarily.
      if (allowedOrigins.length === 0) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("CORS origin not allowed"));
    },
  })
);

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));
app.use(globalLimiter);

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "STARIZION Auth Server",
  });
});

app.use("/api/auth", authRoutes);

app.use((err, req, res, next) => {
  console.error(err);

  res.status(err.status || 500).json({
    success: false,
    message:
      process.env.NODE_ENV === "production"
        ? "Something went wrong."
        : err.message || "Internal server error.",
  });
});

async function start() {
  const mongoUri = process.env.MONGODB_URI;
  const jwtSecret = process.env.JWT_SECRET;

  if (!mongoUri) {
    throw new Error("MONGODB_URI is missing from Render Environment Variables.");
  }

  if (!mongoUri.startsWith("mongodb://") && !mongoUri.startsWith("mongodb+srv://")) {
    throw new Error(
      "MONGODB_URI must start with mongodb:// or mongodb+srv://"
    );
  }

  if (!jwtSecret) {
    throw new Error("JWT_SECRET is missing from Render Environment Variables.");
  }

  if (jwtSecret.length < 32) {
    throw new Error("JWT_SECRET must be at least 32 characters long.");
  }

  try {
    await mongoose.connect(mongoUri);

    console.log("STARIZION MongoDB connected");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`STARIZION Auth Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);
    process.exit(1);
  }
}

start().catch((error) => {
  console.error("Server startup failed:", error.message);
  process.exit(1);
});