const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const dotenv = require("dotenv");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const mongoose = require("mongoose");
const connectDB = require("./Config/db");

// Load environment variables first
dotenv.config();

// Initialize Express app
const app = express();

// Enhanced middleware stack (these can run before DB connection)
app.use(helmet());
app.use(compression());
app.use(morgan("dev"));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS configuration (same as your existing setup)
const allowedOrigins = [
  process.env.FRONTEND_URL,
  "http://localhost:5173",
  "https://*.vercel.app",
  "https://*.netlify.app",
].filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (
        !origin ||
        allowedOrigins.some((allowed) => {
          const pattern = new RegExp(allowed.replace(/\*/g, ".*"));
          return pattern.test(origin);
        })
      ) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    exposedHeaders: ["set-cookie"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  })
);

// Tiered rate limiting (same as your existing setup)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many auth requests, please try again later",
});

const publicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, please try again later",
});

// Health check endpoint (works without DB connection)
app.get("/api/v1/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    dbStatus:
      mongoose.connection.readyState === 1 ? "connected" : "disconnected",
  });
});

// Database connection with retry logic
const MAX_DB_RETRIES = 3;
let retryCount = 0;

const startServer = async () => {
  try {
    // 1. First connect to MongoDB
    await connectDB();
    console.log(
      `[${new Date().toISOString()}] Database connected successfully`
    );

    // 2. THEN require models (this registers them with Mongoose)
    require("./models/Menu");

    // 3. THEN import routes
    const authRoutes = require("./Routes/auth");
    const menuRoutes = require("./Routes/menuRoutes");

    // Apply rate limiting
    app.use("/api/v1/auth", authLimiter);
    app.use("/api/v1/menu", publicLimiter);

    // Mount routes
    app.use("/api/v1/auth", authRoutes);
    app.use("/api/v1/menu", menuRoutes);

    // Enhanced error handling
    app.use((err, req, res, next) => {
      console.error(
        `[${new Date().toISOString()}] Error:`,
        err.stack || err.message
      );

      if (err.message.includes("CORS")) {
        return res.status(403).json({
          success: false,
          message: "CORS policy restriction",
          allowedOrigins:
            process.env.NODE_ENV === "development" ? allowedOrigins : undefined,
        });
      }

      if (err.status === 429) {
        return res.status(429).json({
          success: false,
          message: err.message || "Too many requests, please try again later",
        });
      }

      res.status(err.status || 500).json({
        success: false,
        message: err.message || "Internal Server Error",
        ...(process.env.NODE_ENV === "development" && {
          stack: err.stack,
          details: err,
        }),
      });
    });

    // Start server
    const PORT = process.env.PORT || 8080;
    const server = app.listen(PORT, () => {
      console.log(
        `[${new Date().toISOString()}] Server running on port ${PORT}`
      );
      console.log(`Allowed CORS origins:`, allowedOrigins);
    });

    // Graceful shutdown handlers
    const shutdown = (signal) => {
      console.log(
        `\n[${new Date().toISOString()}] ${signal} received. Shutting down gracefully...`
      );
      server.close(() => {
        console.log(`[${new Date().toISOString()}] HTTP server closed.`);
        mongoose.connection.close(false, () => {
          console.log(
            `[${new Date().toISOString()}] MongoDB connection closed.`
          );
          process.exit(0);
        });
      });

      setTimeout(() => {
        console.error(`[${new Date().toISOString()}] Forcing shutdown...`);
        process.exit(1);
      }, 5000);
    };

    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));
  } catch (err) {
    console.error(
      `[${new Date().toISOString()}] Database connection error:`,
      err
    );
    if (retryCount < MAX_DB_RETRIES) {
      retryCount++;
      console.log(
        `Retrying connection (attempt ${retryCount}/${MAX_DB_RETRIES})...`
      );
      setTimeout(startServer, 5000);
    } else {
      console.error("Max retries reached. Exiting...");
      process.exit(1);
    }
  }
};

startServer();
