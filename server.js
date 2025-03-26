const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const dotenv = require("dotenv");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const connectDB = require("./Config/db");
const authRoutes = require("./Routes/auth");
const menuRoutes = require("./Routes/menuRoutes");

// Load environment variables first
dotenv.config();

// Initialize Express app
const app = express();

// Database connection with error handling
const MAX_DB_RETRIES = 3;
let retryCount = 0;

const establishDbConnection = async () => {
  try {
    await connectDB();
    console.log(
      `[${new Date().toISOString()}] Database connected successfully`
    );
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
      setTimeout(establishDbConnection, 5000);
    } else {
      console.error("Max retries reached. Exiting...");
      process.exit(1);
    }
  }
};

establishDbConnection();

// Enhanced middleware stack
app.use(helmet());
app.use(compression());
app.use(morgan("dev"));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Tiered rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 50, 
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many auth requests, please try again later",
});

const publicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // More generous limit for public routes
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, please try again later",
});

// CORS configuration with enhanced origin handling
const allowedOrigins = [
  process.env.FRONTEND_URL,
  "http://localhost:5173",
  "https://*.vercel.app",
  "https://*.netlify.app",
].filter(Boolean);

// In your server.js
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
    exposedHeaders: ['set-cookie'], // Important for cookies
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  })
);

// Apply rate limiting
app.use("/api/v1/auth", authLimiter);
app.use("/api/v1/menu", publicLimiter);

// Versioned API routes
app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/menu", menuRoutes);

// Health check endpoint
app.get("/api/v1/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    dbStatus:
      retryCount === 0
        ? "connected"
        : `retrying (${retryCount}/${MAX_DB_RETRIES})`,
  });
});

// Enhanced error handling
app.use((err, req, res, next) => {
  console.error(
    `[${new Date().toISOString()}] Error:`,
    err.stack || err.message
  );

  // Special error cases
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

  // Generic error response
  res.status(err.status || 500).json({
    success: false,
    message: err.message || "Internal Server Error",
    ...(process.env.NODE_ENV === "development" && {
      stack: err.stack,
      details: err,
    }),
  });
});

// Server startup
const PORT = process.env.PORT || 8080;
const server = app.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] Server running on port ${PORT}`);
  console.log(`Allowed CORS origins:`, allowedOrigins);
});

// Graceful shutdown handlers
const shutdown = (signal) => {
  console.log(
    `\n[${new Date().toISOString()}] ${signal} received. Shutting down gracefully...`
  );

  server.close(() => {
    console.log(`[${new Date().toISOString()}] HTTP server closed.`);

    // Add any cleanup tasks here (e.g., close database connections)
    console.log(`[${new Date().toISOString()}] Cleanup complete. Exiting.`);
    process.exit(0);
  });

  // Force shutdown if hanging
  setTimeout(() => {
    console.error(`[${new Date().toISOString()}] Forcing shutdown...`);
    process.exit(1);
  }, 5000);
};

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
