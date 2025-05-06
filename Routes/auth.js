const express = require("express");
const {
  register,
  login,
  verifyEmail,
  logout,
  logoutAllDevices,
  getSessions,
  createSession,
  refreshToken,
  terminateSession,
  checkAuth,
  pingActivity,
} = require("../Controllers/auth");
const { verifyToken } = require("../Middleware/auth");

const router = express.Router();

// Public routes
router.post("/register", register);
router.post("/verify-email", verifyEmail);
router.post("/login", login);
router.post("/logout", logout);
router.get("/check-auth", checkAuth);

router.post("/refresh-token", refreshToken);
router.post("/activity-ping", verifyToken, pingActivity);

// Protected routes (require valid JWT)
router.post("/logout-all", verifyToken, logoutAllDevices);
router.get("/sessions", createSession, verifyToken, getSessions);
router.post("/sessions/:sessionId/terminate", verifyToken, terminateSession);

module.exports = router;
