const express = require("express");
const { 
  register, 
  login, 
  verifyEmail,
  logout,
  logoutAllDevices,
  getSessions,
  terminateSession,
  checkAuth
} = require("../Controllers/auth");
const { verifyToken } = require("../Middleware/auth"); 

const router = express.Router();

// Public routes
router.post("/register", register);
router.post("/verify-email", verifyEmail);
router.post("/login", login);
router.get("/check-auth", checkAuth); 


// Protected routes (require valid JWT)
router.post("/logout", verifyToken, logout);
router.post("/logout-all", verifyToken, logoutAllDevices);
router.get("/sessions", verifyToken, getSessions);
router.post("/sessions/:sessionId/terminate", verifyToken, terminateSession);

module.exports = router;