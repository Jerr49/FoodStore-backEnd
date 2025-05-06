const express = require("express");
const router = express.Router();
const upload = require("../Middleware/upload");
const { validateMenuItem } = require("../Middleware/validators/menuItem");
const { verifyToken, verifyAdmin } = require("../Middleware/auth");
const {
  createCategory,
  getAllCategories,
  addMenuItem,
  getMenuByCategory,
} = require("../Controllers/menuController");

// Public Routes
router.get("/categories", getAllCategories);
router.get("/", getMenuByCategory);

// Protected Admin Routes
router.post("/categories", verifyToken, verifyAdmin, createCategory);

router.post(
  "/items",
  verifyToken,
  verifyAdmin,
  (req, res, next) => {
    // Debug logging
    console.log("Content-Type:", req.headers["content-type"]);
    console.log("Content-Length:", req.headers["content-length"]);
    next();
  },
  upload.single("image"),
  (req, res, next) => {
    if (!req.file) {
      console.warn("No file was uploaded");
    } else {
      console.log("Uploaded file info:", {
        originalname: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype,
      });
    }
    next();
  },
  validateMenuItem,
  addMenuItem
);

module.exports = router;
