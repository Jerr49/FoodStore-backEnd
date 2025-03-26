const express = require("express");
const router = express.Router();
const upload = require("../Middleware/upload");
const { validateMenuItem } = require('../Middleware/validators/menuItem');


const {
  createCategory,
  getAllCategories,
  addMenuItem,
  getMenuByCategory,
} = require("../Controllers/menuController");
const { verifyToken, verifyAdmin } = require("../Middleware/auth");

// Public Routes
router.get("/categories", getAllCategories);
router.get("/", getMenuByCategory);

// Protected Routes with Image Upload
router.post("/categories", verifyToken, verifyAdmin, createCategory);

router.post(
  "/items",
  verifyToken,
  verifyAdmin,
  upload.single("image"),
  validateMenuItem, 
  addMenuItem
);

module.exports = router;
