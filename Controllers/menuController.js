const { Category, MenuItem } = require("../models/menu.js");
const cloudinary = require("../Utils/cloudinaryConfig");

// Category Management
exports.createCategory = async (req, res) => {
  try {
    const { name, description } = req.body;

    const newCategory = new Category({
      name: name.toLowerCase(),
      description,
    });

    const savedCategory = await newCategory.save();

    res.status(201).json({
      success: true,
      message: "Category created successfully",
      data: savedCategory,
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: "Category already exists",
      });
    }
    res.status(500).json({
      success: false,
      message: "Failed to create category",
      error: error.message,
    });
  }
};

exports.getAllCategories = async (req, res) => {
  try {
    const categories = await Category.find({});
    res.status(200).json({
      success: true,
      data: categories,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch categories",
      error: error.message,
    });
  }
};

// Menu Item Management
exports.addMenuItem = async (req, res) => {
  try {
    console.log("Request received:", { body: req.body, file: req.file });

    const { name, description, price, categoryId } = req.body;

    // Validate input data
    if (!name || !description || !price || !categoryId) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
        requiredFields: ["name", "description", "price", "categoryId"],
      });
    }

    // Validate price
    const numericPrice = parseFloat(price);
    if (isNaN(numericPrice) || numericPrice <= 0) {
      return res.status(400).json({
        success: false,
        message: "Price must be a positive number",
      });
    }

    // Verify category exists
    const categoryExists = await Category.exists({ _id: categoryId });
    if (!categoryExists) {
      return res.status(404).json({
        success: false,
        message: "Category not found",
      });
    }

    // Process image
    let imageData = null;
    if (req.file) {
      console.log("Processing uploaded file:", {
        originalname: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype,
        cloudinaryData: req.file,
      });

      imageData = {
        public_id: req.file.public_id,
        url: req.file.secure_url,
        width: req.file.width,
        height: req.file.height,
        format: req.file.format,
        bytes: req.file.bytes,
        created_at: new Date(),
      };
    } else {
      console.warn("No file was uploaded with the request");
    }

    // Create menu item
    const newItem = new MenuItem({
      name: name.trim(),
      description: description.trim(),
      price: numericPrice,
      category: categoryId,
      image: imageData,
    });

    const savedItem = await newItem.save();
    console.log("Menu item saved successfully:", savedItem._id);

    return res.status(201).json({
      success: true,
      data: {
        id: savedItem._id,
        name: savedItem.name,
        price: savedItem.price,
        imageUrl: savedItem.image?.url || null,
        category: savedItem.category,
      },
      message: "Menu item created successfully",
    });
  } catch (error) {
    console.error("Error in addMenuItem:", {
      error: error.message,
      stack: error.stack,
      requestBody: req.body,
      requestFile: req.file,
    });

    // Cleanup uploaded image if DB operation failed
    if (req.file?.public_id) {
      try {
        await cloudinary.uploader.destroy(req.file.public_id);
        console.log(`Cleaned up image: ${req.file.public_id}`);
      } catch (cloudinaryError) {
        console.error("Image cleanup failed:", cloudinaryError);
      }
    }

    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "Menu item with this name already exists",
      });
    }

    return res.status(500).json({
      success: false,
      message: "Failed to create menu item",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

exports.getMenuByCategory = async (req, res) => {
  try {
    const menuItems = await MenuItem.find({})
      .populate("category", "name description")
      .exec();

    // Organize by category
    const menuByCategory = {};

    menuItems.forEach((item) => {
      const categoryName = item.category.name;
      if (!menuByCategory[categoryName]) {
        menuByCategory[categoryName] = {
          categoryInfo: {
            id: item.category._id,
            name: item.category.name,
            description: item.category.description,
          },
          items: [],
        };
      }
      menuByCategory[categoryName].items.push(item);
    });

    res.status(200).json({
      success: true,
      data: menuByCategory,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch menu",
      error: error.message,
    });
  }
};
