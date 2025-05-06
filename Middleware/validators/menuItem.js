const { body, validationResult } = require('express-validator');
const mongoose = require('mongoose');
const { Category } = require('../../Models/Menu'); // Destructured import
const cloudinary = require('../../Utils/cloudinaryConfig');

exports.validateMenuItem = [
  // Name validation
  body('name')
    .trim()
    .notEmpty().withMessage('Name is required')
    .isLength({ min: 2, max: 50 }).withMessage('Name must be 2-50 characters')
    .escape(),

  // Description validation
  body('description')
    .trim()
    .notEmpty().withMessage('Description is required')
    .isLength({ min: 10, max: 500 }).withMessage('Description must be 10-500 characters')
    .escape(),

  // Price validation
  body('price')
    .notEmpty().withMessage('Price is required')
    .isFloat({ 
      min: 0.01,
      max: 10000 
    }).withMessage('Price must be between 0.01 and 10,000')
    .customSanitizer(value => parseFloat(value).toFixed(2))
    .toFloat(),

  // Category validation - updated with better error handling
  body('categoryId')
    .notEmpty().withMessage('Category ID is required')
    .isMongoId().withMessage('Invalid category ID format')
    .custom(async (value, { req }) => {
      try {
        if (!mongoose.Types.ObjectId.isValid(value)) {
          throw new Error('Invalid category ID format');
        }
        
        const category = await Category.findById(value);
        if (!category) {
          throw new Error('Category not found');
        }
        return true;
      } catch (error) {
        // Clean up image if validation fails
        if (req.file?.public_id) {
          await cloudinary.uploader.destroy(req.file.public_id)
            .catch(err => console.error('Image cleanup failed:', err));
        }
        throw error;
      }
    }),

  // Dietary restrictions validation
  body('dietaryRestrictions')
    .optional()
    .isArray().withMessage('Dietary restrictions must be an array')
    .custom((value) => {
      const allowed = ['vegetarian', 'vegan', 'gluten-free', 'dairy-free', 'nut-free', 'halal', 'kosher'];
      if (value.some(item => !allowed.includes(item))) {
        throw new Error(`Invalid dietary restriction. Allowed values: ${allowed.join(', ')}`);
      }
      return true;
    }),

  // Validation handler
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().reduce((acc, err) => {
        acc[err.path] = err.msg;
        return acc;
      }, {});

      // Clean up uploaded file if validation fails
      if (req.file?.public_id) {
        try {
          await cloudinary.uploader.destroy(req.file.public_id);
        } catch (cloudinaryError) {
          console.error('Image cleanup failed:', cloudinaryError);
        }
      }

      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errorMessages,
        code: "VALIDATION_ERROR",
        timestamp: new Date().toISOString(),
        requestId: req.id || req.requestId
      });
    }
    next();
  }
];