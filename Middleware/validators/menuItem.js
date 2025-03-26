const { body } = require('express-validator');

exports.validateMenuItem = [
  body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
  body('description').trim().isLength({ min: 10 }),
  body('price').isFloat({ gt: 0 }),
  body('categoryId').isMongoId()
];