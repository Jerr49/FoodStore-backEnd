const multer = require('multer');
const path = require('path');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Configure Cloudinary (make sure this runs before storage setup)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Cloudinary storage configuration
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: (req, file) => {
    return {
      folder: 'menu-items',
      allowed_formats: ['jpg', 'png', 'jpeg', 'gif'],
      transformation: [{ width: 800, height: 600, crop: 'limit' }],
      public_id: 'item-' + Date.now(),
      resource_type: 'auto' 
    };
  }
});

// File filter
const fileFilter = (req, file, cb) => {
  const filetypes = /jpe?g|png|gif/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Error: Only JPEG, PNG, and GIF images are allowed!'));
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { 
    fileSize: 5 * 1024 * 1024, 
    files: 1
  }
});

module.exports = upload;