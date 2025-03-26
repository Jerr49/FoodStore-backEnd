// utils/imageUpload.js
const cloudinary = require('cloudinary').v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const uploadImage = async (fileBuffer) => {
  return new Promise((resolve, reject) => {
    cloudinary.uploader
      .upload_stream({ resource_type: 'auto' }, (error, result) => {
        if (error) reject(error);
        else resolve(result);
      })
      .end(fileBuffer);
  });
};

module.exports = { uploadImage };