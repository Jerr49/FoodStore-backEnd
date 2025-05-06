const mongoose = require("mongoose");

const categorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  description: String,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const menuItemSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      required: true,
    },
    price: {
      type: Number,
      required: true,
      min: 0,
    },
    image: {
      public_id: {
        type: String,
        required: false,
      },
      url: {
        type: String,
        required: false,
        default:
          "https://res.cloudinary.com/your-cloud/image/upload/v1630000000/default_food_item.jpg",
      },
      width: Number,
      height: Number,
      format: String,
      bytes: Number,
    },
    category: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Category",
      required: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

// Add index for better performance
menuItemSchema.index({ name: "text", description: "text" });

const Category = mongoose.model("Category", categorySchema);
const MenuItem = mongoose.model("MenuItem", menuItemSchema);

module.exports = { Category, MenuItem };
