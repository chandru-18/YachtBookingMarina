const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, required: true, unique: true },
  password: String,
  isAdmin: { type: Boolean, default: false },
  verified: { type: Boolean, default: false },
  emailToken: String,
  resetToken: String,
  resetTokenExpires: Date
});

module.exports = mongoose.model('User', userSchema);
