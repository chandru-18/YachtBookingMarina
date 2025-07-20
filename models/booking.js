const mongoose = require('mongoose');

const bookingSchema = new mongoose.Schema({
  boat: { type: String, required: true },
  date: { type: Date, required: true },
  hours: { type: Number, required: true },
  persons: { type: Number, required: true },
  phoneNumber: { type: String, required: true },  // Supports any country code
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});

// Pre-save: Format any phone to international (+countrycode) style
bookingSchema.pre('save', function(next) {
  let num = this.phoneNumber ? this.phoneNumber.trim() : '';
  // Remove all spaces, dashes, and parentheses
  num = num.replace(/[\s\-()]/g, '');

  // Convert '00...' to '+...'
  if (num.startsWith('00')) {
    num = '+' + num.slice(2);
  }

  // If not starting with '+', make "best guess" (default to UAE +971, OR replace with your main country code)
  if (!num.startsWith('+')) {
    // If 10-digit & starts with 0 (UAE mobile), assume +971
    if (num.length === 10 && num.startsWith('0')) {
      num = '+971' + num.slice(1);
    }
    // If all digits, fallback default (change +971 to +91 for India, etc, if needed)
    else if (num.length >= 8 && /^\d+$/.test(num)) {
      num = '+971' + num;
    }
    // Last-resort: just add +
    else {
      num = '+' + num;
    }
  }

  this.phoneNumber = num;
  next();
});

module.exports = mongoose.model('Booking', bookingSchema);
