const express = require("express");
const router = express.Router();
const Booking = require("../models/booking");
const Boat = require("../models/boat");
const nodemailer = require("nodemailer");

// Middleware to ensure user is logged in
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

router.post("/book", isLoggedIn, async (req, res) => {
  console.log("🔥 POST /book triggered");

  try {
    const { boatId, bookingDate, startTime, endTime, numberOfPersons, phoneNumber } = req.body;
    console.log("📦 Booking data received:", req.body);

    const boat = await Boat.findById(boatId);
    if (!boat) {
      console.log("❌ Boat not found");
      req.flash("error", "Boat not found.");
      return res.redirect("/");
    }

    // Calculate total price
    const start = parseInt(startTime.split(":")[0]);
    const end = parseInt(endTime.split(":")[0]);
    const duration = end - start;
    const totalPrice = duration * boat.price;

    const booking = new Booking({
      boat: boat._id,
      user: req.user._id,
      bookingDate,
      startTime,
      endTime,
      numberOfPersons,
      phoneNumber,
      totalPrice,
    });

    await booking.save();
    console.log("✅ Booking saved. Preparing to send email...");

    // Email admin after booking
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: `"Yacht Booking" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER, // admin
      subject: `🛥️ New Booking by ${req.user.name}`,
      text: `
A new yacht booking has been made!

👤 Name: ${req.user.name}
📧 Email: ${req.user.email}
📱 Phone: ${booking.phoneNumber}
🛥️ Boat: ${boat.display || boat.name}
📅 Date: ${booking.bookingDate}
⏰ Time: ${booking.startTime} - ${booking.endTime}
👥 Persons: ${booking.numberOfPersons}
💰 Total: AED ${booking.totalPrice}
      `,
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error("❌ Email error:", err);
      } else {
        console.log("✅ Email sent:", info.response);
      }
    });

    req.flash("success", "Booking successful! Admin has been notified.");
    res.redirect("/bookings");

  } catch (err) {
    console.error("🔥 Booking Error:", err);
    req.flash("error", "Booking failed.");
    res.redirect("/");
  }
});

module.exports = router;
