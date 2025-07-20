// Load environment variables
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const flash = require('connect-flash');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const http = require('http');
const { format } = require('@fast-csv/format');
const PDFDocument = require('pdfkit');
const socketIO = require('socket.io');
const User = require('./models/user');
const Boat = require('./models/boat');
const Booking = require('./models/booking');

// Express/server setup
const app = express();
const server = http.createServer(app);
const io = socketIO(server);

const PORT = 3000;

// Nodemailer transporter (Gmail)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// Sync boats on DB boot
const boatsArray = [
  { name: "Boat 1", display: "ORYX 46 ft (12-15) – 500 AED/hr", max: 15, price: 500, available: true },
  { name: "Boat 2", display: "Majesty 56 ft (20) – 800 AED/hr", max: 20, price: 800, available: true },
  { name: "Boat 3", display: "Fishing/Speed Boat 31 ft (10) – 349 AED/hr", max: 10, price: 349, available: true },
  { name: "Boat 4", display: "ORYX 36 ft (10) – 400 AED/hr", max: 10, price: 400, available: true }
];

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
.then(async () => {
  console.log('✅ MongoDB Connected');

  // Sync boats
  for (const b of boatsArray) {
    await Boat.updateOne(
      { name: b.name },
      { $setOnInsert: b },
      { upsert: true }
    );
  }

  // Admin user creation
  const adminEmail = "Admin@yachtmarina.com";
  const adminPassword = "PrinceAnthony@24";
  const existingAdmin = await User.findOne({ email: adminEmail });

  if (!existingAdmin) {
    const hash = await bcrypt.hash(adminPassword, 10);
    await User.create({
      name: 'Yacht Admin',
      email: adminEmail,
      password: hash,
      isAdmin: true
    });
    console.log('✅ Default Admin Created!');
  }

  console.log('✅ Boats Synced. Ready to Sail ⛵');
})
.catch((err) => {
  console.error('❌ MongoDB Connection Error:', err.message);
});

// Basic middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Sessions & flash
app.use(session({
  secret: process.env.SESSION_SECRET || 'backupsecret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI })
}));
app.use(flash());
app.use((req, res, next) => {
  res.locals.success = req.flash("success");
  res.locals.error = req.flash("error");
  res.locals.user = req.session.user;
  next();
});

// Auth utils
function ensureAuth(req, res, next) {
  if (req.session.userId) return next();
  return res.redirect('/login');
}
function ensureGuest(req, res, next) {
  if (!req.session.userId) return next();
  return res.redirect('/dashboard');
}

// =============== ROUTES ===============

// Home
app.get('/', async (req, res) => {
  const boats = await Boat.find({ available: true });
  res.render('index', { boats });
});

// Register
app.get('/register', ensureGuest, (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.password, 10);
    await User.create({
      name: req.body.name,
      email: req.body.email,
      password: hash
    });
    req.flash("success", "Account created! Please login.");
    res.redirect('/login');
  } catch (err) {
    req.flash("error", "Email already exists.");
    res.redirect('/register');
  }
});

// Login/Logout
app.get('/login', ensureGuest, (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user && await bcrypt.compare(req.body.password, user.password)) {
    req.session.userId = user._id;
    req.session.user = user;
    res.redirect('/dashboard');
  } else {
    req.flash("error", "Invalid login details");
    res.redirect('/login');
  }
});
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ======= FORGOT PASSWORD & RESET =======
app.get('/forgot', ensureGuest, (req, res) => res.render('forgot'));
app.post('/forgot', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    req.flash("error", "No account with that email.");
    return res.redirect('/forgot');
  }
  const token = crypto.randomBytes(32).toString('hex');
  user.resetToken = token;
  user.resetTokenExpiry = Date.now() + 3600000; // 1hr
  await user.save();

  // Send reset mail
  await transporter.sendMail({
    to: user.email,
    from: process.env.EMAIL_USER,
    subject: '🔑 Reset Yacht Booking Password',
    html: `<p>Click <a href="https://yachtbookingmarina.onrender.com/reset/${token}">here</a> to reset your password (valid 1hr).</p>`
  });

  req.flash("success", "Password reset link sent! Check your mail.");
  res.redirect('/login');
});

app.get('/reset/:token', ensureGuest, async (req, res) => {
  const user = await User.findOne({
    resetToken: req.params.token,
    resetTokenExpiry: { $gt: Date.now() }
  });
  if (!user) {
    req.flash("error", "Forgot password link is expired/invalid.");
    return res.redirect('/forgot');
  }
  res.render('reset-password', { token: req.params.token });
});

app.post('/reset/:token', async (req, res) => {
  const user = await User.findOne({
    resetToken: req.params.token,
    resetTokenExpiry: { $gt: Date.now() }
  });
  if (!user) {
    req.flash("error", "Token expired! Retry forgot password.");
    return res.redirect('/forgot');
  }
  user.password = await bcrypt.hash(req.body.password, 10);
  user.resetToken = undefined;
  user.resetTokenExpiry = undefined;
  await user.save();
  req.flash("success", "Password changed! Please log in.");
  res.redirect('/login');
});

// ======= Book a Yacht + Notification/Email =======
app.post('/book', ensureAuth, async (req, res) => {
  try {
    const booking = await Booking.create({
      boat: req.body.boat,
      date: req.body.date,
      hours: req.body.hours,
      persons: req.body.persons,
      user: req.session.userId,
      phoneNumber: req.body.phoneNumber // ← must be present in form
    });
    const user = await User.findById(req.session.userId);

    // Confirm email
    await transporter.sendMail({
      to: user.email,
      from: process.env.EMAIL_USER,
      subject: "✅ Booking Confirmed",
      html: `<p>Hi ${user.name},<br>Your booking for ${booking.boat} on ${booking.date} is confirmed.<br>Thank you!</p>`
    });

    io.emit('new-booking');

    req.flash("success", "✅ Booking confirmed! Details emailed.");
    res.redirect('/dashboard');
  } catch (e) {
    req.flash("error", "Booking failed: " + (e.message || ""));
    res.redirect('/');
  }
});

// ======= User Dashboard =======
app.get('/dashboard', ensureAuth, async (req, res) => {
  const bookings = await Booking.find({ user: req.session.userId });
  res.render('dashboard', { bookings });
});

// ======= Admin Panel =======
app.get('/admin', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  const boats = await Boat.find();
  const bookings = await Booking.find().populate('user');
  res.render('admin', { bookings, boats });
});
app.post('/admin/update-boats', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  const boats = await Boat.find();
  for (let boat of boats) {
    const available = req.body[boat.name] === 'on';
    await Boat.updateOne({ name: boat.name }, { available });
  }
  req.flash("success", "✅ Boat availability updated");
  res.redirect('/admin');
});

// ======= Admin: CSV Export =======
app.get('/admin/export/csv', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  const bookings = await Booking.find().populate('user');
  res.setHeader('Content-Disposition', 'attachment; filename=bookings.csv');
  res.setHeader('Content-Type', 'text/csv');
  const csvStream = format({ headers: true });
  csvStream.pipe(res);
  bookings.forEach(b => {
    csvStream.write({
      Boat: b.boat,
      Date: b.date,
      Hours: b.hours,
      Persons: b.persons,
      Phone: b.phoneNumber,
      Name: b.user?.name,
      Email: b.user?.email
    });
  });
  csvStream.end();
});

// ======= Admin: PDF Export =======
app.get('/admin/export/pdf', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  const bookings = await Booking.find().populate('user');
  res.setHeader('Content-Disposition', 'attachment; filename=bookings.pdf');
  res.setHeader('Content-Type', 'application/pdf');
  const doc = new PDFDocument();
  doc.pipe(res);
  doc.fontSize(20).text('📋 Booking Records', { align: 'center' }).moveDown();
  bookings.forEach((b, i) => {
    doc.fontSize(12).text(`${i + 1}. 🛥 Boat: ${b.boat}, 📅 Date: ${b.date}, ⏱ Hours: ${b.hours}, 👥 Persons: ${b.persons}, ☎️ Phone: ${b.phoneNumber}, 👤 User: ${b.user?.name} (${b.user?.email})`);
  });
  doc.end();
});

// ======= Admin: Booking Delete/Edit =======
app.post('/admin/delete-booking/:id', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  await Booking.deleteOne({ _id: req.params.id });
  req.flash("success", "✅ Booking deleted");
  res.redirect('/admin');
});
app.get('/admin/edit-booking/:id', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  const booking = await Booking.findById(req.params.id).populate('user');
  const boats = await Boat.find();
  res.render('edit-booking', { booking, boats });
});
app.post('/admin/edit-booking/:id', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  await Booking.updateOne(
    { _id: req.params.id },
    {
      boat: req.body.boat,
      date: req.body.date,
      hours: req.body.hours,
      persons: req.body.persons,
      phoneNumber: req.body.phoneNumber,
    }
  );
  req.flash("success", "✅ Booking updated");
  res.redirect('/admin');
});

// 404 Not Found Handler
app.use((req, res) => {
  res.status(404).send('<h2>404 - Page Not Found</h2>');
});

// === Socket.IO for admin notifications ===
io.on('connection', socket => {
  // Optionally log: console.log('Admin connected...');
});

// Final listen (note: use server, not app)
server.listen(PORT, () => {
  console.log(`🚢 Yacht Booking server running on http://localhost:${PORT}`);
});
