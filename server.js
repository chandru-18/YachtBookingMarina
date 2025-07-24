require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const flash = require('connect-flash');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const methodOverride = require('method-override');
const multer = require('multer'); // For file uploads
const fs = require('fs'); // For deleting files

const app = express();
const PORT = process.env.PORT || 3000;

// ====== Models =======
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    isVerified: { type: Boolean, default: false },
    verificationToken: String,
    verificationTokenExpires: Date,
    resetToken: String,
    resetTokenExpires: Date
});
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});
const User = mongoose.model('User', userSchema);

const boatSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true, trim: true },
    display: { type: String, trim: true },
    maxPersons: { type: Number, required: true, min: 1 },
    pricePerHour: { type: Number, required: true, min: 0 },
    imageUrl: { type: String, default: '/images/default_boat.jpg', trim: true },
    description: { type: String, trim: true, default: '' }, // NEW FIELD
    availability: { type: Boolean, default: true }
});
const Boat = mongoose.model('Boat', boatSchema);

const bookingSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    boat: { type: mongoose.Schema.Types.ObjectId, ref: 'Boat', required: true },
    bookingDate: { type: Date, required: true },
    startTime: { type: String, required: true }, // HH:MM format
    endTime: { type: String, required: true },   // HH:MM format
    numberOfPersons: { type: Number, required: true, min: 1 },
    phoneNumber: { type: String, required: true, trim: true },
    totalPrice: { type: Number, required: true, min: 0 },
    status: { type: String, enum: ['pending', 'confirmed', 'cancelled', 'completed'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

bookingSchema.pre('save', function(next) {
    if (this.isModified('phoneNumber')) {
        let cleaned = this.phoneNumber.replace(/\D/g, '');
        // Basic formatting for India (+91) if 10 digits and no leading +
        if (cleaned.length === 10 && !cleaned.startsWith('91')) {
            this.phoneNumber = '+91' + cleaned;
        } else if (!cleaned.startsWith('+')) {
            this.phoneNumber = '+' + cleaned;
        } else {
            this.phoneNumber = cleaned;
        }
    }
    next();
});

const Booking = mongoose.model('Booking', bookingSchema);

// ===== MongoDB Connection & Default Boats ======
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('MongoDB connected successfully');
        syncDefaultBoats(); // Ensure this is called only once on startup
    })
    .catch(err => console.error('MongoDB connection error:', err));

async function syncDefaultBoats() {
    const defaultBoats = [
        { name: "ORYX 46 ft", display: "ORYX 46 ft", maxPersons: 15, pricePerHour: 500, imageUrl: "/images/oryx_46ft.jpg", description: "A luxurious and spacious yacht, perfect for larger groups." },
        { name: "Majesty 56 ft", display: "Majesty 56 ft", maxPersons: 20, pricePerHour: 800, imageUrl: "/images/majesty_56ft.jpg", description: "Experience ultimate luxury on this grand yacht, ideal for events." },
        { name: "Fishing/Speed Boat 31 ft", display: "Fishing/Speed Boat 31 ft", maxPersons: 10, pricePerHour: 349, imageUrl: "/images/fishing_speed_31ft.jpg", description: "Fast and versatile, great for fishing trips or quick cruises." },
        { name: "ORYX 36 ft", display: "ORYX 36 ft", maxPersons: 10, pricePerHour: 400, imageUrl: "/images/oryx_36ft.jpg", description: "A comfortable and stylish yacht, suitable for family outings." }
    ];

    const desiredBoatNames = defaultBoats.map(boat => boat.name);

    try {
        // Step 1: Add/Update only the desired boats
        for (const boatData of defaultBoats) {
            await Boat.findOneAndUpdate(
                { name: boatData.name },
                { $set: boatData },
                { upsert: true, new: true, setDefaultsOnInsert: true }
            );
        }
        console.log('Desired default boats synced/updated.');

        // Step 2: Remove any old default boats that are no longer desired
        const allExistingBoatNames = (await Boat.find({}, { name: 1, _id: 0 })).map(b => b.name);
        const namesToRemove = allExistingBoatNames.filter(name => !desiredBoatNames.includes(name));

        if (namesToRemove.length > 0) {
            await Boat.deleteMany({ name: { $in: namesToRemove } });
            console.log(`Removed old default boats: ${namesToRemove.join(', ')}`);
        } else {
            console.log('No old default boats to remove.');
        }

    } catch (error) {
        console.error('Error syncing default boats:', error);
    }
}

// ===== Middleware Order =====
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true })); // For parsing form data
app.use(express.json()); // For parsing JSON payloads
app.use(methodOverride('_method')); // For PUT/DELETE methods in forms

// Set up Multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/images/'); // Save uploaded images to public/images folder
    },
    filename: function (req, file, cb) {
        // Use a unique filename to prevent conflicts
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5MB
    fileFilter: (req, file, cb) => {
        // Accept only JPEG, PNG, GIF
        if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png' || file.mimetype === 'image/gif') {
            cb(null, true);
        } else {
            cb(new Error('Only .jpg, .jpeg, .png, .gif files are allowed!'), false);
        }
    }
});


app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: { maxAge: 86400000, httpOnly: true, secure: process.env.NODE_ENV === 'production' } // 24 hours
}));
app.use(flash());

// Make flash messages and user data available to all templates
app.use((req, res, next) => {
    res.locals.messages = req.flash();
    res.locals.user = req.session.user || null;
    next();
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ===== Email Transporter ======
const transporter = nodemailer.createTransport({
    service: "gmail", // Or your preferred SMTP service
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// ===== Auth Middleware =====
const isAuthenticated = (req, res, next) => {
    if (!req.session.userId) {
        req.flash('error', 'Please log in to access this page.');
        return res.redirect('/login');
    }

    User.findById(req.session.userId)
        .then(user => {
            if (!user) {
                req.flash('error', 'User not found. Please log in again.');
                req.session.destroy(err => {
                    if(err) console.error('Error destroying session during isAuthenticated:', err);
                    res.clearCookie('connect.sid');
                    res.redirect('/login');
                });
                return;
            }

            // Admins bypass email verification
            if (!user.isVerified && !user.isAdmin && req.path !== '/verify-email' && req.path !== '/resend-verification' && req.path !== '/logout' && req.path.indexOf('/verify/') === -1) {
                req.flash('error', 'Please verify your email to access this feature.');
                return res.redirect('/verify-email');
            }

            // This ensures req.session.user is always up-to-date with current DB status
            req.session.user = {
                id: user._id,
                name: user.name,
                email: user.email,
                isAdmin: user.isAdmin,
                isVerified: user.isVerified
            };
            next();
        })
        .catch(err => {
            console.error('Error in isAuthenticated middleware:', err);
            req.flash('error', 'An authentication error occurred. Please log in again.');
            res.redirect('/login');
        });
};

const isAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.isAdmin) {
        return next();
    }
    req.flash('error', 'Access denied. Administrator privileges required.');
    res.redirect('/');
};

// Helper function to check for time overlaps
function isTimeOverlap(start1, end1, start2, end2) {
    const timeToMinutes = (timeStr) => {
        const [hours, minutes] = timeStr.split(':').map(Number);
        return hours * 60 + minutes;
    };
    const s1 = timeToMinutes(start1);
    const e1 = timeToMinutes(end1);
    const s2 = timeToMinutes(start2);
    const e2 = timeToMinutes(end2);

    return (s1 < e2 && s2 < e1);
}

// ===== ROUTES =====

// Home Page
app.get('/', async (req, res) => {
    try {
        const boats = await Boat.find({}); // This fetches ALL boats in your DB
        res.render('index', { boats });
    } catch (error) {
        console.error('Error loading home page (boats):', error);
        req.flash('error', 'Could not load boats.');
        res.render('index', { boats: [] });
    }
});

// User Registration
app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;

        if (!name || !email || !password || !confirmPassword) {
            req.flash('error', 'All fields are required.');
            return res.redirect('/register');
        }
        if (password.length < 6) {
            req.flash('error', 'Password must be at least 6 characters long.');
            return res.redirect('/register');
        }
        if (password !== confirmPassword) {
            req.flash('error', 'Passwords do not match.');
            return res.redirect('/register');
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            req.flash('error', 'Please enter a valid email address.');
            return res.redirect('/register');
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            req.flash('error', 'Email already registered.');
            return res.redirect('/register');
        }

        const verificationToken = crypto.randomBytes(32).toString('hex');
        const verificationTokenExpires = Date.now() + 3600000; // 1 hour

        const newUser = new User({
            name,
            email,
            password,
            verificationToken,
            verificationTokenExpires
        });
        await newUser.save();

        const verificationUrl = `http://localhost:${PORT}/verify/${verificationToken}`;
        transporter.sendMail({
            to: newUser.email,
            from: process.env.EMAIL_USER,
            subject: 'Yacht Marina Booking - Email Verification',
            html: `<p>Thank you for registering! Please click <a href="${verificationUrl}">here</a> to verify your email. This link will expire in 1 hour.</p>`
        }, (error, info) => {
            if (error) {
                console.error("Error sending registration email:", error);
            } else {
                console.log("Registration email sent:", info.response);
            }
        });

        req.flash('success', 'Registration successful! A verification link has been sent to your email. Please verify to log in.');
        res.redirect('/login');
    } catch (error) {
        console.error('Registration failed:', error);
        req.flash('error', 'Registration failed. Please try again.');
        res.redirect('/register');
    }
});

// Login/Logout
app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            req.flash('error', 'Invalid email or password.');
            return res.redirect('/login');
        }
        // Only non-admin users need to verify email
        if (!user.isVerified && !user.isAdmin) {
            req.flash('error', 'Your email is not verified. Please check your inbox or resend the verification email.');
            return res.redirect('/verify-email');
        }

        req.session.userId = user._id;
        req.session.user = {
            id: user._id,
            name: user.name,
            email: user.email,
            isAdmin: user.isAdmin,
            isVerified: user.isVerified
        };
        req.flash('success', 'Logged in successfully!');
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Login error:', error);
        req.flash('error', 'An error occurred during login.');
        res.redirect('/login');
    }
});

app.get('/logout', (req, res) => {
    if (req.session) {
        req.flash('success', 'You have been logged out successfully.');

        req.session.destroy(err => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.redirect('/');
            }
            res.clearCookie('connect.sid');
            res.redirect('/login');
        });
    } else {
        res.clearCookie('connect.sid');
        res.redirect('/login');
    }
});

// Email Verification Routes
app.get('/verify-email', isAuthenticated, (req, res) => {
    res.render('verify-email', { user: req.session.user });
});

app.get('/verify/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            verificationToken: req.params.token,
            verificationTokenExpires: { $gt: Date.now() }
        });

        if (!user) {
            req.flash('error', 'Verification token is invalid or has expired.');
            return res.redirect('/login');
        }

        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpires = undefined;
        await user.save();

        req.flash('success', 'Your email has been successfully verified! You can now log in.');
        res.redirect('/login');
    } catch (error) {
        console.error('Error verifying email:', error);
        req.flash('error', 'An error occurred during email verification.');
        res.redirect('/login');
    }
});

app.post('/resend-verification', async (req, res) => {
    try {
        const emailToResend = req.session.user ? req.session.user.email : req.body.email;

        if (!emailToResend) {
            req.flash('error', 'No email provided for resending verification.');
            return res.redirect('/verify-email');
        }

        const user = await User.findOne({ email: emailToResend });

        if (!user) {
            req.flash('error', 'No account found with that email address.');
            return res.redirect('/verify-email');
        }
        if (user.isVerified) {
            req.flash('success', 'Your email is already verified. Please log in.');
            return res.redirect('/login');
        }

        const newVerificationToken = crypto.randomBytes(32).toString('hex');
        user.verificationToken = newVerificationToken;
        user.verificationTokenExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const verificationUrl = `http://localhost:${PORT}/verify/${newVerificationToken}`;
        transporter.sendMail({
            to: user.email,
            from: process.env.EMAIL_USER,
            subject: 'Yacht Marina Booking - Resend Email Verification',
            html: `<p>We received a request to resend your verification link. Please click <a href="${verificationUrl}">here</a> to verify your email. This link will expire in 1 hour.</p>`
        }, (error, info) => {
            if (error) {
                console.error("Error resending verification email:", error);
            } else {
                console.log("Resend verification email sent:", info.response);
            }
        });

        req.flash('success', 'A new verification link has been sent to your email.');
        res.redirect('/verify-email');
    } catch (error) {
        console.error('Error resending verification email:', error);
        req.flash('error', 'Could not resend verification email. Please try again later.');
        res.redirect('/verify-email');
    }
});


// Forgot Password
app.get('/forgot', (req, res) => res.render('forgot'));
app.post('/forgot', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            req.flash('error', 'No account with that email address exists.');
            return res.redirect('/forgot');
        }
        const resetToken = crypto.randomBytes(20).toString('hex');
        user.resetToken = resetToken;
        user.resetTokenExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const resetUrl = `http://localhost:${PORT}/reset-password/${resetToken}`;
        transporter.sendMail({
            to: user.email,
            from: process.env.EMAIL_USER,
            subject: 'Yacht Marina Booking - Password Reset',
            html: `<p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
                     <p>Please click on the following link, or paste this into your browser to complete the process:</p>
                     <p><a href="${resetUrl}">${resetUrl}</a></p>
                     <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
                     <p>This link will expire in 1 hour.</p>`
        }, (error, info) => {
            if (error) {
                console.error("Error sending password reset email:", error);
            } else {
                console.log("Password reset email sent:", info.response);
            }
        });

        req.flash('success', 'A password reset link has been sent to your email.');
        res.redirect('/forgot');
    } catch (error) {
        console.error('Error sending reset email:', error);
        req.flash('error', 'Could not send reset email. Please try again.');
        res.redirect('/forgot');
    }
});

app.get('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetToken: req.params.token,
            resetTokenExpires: { $gt: Date.now() }
        });
        if (!user) {
            req.flash('error', 'Password reset token is invalid or has expired.');
            return res.redirect('/forgot');
        }
        res.render('reset-password', { token: req.params.token });
    } catch (error) {
        console.error('Error rendering reset password page:', error);
        req.flash('error', 'Server error while loading password reset page.');
        res.redirect('/forgot');
    }
});

app.post('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetToken: req.params.token,
            resetTokenExpires: { $gt: Date.now() }
        });
        if (!user) {
            req.flash('error', 'Password reset token is invalid or has expired.');
            return res.redirect('/forgot');
        }

        const { password, confirmPassword } = req.body;
        if (password.length < 6) {
            req.flash('error', 'New password must be at least 6 characters long.');
            return res.redirect('/reset-password/' + req.params.token);
        }
        if (password !== confirmPassword) {
            req.flash('error', 'Passwords do not match.');
            return res.redirect('/reset-password/' + req.params.token);
        }

        user.password = password;
        user.resetToken = undefined;
        user.resetTokenExpires = undefined;
        await user.save();

        req.flash('success', 'Your password has been successfully updated! Please log in with your new password.');
        res.redirect('/login');
    } catch (error) {
        console.error('Error resetting password:', error);
        req.flash('error', 'Error resetting password. Please try again.');
        res.redirect('/forgot');
    }
});

// User Dashboard
app.get('/dashboard', isAuthenticated, async (req, res) => {
    try {
        const bookings = await Booking.find({ user: req.session.userId }).populate('boat').sort({ bookingDate: 1, startTime: 1 });
        res.render('dashboard', {
            user: req.session.user,
            bookings: bookings
        });
    } catch (err) {
        console.error('Error loading user dashboard:', err);
        req.flash('error', 'Unable to load dashboard.');
        res.redirect('/');
    }
});

// Bookings
app.get('/book/:boatId', isAuthenticated, async (req, res) => {
    try {
        const boat = await Boat.findById(req.params.boatId);
        if (!boat) {
            req.flash('error', 'Boat not found.');
            return res.redirect('/');
        }
        res.render('book', { boat });
    } catch (error) {
        console.error('Error loading book page:', error);
        req.flash('error', 'Could not load booking page for the selected boat.');
        res.redirect('/');
    }
});

app.post('/book', isAuthenticated, async (req, res) => {
    try {
        const { boatId, bookingDate, startTime, endTime, numberOfPersons, phoneNumber } = req.body;

        if (!boatId || !bookingDate || !startTime || !endTime || !numberOfPersons || !phoneNumber) {
            req.flash('error', 'All fields are required.');
            return res.redirect(`/book/${boatId || ''}`);
        }

        const boat = await Boat.findById(boatId);
        if (!boat) {
            req.flash('error', 'Selected boat not found.');
            return res.redirect('/');
        }

        if (!boat.availability) { // Check boat availability
            req.flash('error', 'This yacht is currently unavailable for booking.');
            return res.redirect('/');
        }

        const parsedBookingDate = new Date(bookingDate);
        const today = new Date();
        today.setHours(0,0,0,0);

        if (isNaN(parsedBookingDate.getTime()) || parsedBookingDate < today) {
            req.flash('error', 'Please select a valid future date.');
            return res.redirect(`/book/${boatId}`);
        }

        const timeRegex = /^(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$/; // HH:MM format (00:00 to 23:59)
        if (!timeRegex.test(startTime) || !timeRegex.test(endTime)) {
            req.flash('error', 'Invalid time format. Please use HH:MM (e.g., 09:00).');
            return res.redirect(`/book/${boatId}`);
        }

        // Validate time range (09:00 to 21:00)
        const startHour = parseInt(startTime.split(':')[0]);
        const endHour = parseInt(endTime.split(':')[0]);

        if (startHour < 9 || startHour > 20 || endHour < 9 || endHour > 21 || (endHour === 21 && parseInt(endTime.split(':')[1]) > 0)) {
             req.flash('error', 'Booking times must be between 09:00 and 21:00.');
             return res.redirect(`/book/${boatId}`);
        }


        // --- START DEBUG LOGS FOR TOTALPRICE (SERVER-SIDE) ---
        console.log("--- Server-side Booking Calculation Debug ---");
        console.log("Raw startTime:", startTime);
        console.log("Raw endTime:", endTime);

        const startMinutes = parseInt(startTime.split(':')[0]) * 60 + parseInt(startTime.split(':')[1]);
        const endMinutes = parseInt(endTime.split(':')[0]) * 60 + parseInt(endTime.split(':')[1]);

        console.log("Parsed startMinutes:", startMinutes);
        console.log("Parsed endMinutes:", endMinutes);

        if (startMinutes >= endMinutes) {
            req.flash('error', 'End time must be after start time.');
            return res.redirect(`/book/${boatId}`);
        }

        const durationHours = (endMinutes - startMinutes) / 60;
        console.log("Calculated durationHours:", durationHours);

        console.log("Boat pricePerHour:", boat.pricePerHour);

        const totalPrice = durationHours * boat.pricePerHour;
        console.log("Calculated totalPrice (Final):", totalPrice);
        // --- END DEBUG LOGS FOR TOTALPRICE ---

        if (durationHours <= 0) { // Should be caught by startMinutes >= endMinutes, but good safeguard
             req.flash('error', 'Booking duration must be at least 1 hour.'); // Or adjust minimum duration
             return res.redirect(`/book/${boatId}`);
        }

        if (numberOfPersons < 1 || numberOfPersons > boat.maxPersons) {
            req.flash('error', `Number of persons must be between 1 and ${boat.maxPersons} for this boat.`);
            return res.redirect(`/book/${boatId}`);
        }

        // Basic phone number validation
        if (!/^\+?[0-9\s-()]{7,20}$/.test(phoneNumber)) {
            req.flash('error', 'Please enter a valid phone number (min 7, max 20 digits, can include +, spaces, -, ()).');
            return res.redirect(`/book/${boatId}`);
        }

        // Check for time overlaps for the selected boat and date
        const existingBookings = await Booking.find({
            boat: boatId,
            bookingDate: parsedBookingDate,
            status: { $in: ['pending', 'confirmed'] } // Only consider active bookings for overlap check
        });

        const hasOverlap = existingBookings.some(existingBooking => {
            return isTimeOverlap(startTime, endTime, existingBooking.startTime, existingBooking.endTime);
        });

        if (hasOverlap) {
            req.flash('error', 'The selected boat is already booked for this time slot. Please choose another time or boat.');
            return res.redirect(`/book/${boatId}`);
        }

        const newBooking = new Booking({
            user: req.session.userId,
            boat: boatId,
            bookingDate: parsedBookingDate,
            startTime,
            endTime,
            numberOfPersons,
            phoneNumber,
            totalPrice // Use the calculated price
        });
        await newBooking.save();

        req.flash('success', 'Booking successful! Your booking is pending confirmation.');
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Booking failed:', error);
        req.flash('error', 'Booking failed. An unexpected error occurred. Please try again.');
        const boatId = req.body.boatId || '';
        res.redirect(`/book/${boatId}`);
    }
});

// User's All Bookings
app.get('/bookings', isAuthenticated, async (req, res) => {
    try {
        const bookings = await Booking.find({ user: req.session.userId }).populate('boat').sort({ bookingDate: 1, startTime: 1 });
        res.render('user-bookings', { bookings });
    } catch (error) {
        console.error('Error loading user bookings:', error);
        req.flash('error', 'Error loading your bookings.');
        res.render('user-bookings', { bookings: [] });
    }
});

// Update/Cancel Booking (User-side)
app.post('/bookings/:id', isAuthenticated, async (req, res) => {
    try {
        const { status } = req.body;
        const bookingId = req.params.id;

        const booking = await Booking.findOne({ _id: bookingId, user: req.session.userId });

        if (!booking) {
            req.flash('error', 'Booking not found or you do not have permission to modify it.');
            return res.redirect('/bookings');
        }

        if (status === 'cancelled' && (booking.status === 'pending' || booking.status === 'confirmed')) {
            booking.status = 'cancelled';
            await booking.save();
            req.flash('success', 'Booking has been cancelled successfully.');
        } else {
            req.flash('error', 'Invalid action or booking status for this operation.');
        }
        res.redirect('/bookings');

    } catch (error) {
        console.error('Error updating/cancelling booking:', error);
        req.flash('error', 'An error occurred while trying to update your booking.');
        res.redirect('/bookings');
    }
});


// Profile
app.get('/profile', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            req.flash('error', 'User profile not found. Please log in again.');
            return res.redirect('/login');
        }
        res.render('profile', { user });
    } catch (error) {
        console.error('Error loading profile page:', error);
        req.flash('error', 'Could not load your profile.');
        res.redirect('/dashboard');
    }
});


// Admin Panel
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    res.redirect('/admin/dashboard');
});

app.get('/admin/dashboard', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const users = await User.find({});
        const bookings = await Booking.find({}).populate('user').populate('boat').sort({ createdAt: -1 });
        res.render('admin/dashboard', { users, bookings });
    } catch (error) {
        console.error('Error loading admin dashboard:', error);
        req.flash('error', 'Could not load admin dashboard.');
        res.redirect('/');
    }
});

// ADMIN BOOKING EDIT
app.get('/admin/edit-booking/:id', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const booking = await Booking.findById(req.params.id).populate('user').populate('boat');
        const boats = await Boat.find({});
        if (!booking) {
            req.flash('error', 'Booking not found.');
            return res.redirect('/admin/dashboard');
        }
        // Format date for the input type="date"
        const formattedBookingDate = booking.bookingDate ? booking.bookingDate.toISOString().split('T')[0] : '';
        res.render('admin/edit-booking', { booking, boats, formattedBookingDate });
    } catch (err) {
        console.error('Error loading admin edit booking page:', err);
        req.flash('error', 'Could not load edit page for booking.');
        res.redirect('/admin/dashboard');
    }
});

app.post('/admin/edit-booking/:id', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const { bookingDate, startTime, endTime, numberOfPersons, phoneNumber, boatId, status } = req.body;
        const booking = await Booking.findById(req.params.id);

        if (!booking) {
            req.flash('error', 'Booking not found.');
            return res.redirect('/admin/dashboard');
        }

        // Update fields only if provided
        if (bookingDate) {
            const parsedBookingDate = new Date(bookingDate);
            if (isNaN(parsedBookingDate.getTime())) {
                req.flash('error', 'Invalid booking date provided.');
                return res.redirect(`/admin/edit-booking/${req.params.id}`);
            }
            booking.bookingDate = parsedBookingDate;
        }
        if (startTime) {
            const timeRegex = /^(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$/;
            if (!timeRegex.test(startTime)) {
                req.flash('error', 'Invalid start time format (HH:MM).');
                return res.redirect(`/admin/edit-booking/${req.params.id}`);
            }
            booking.startTime = startTime;
        }
        if (endTime) {
            const timeRegex = /^(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$/;
            if (!timeRegex.test(endTime)) {
                req.flash('error', 'Invalid end time format (HH:MM).');
                return res.redirect(`/admin/edit-booking/${req.params.id}`);
            }
            booking.endTime = endTime;
        }
        if (numberOfPersons) {
            const numPersons = parseInt(numberOfPersons);
            if (isNaN(numPersons) || numPersons < 1) {
                req.flash('error', 'Number of persons must be a positive number.');
                return res.redirect(`/admin/edit-booking/${req.params.id}`);
            }
            booking.numberOfPersons = numPersons;
        }
        if (phoneNumber) {
             if (!/^\+?[0-9\s-()]{7,20}$/.test(phoneNumber)) {
                 req.flash('error', 'Please enter a valid phone number (min 7, max 20 digits, can include +, spaces, -, ()).');
                 return res.redirect(`/admin/edit-booking/${req.params.id}`);
             }
             booking.phoneNumber = phoneNumber;
        }
        if (status) {
            const validStatuses = ['pending', 'confirmed', 'cancelled', 'completed'];
            if (!validStatuses.includes(status)) {
                req.flash('error', 'Invalid booking status.');
                return res.redirect(`/admin/edit-booking/${req.params.id}`);
            }
            booking.status = status;
        }

        let currentBoatPricePerHour;

        if (boatId && String(boatId) !== String(booking.boat)) {
            const newBoat = await Boat.findById(boatId);
            if (!newBoat) {
                req.flash('error', 'New boat selected for booking not found.');
                return res.redirect(`/admin/edit-booking/${req.params.id}`);
            }
            booking.boat = boatId;
            currentBoatPricePerHour = newBoat.pricePerHour;
        } else {
            // Populate boat if not already populated
            if (!booking.boat || !booking.boat.pricePerHour) {
                await booking.populate('boat');
            }
            currentBoatPricePerHour = booking.boat.pricePerHour;
        }

        // Recalculate totalPrice based on potentially new times or boat
        const currentStartMinutes = parseInt(booking.startTime.split(':')[0]) * 60 + parseInt(booking.startTime.split(':')[1]);
        const currentEndMinutes = parseInt(booking.endTime.split(':')[0]) * 60 + parseInt(booking.endTime.split(':')[1]);

        if (currentEndMinutes <= currentStartMinutes) {
            req.flash('error', 'End time must be after start time.');
            return res.redirect(`/admin/edit-booking/${req.params.id}`);
        }

        const durationHours = (currentEndMinutes - currentStartMinutes) / 60;
        booking.totalPrice = durationHours * currentBoatPricePerHour;

        await booking.save();
        req.flash('success', 'Booking updated successfully!');
        res.redirect('/admin/dashboard');
    } catch (err) {
        console.error('Error updating booking by admin:', err);
        req.flash('error', 'Error updating booking. Please try again.');
        res.redirect('/admin/dashboard');
    }
});

app.post('/admin/bookings/:id', isAuthenticated, isAdmin, async (req, res) => {
    if (req.body._method === 'DELETE') {
        try {
            const bookingId = req.params.id;
            const deletedBooking = await Booking.findByIdAndDelete(bookingId);

            if (!deletedBooking) {
                req.flash('error', 'Booking not found.');
            } else {
                req.flash('success', 'Booking deleted successfully.');
            }
            res.redirect('/admin/dashboard');
        } catch (error) {
            console.error('Error deleting booking by admin:', error);
            req.flash('error', 'Error deleting booking. Please try again.');
            res.redirect('/admin/dashboard');
        }
    } else {
        res.status(405).send('Method Not Allowed');
    }
});

// ADMIN YACHT MANAGEMENT

// Get all yachts for admin view
app.get('/admin/yachts', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const yachts = await Boat.find({});
        res.render('admin/yachts', { yachts });
    } catch (error) {
        console.error('Error loading admin yachts page:', error);
        req.flash('error', 'Could not load yachts for management.');
        res.redirect('/admin/dashboard');
    }
});

// Render Add Yacht Form
app.get('/admin/yachts/add', isAuthenticated, isAdmin, (req, res) => {
    res.render('admin/add-yacht');
});

// Handle Add Yacht Submission
app.post('/admin/yachts/add', isAuthenticated, isAdmin, upload.single('imageUrl'), async (req, res) => {
    try {
        const { name, display, maxPersons, pricePerHour, description } = req.body;
        const imageUrl = req.file ? `/images/${req.file.filename}` : '/images/default_boat.jpg';

        if (!name || !maxPersons || !pricePerHour) {
            req.flash('error', 'Name, Max Persons, and Price Per Hour are required.');
            // If file was uploaded, delete it if there's a validation error
            if (req.file) {
                fs.unlink(req.file.path, (err) => {
                    if (err) console.error('Error deleting uploaded file:', err);
                });
            }
            return res.redirect('/admin/yachts/add');
        }

        // Basic validation (you can add more robust validation)
        if (isNaN(maxPersons) || parseInt(maxPersons) < 1) {
            req.flash('error', 'Max Persons must be a number greater than 0.');
            if (req.file) fs.unlink(req.file.path, (err) => { if (err) console.error(err); });
            return res.redirect('/admin/yachts/add');
        }
        if (isNaN(pricePerHour) || parseFloat(pricePerHour) < 0) {
            req.flash('error', 'Price Per Hour must be a non-negative number.');
            if (req.file) fs.unlink(req.file.path, (err) => { if (err) console.error(err); });
            return res.redirect('/admin/yachts/add');
        }

        const newBoat = new Boat({
            name,
            display: display || name, // Use name if display is empty
            maxPersons: parseInt(maxPersons),
            pricePerHour: parseFloat(pricePerHour),
            imageUrl,
            description: description || '' // Use empty string if description is empty
        });

        await newBoat.save();
        req.flash('success', 'Yacht added successfully!');
        res.redirect('/admin/yachts');
    } catch (error) {
        console.error('Error adding yacht:', error);
        req.flash('error', 'Failed to add yacht. ' + (error.code === 11000 ? 'A yacht with this name already exists.' : error.message));
        // If file was uploaded, delete it
        if (req.file) {
            fs.unlink(req.file.path, (err) => {
                if (err) console.error('Error deleting uploaded file on save error:', err);
            });
        }
        res.redirect('/admin/yachts/add');
    }
});


// Render Edit Yacht Form
app.get('/admin/yachts/edit/:id', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const yacht = await Boat.findById(req.params.id);
        if (!yacht) {
            req.flash('error', 'Yacht not found.');
            return res.redirect('/admin/yachts');
        }
        res.render('admin/edit-yacht', { yacht });
    } catch (error) {
        console.error('Error loading edit yacht page:', error);
        req.flash('error', 'Could not load yacht for editing.');
        res.redirect('/admin/yachts');
    }
});

// Handle Edit Yacht Submission
app.post('/admin/yachts/edit/:id', isAuthenticated, isAdmin, upload.single('imageUrl'), async (req, res) => {
    try {
        const { name, display, maxPersons, pricePerHour, description, availability } = req.body;
        const yachtId = req.params.id;
        const currentYacht = await Boat.findById(yachtId);

        if (!currentYacht) {
            req.flash('error', 'Yacht not found for update.');
            // If file was uploaded, delete it
            if (req.file) {
                fs.unlink(req.file.path, (err) => {
                    if (err) console.error('Error deleting uploaded file on yacht not found:', err);
                });
            }
            return res.redirect('/admin/yachts');
        }

        // Update fields
        currentYacht.name = name || currentYacht.name;
        currentYacht.display = display || name || currentYacht.display;
        currentYacht.maxPersons = parseInt(maxPersons) || currentYacht.maxPersons;
        currentYacht.pricePerHour = parseFloat(pricePerHour) || currentYacht.pricePerHour;
        currentYacht.description = description !== undefined ? description : currentYacht.description; // Allow empty string
        currentYacht.availability = (availability === 'true'); // Convert string to boolean

        // Handle image update
        if (req.file) {
            // Delete old image if it's not the default one
            if (currentYacht.imageUrl && currentYacht.imageUrl !== '/images/default_boat.jpg') {
                const oldImagePath = path.join(__dirname, 'public', currentYacht.imageUrl);
                fs.unlink(oldImagePath, (err) => {
                    if (err) console.error('Error deleting old image:', err);
                });
            }
            currentYacht.imageUrl = `/images/${req.file.filename}`;
        }

        await currentYacht.save();
        req.flash('success', 'Yacht updated successfully!');
        res.redirect('/admin/yachts');

    } catch (error) {
        console.error('Error updating yacht:', error);
        req.flash('error', 'Failed to update yacht. ' + error.message);
        // If file was uploaded, delete it
        if (req.file) {
            fs.unlink(req.file.path, (err) => {
                if (err) console.error('Error deleting uploaded file on update error:', err);
            });
        }
        res.redirect(`/admin/yachts/edit/${req.params.id}`);
    }
});

// Handle Delete Yacht
app.post('/admin/yachts/:id', isAuthenticated, isAdmin, async (req, res) => {
    if (req.body._method === 'DELETE') {
        try {
            const yachtId = req.params.id;
            const yacht = await Boat.findById(yachtId);

            if (!yacht) {
                req.flash('error', 'Yacht not found.');
                return res.redirect('/admin/yachts');
            }

            // Before deleting the boat, delete its image if not default
            if (yacht.imageUrl && yacht.imageUrl !== '/images/default_boat.jpg') {
                const imagePath = path.join(__dirname, 'public', yacht.imageUrl);
                fs.unlink(imagePath, (err) => {
                    if (err) console.error('Error deleting yacht image:', err);
                });
            }

            // Optional: Handle associated bookings
            // Decide what to do with bookings for this deleted yacht:
            // 1. Delete them: await Booking.deleteMany({ boat: yachtId });
            // 2. Mark them cancelled: await Booking.updateMany({ boat: yachtId }, { status: 'cancelled' });
            // For now, we'll just delete the boat. Consider your data integrity needs.

            await Boat.findByIdAndDelete(yachtId);
            req.flash('success', 'Yacht deleted successfully!');
            res.redirect('/admin/yachts');

        } catch (error) {
            console.error('Error deleting yacht:', error);
            req.flash('error', 'Failed to delete yacht. ' + error.message);
            res.redirect('/admin/yachts');
        }
    } else {
        res.status(405).send('Method Not Allowed');
    }
});


app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});