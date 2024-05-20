const express = require('express');
const connectDB = require('./config/db');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const transporter = require('./config/nodemailer');
const TempUser = require('./models/TempUser');
const User = require('./models/User');
require('dotenv').config();

const app = express();

// Connect Database
connectDB();

// Serve static files from the 'public' directory
app.use(express.static('public'));

// Init Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Session Middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// View Engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public'));

// Route for the register page
app.get('/register', (req, res) => {
    const formData = {};
    res.render('register', { error: null, formData });
});


// Route to handle registration form submission
app.post('/register', async (req, res) => {
    try {
        const { email, username, phone } = req.body;

        // Validate username format
        const usernameRegex = /^[a-zA-Z0-9._]{1,30}$/;
        if (!usernameRegex.test(username)) {
            return res.render('register', { error: 'Username must be 1-30 characters long and can only contain letters, numbers, periods, and underscores.' });
        }

        // Check if the username already exists
        const existingUsernameUser = await User.findOne({ username });
        const existingTempUsernameUser = await TempUser.findOne({ username });

        if (existingUsernameUser || existingTempUsernameUser) {
            req.formData = { email, username, phone };
            return res.render('register', { error: 'username taken', formData: req.formData });
        }

        // Check if the email already exists
        const existingEmailUser = await User.findOne({ email });
        const existingTempEmailUser = await TempUser.findOne({ email });
        if (existingEmailUser || existingTempEmailUser) {
            return res.render('register', { error: 'user already exists with this email.', formData: { email, username, phone } });
        }

        // Check if the phone number already exists
        const existingPhoneUser = await User.findOne({ phone });
        const existingTempPhoneUser = await TempUser.findOne({ phone });
        if (existingPhoneUser || existingTempPhoneUser) {
            return res.render('register', { error: 'user already exists with this number.', formData: { email, username, phone } });
        }


        const passphrase = generatePassphrase();
        console.log(`Generated passphrase for ${email}: ${passphrase}`);

        // Save user details and passphrase to the temporary user collection
        await TempUser.create({ email, username, phone, passphrase });

        // Send passphrase to user's email using Nodemailer transporter
        await transporter.sendMail({
            from: process.env.EMAIL_FROM,
            to: email,
            subject: 'Your Passphrase for Registration',
            text: `Your passphrase for registration is: ${passphrase}`,
        });

        res.redirect(`/verify?email=${encodeURIComponent(email)}`);
    } catch (error) {
        console.error('Error in registration route:', error);
        res.status(500).send('Internal Server Error');
    }
});


// Function to generate a passphrase (replace with your own logic)
function generatePassphrase() {
    return Math.random().toString(36).substr(2, 8);
}

// Route for the verify page (GET)
app.get('/verify', (req, res) => {
    const email = req.query.email;
    res.render('verify', { email });
});
// Route for handling verification form submission (POST)
app.post('/verify', async (req, res) => {
    try {
        const { email, passphrase } = req.body;

        // Retrieve the temporary user details
        const tempUser = await TempUser.findOne({ email });

        if (tempUser && tempUser.passphrase === passphrase) {
            // Store email and username in session to use in the set password page
            req.session.email = email;
            req.session.username = tempUser.username; // Store username in session

            res.redirect('/setpassword'); // Redirect to set password page
        } else {
            res.render('verify', { email, error: 'Invalid passphrase' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});


// Route for the set password page (GET)
app.get('/setpassword', (req, res) => {
    const email = req.session.email;
    const username = req.session.username;
    if (email) {
        res.render('setpassword', { email, username, error: null });
    } else {
        res.redirect('/register');
    }
});

// Route for handling set password form submission (POST)
app.post('/setpassword', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate password
        const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,12}$/;
        if (!passwordRegex.test(password)) {
            return res.render('setpassword', { email, error: 'Password must be 8-12 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.', username: req.session.username });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save the user details to the main user collection
        const tempUser = await TempUser.findOne({ email });
        await User.create({
            email,
            password: hashedPassword,
            username: tempUser.username,
            phone: tempUser.phone,
        });

        // Remove the temporary user details
        await TempUser.deleteOne({ email });

        res.redirect('/login');
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// Route for the login page
app.get('/login', (req, res) => {
    res.render('login', { error: null, username: '' });
});

// Route for handling login form submission (POST)
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find the user by username
        const user = await User.findOne({ username });
        if (!user) {
            return res.render('login', { error: 'user not registered', username });
        }

        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.render('login', { error: 'Invalid  password', username });
        }

        // Store user information in session
        req.session.user = { id: user._id, username: user.username, email: user.email };

        res.redirect('/dashboard');
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});



// Middleware to protect routes
function ensureAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    } else {
        res.redirect('/login');
    }
}

// Route for the home page (protected)
app.get('/dashboard', ensureAuthenticated, (req, res) => {
    res.render('dashboard', { user: req.session.user });
});

// Route for handling logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Internal Server Error');
        }
        res.redirect('/login');
    });
});

// Route for the contact page
app.get('/contact', (req, res) => {
    res.render('contact');
});

// Route for the main page
app.get('/', (req, res) => {
    res.render('home');
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
