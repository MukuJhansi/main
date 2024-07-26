const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const PORT = 443;

// Database configuration
const dbConfig = {
    user: 'user_pnj7_user',
    host: 'dpg-cqgfq62ju9rs73cdicu0-a',
    database: 'user_pnj7',
    password: 'c2c6apNS6pCoyYRdv5eGqJzoGf78ptLN',
    port: 5432,
};

const pool = new Pool(dbConfig);

app.use(session({
    store: new pgSession({
        pool, // Connection pool
        tableName: 'session', // Use another table-name than the default "session" one
    }),
    secret: 'GRP"mFa`wL9?D%X]etH>k#',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week
        secure: true, // Ensure cookies are sent only over HTTPS
        httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
        sameSite: 'Strict', // Ensures cookies are only sent for same-site requests
    }
}));

app.use(express.static('public'));
app.use('/styles', express.static(path.join(__dirname, 'styles')));
app.use('/pic/', express.static(path.join(__dirname, 'pic')));
app.use('/video/', express.static(path.join(__dirname, 'video')));
app.use('/', express.static(path.join(__dirname, 'home')));
app.use('/html/', express.static(path.join(__dirname, 'html')));
app.use('/script/', express.static(path.join(__dirname, 'scripts')));

app.use(bodyParser.json());
app.use(cors());

const transporter = nodemailer.createTransport({
    host: 'smtp.office365.com',
    port: 587,
    secure: false,
    auth: {
        user: 'a@3pmmsm.onmicrosoft.com',
        pass: 'Mukund@123',
    },
    tls: {
        ciphers: 'SSLv3',
        minVersion: 'TLSv1',
        maxVersion: 'TLSv1.2',
    },
    debug: true
});

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Serve the home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'index.html'));
});

// Serve the Rickroll page
app.get('/bamlaJiSmash', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'Rickroll.html'));
});

// Serve the development page
app.get('/development', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'devlopment.html'));
});

// Serve the signup page
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'signup.html'));
});

// Serve the login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'login.html'));
});

// Serve the dashboard page
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'dashboard.html'));
});

app.post('/generate-otp', async (req, res) => {
    try {
        const { name, id, mobile, password } = req.body;

        if (!name || !id || !mobile || !password) {
            return res.status(400).json({ success: false, message: "All fields are required." });
        }

        const client = await pool.connect();
        try {
            // Generate a new OTP
            const otp = generateOTP();

            // Check if the email already exists in the OTP table
            const { rows } = await client.query('SELECT * FROM otps WHERE email = $1', [id]);

            if (rows.length > 0) {
                // Email already exists, update the OTP
                await client.query('UPDATE otps SET otp = $1, created_at = NOW() WHERE email = $2', [otp, id]);
            } else {
                // Email does not exist, insert new OTP
                await client.query('INSERT INTO otps (email, otp, created_at) VALUES ($1, $2, NOW())', [id, otp]);
            }

            // Send OTP email
            const mailOptions = {
                from: 'a@3pmmsm.onmicrosoft.com',
                to: id,
                subject: 'Verification OTP',
                text: `Your OTP for registration is: ${otp}`,
            };

            try {
                await transporter.sendMail(mailOptions);
                // Store the OTP in the session
                req.session.otp = otp;
                req.session.email = id; // Store email for verification
                req.session.name = name;
                req.session.mobile = mobile;
                req.session.password = password;

                res.json({ success: true, otp });
            } catch (emailError) {
                console.error('Error sending OTP:', emailError);
                res.status(500).json({ success: false, message: "Failed to send OTP. Please try again." });
            }
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error in /generate-otp:', error);
        return res.status(500).json({ success: false, message: "Internal server error during OTP generation." });
    }
});

app.post('/verify-otp', async (req, res) => {
    try {
        const { otp } = req.body;

        if (!otp) {
            return res.status(400).json({ success: false, message: "OTP is required." });
        }

        const client = await pool.connect();
        try {
            // Retrieve the OTP and email from the session
            const storedOTP = req.session.otp;
            const email = req.session.email;

            if (!storedOTP || !email) {
                return res.status(400).json({ success: false, message: "OTP or email is missing in the session." });
            }

            // Check if the provided OTP matches the stored OTP
            if (otp !== storedOTP) {
                return res.status(400).json({ success: false, message: "Invalid OTP." });
            }

            // Check if the email is already registered
            const { rows: userRows } = await client.query('SELECT * FROM users WHERE email = $1', [email]);

            if (userRows.length > 0) {
                // Email is already registered
                return res.json({ success: true, message: "Email is already registered. You can log in." });
            }

            // Retrieve additional user data from session
            const { name, mobile, password } = req.session;

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert new user into the database
            await client.query(
                'INSERT INTO users (username, password, name, email, mobile) VALUES ($1, $2, $3, $4, $5)',
                [name, hashedPassword, name, email, mobile]
            );

            // Delete OTP from the database
            await client.query('DELETE FROM otps WHERE email = $1', [email]);

            // Respond with success
            return res.json({ success: true, message: "Signup successful!" });
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error in /verify-otp:', error);
        return res.status(500).json({ success: false, message: "Internal server error during OTP verification." });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            console.log('Error: Missing email or password');
            return res.status(400).json({ success: false, message: "Email and password are required." });
        }

        const client = await pool.connect();
        try {
            // Fetch user from database
            const { rows } = await client.query('SELECT * FROM users WHERE email = $1', [email]);

            if (rows.length === 0) {
                console.log('Error: Invalid email');
                return res.status(401).json({ success: false, message: "Invalid email or password." });
            }

            const user = rows[0];

            // Compare the provided password with the stored hashed password
            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                console.log('Error: Invalid password');
                return res.status(401).json({ success: false, message: "Invalid email or password." });
            }

            // Successful login
            req.session.userId = user.id; // Store user ID in session
            console.log('Session data after login:', req.session);

            res.json({ success: true, message: "Login successful!" });
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error in /login:', error);
        res.status(500).json({ success: false, message: "Internal server error during login." });
    }
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.status(401).json({ success: false, message: "Unauthorized. Please log in." });
}

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
