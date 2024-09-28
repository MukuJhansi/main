require('dotenv').config();
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
const rateLimit = require('express-rate-limit');
const csurf = require('csurf');

const app = express();
const PORT = 443;

// Database configuration using environment variables
const dbConfig = {
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: 5432,
};

const pool = new Pool(dbConfig);

app.use(session({
    store: new pgSession({
        pool, // Connection pool
        tableName: 'session', // Use another table-name than the default "session" one
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week
        secure: false, // Change to true if using HTTPS
        httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
        sameSite: 'Strict', // Ensures cookies are only sent for same-site requests
    }
}));

app.use(express.static('public'));
app.use('/styles', express.static(path.join(__dirname, 'styles')));
app.use('/pic/', express.static(path.join(__dirname, 'pic')));
app.use('/video/', express.static(path.join(__dirname, 'video')));
app.use('/html/', express.static(path.join(__dirname, 'html')));
app.use('/script/', express.static(path.join(__dirname, 'scripts')));
app.use('/files/', express.static(path.join(__dirname, 'files')));

app.use(bodyParser.json());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// CSRF protection
const csrfProtection = csurf({ cookie: true });

const transporter = nodemailer.createTransport({
    host: 'smtp.office365.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    tls: {
        ciphers: 'SSLv3',
        minVersion: 'TLSv1',
        maxVersion: 'TLSv1.2',
    },
    debug: true
});

function generateOTP() {
    return crypto.randomBytes(3).toString('hex').toUpperCase();
}

// Serve the home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'index.html'));
});

// Serve the gen page
app.get('/gen', (req, res) => {
    res.sendFile(path.join(__dirname, 'files', 'Gen.zip'));
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

// Serve the calculator page
app.get('/calculator', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'calculator.html'));
});

// Serve the login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'login.html'));
});

// Serve the dashboard page
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'dashboard.html'));
});

app.post('/generate-otp', csrfProtection, async (req, res) => {
    try {
        const { name, id, mobile, password } = req.body;

        // Check if all required fields are provided
        if (!name || !id || !mobile || !password) {
            return res.status(400).json({ success: false, message: "All fields are required." });
        }

        // Connect to the database
        const client = await pool.connect();
        try {
            const otp = generateOTP(); // Generate a new OTP

            // Check if the email already exists in the OTP table
            const { rows } = await client.query('SELECT * FROM otps WHERE email = $1', [id]);

            if (rows.length > 0) {
                // Update existing OTP
                await client.query('UPDATE otps SET otp = $1, created_at = NOW() WHERE email = $2', [otp, id]);
            } else {
                // Insert new OTP
                await client.query('INSERT INTO otps (email, otp, created_at) VALUES ($1, $2, NOW())', [id, otp]);
            }

            // Prepare and send the OTP email
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: id,
                subject: 'Verification OTP',
                text: `Your OTP for registration is: ${otp}`,
            };

            await transporter.sendMail(mailOptions); // Send the email

            // Store OTP and details in the session
            req.session.otp = otp;
            req.session.email = id;
            req.session.name = name;
            req.session.mobile = mobile;
            req.session.password = password;

            res.json({ success: true, otp }); // Respond with success
        } catch (dbError) {
            console.error('Database error:', dbError);
            res.status(500).json({ success: false, message: "Database error during OTP generation." });
        } finally {
            client.release(); // Always release the client
        }
    } catch (error) {
        console.error('Error in /generate-otp:', error);
        res.status(500).json({ success: false, message: "Internal server error during OTP generation." });
    }
});

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

app.post('/verify-otp', csrfProtection, async (req, res) => {
    try {
        const { otp } = req.body;

        if (!otp) {
            return res.status(400).json({ success: false, message: "OTP is required." });
        }

        const client = await pool.connect();
        try {
            const storedOTP = req.session.otp;
            const email = req.session.email;

            if (!storedOTP || !email) {
                return res.status(400).json({ success: false, message: "OTP or email is missing in the session." });
            }

            if (otp !== storedOTP) {
                return res.status(400).json({ success: false, message: "Invalid OTP." });
            }

            const { rows: userRows } = await client.query('SELECT * FROM users WHERE email = $1', [email]);

            if (userRows.length > 0) {
                return res.json({ success: true, message: "Email is already registered. You can log in." });
            }

            const name = req.session.name;
            const mobile = req.session.mobile;
            const password = req.session.password;
            const hashedPassword = await bcrypt.hash(password, 10);

            await client.query(
                'INSERT INTO users (username, password, name, email, mobile) VALUES ($1, $2, $3, $4, $5)',
                [name, hashedPassword, name, email, mobile]
            );

            await client.query('DELETE FROM otps WHERE email = $1', [email]);

            res.json({ success: true, message: "Signup successful!" });
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error in /verify-otp:', error);
        res.status(500).json({ success: false, message: "Internal server error during OTP verification." });
    }
});

app.post('/login', csrfProtection, async (req, res) => {
    try {
        const { id, password } = req.body;

        if (!id || !password) {
            return res.status(400).json({ success: false, message: "Email and password are required." });
        }

        const client = await pool.connect();
        try {
            const { rows } = await client.query('SELECT * FROM users WHERE email = $1', [id]);

            if (rows.length === 0) {
                return res.status(400).json({ success: false, message: "Invalid email or password." });
            }

            const user = rows[0];
            const passwordMatch = await bcrypt.compare(password, user.password);

            if (!passwordMatch) {
                return res.status(400).json({ success: false, message: "Invalid email or password." });
            }

            req.session.userId = user.id;
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
