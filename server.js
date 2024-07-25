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
        tableName: 'session' // Use another table-name than the default "session" one
    }),
    secret: 'GRP"mFa`wL9?D%X]etH>k#',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week
        secure: true, // Ensure cookies are sent only over HTTPS
        httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
        sameSite: 'Strict' // Ensures cookies are only sent for same-site requests
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
            const otp = generateOTP();

            const { rows } = await client.query('SELECT * FROM otps WHERE email = $1', [id]);

            if (rows.length > 0) {
                await client.query('UPDATE otps SET otp = $1, created_at = NOW() WHERE email = $2', [otp, id]);
            } else {
                await client.query('INSERT INTO otps (email, otp, created_at) VALUES ($1, $2, NOW())', [id, otp]);
            }

            const mailOptions = {
                from: 'a@3pmmsm.onmicrosoft.com',
                to: id,
                subject: 'Verification OTP',
                text: `Your OTP for registration is: ${otp}`,
            };

            try {
                await transporter.sendMail(mailOptions);
                req.session.otp = otp;
                req.session.email = id;
                req.session.name = name;
                req.session.mobile = mobile;
                req.session.password = password;
                console.log('Session data after OTP generation:', req.session); // Debugging
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
            const storedOTP = req.session.otp;
            const email = req.session.email;
            console.log('Session data during OTP verification:', req.session); // Debugging

            if (!storedOTP || !email) {
                return res.status(400).json({ success: false, message: "OTP or email is missing in the session." });
            }

            if (otp !== storedOTP) {
                console.log('Stored OTP:', storedOTP, 'Provided OTP:', otp); // Debugging
                return res.status(400).json({ success: false, message: "Invalid OTP." });
            }

            const { rows: userRows } = await client.query('SELECT * FROM users WHERE email = $1', [email]);

            if (userRows.length > 0) {
                return res.json({ success: true, message: "Email is already registered. You can log in." });
            }

            const { name, mobile, password } = req.session;
            const hashedPassword = await bcrypt.hash(password, 10);

            await client.query(
                'INSERT INTO users (username, password, name, email, mobile) VALUES ($1, $2, $3, $4, $5)',
                [name, hashedPassword, name, email, mobile]
            );

            await client.query('DELETE FROM otps WHERE email = $1', [email]);

            req.session.otp = null;
            req.session.email = null;
            req.session.name = null;
            req.session.mobile = null;
            req.session.password = null;

            return res.json({ success: true, message: "Signup successful!" });
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error in /verify-otp:', error);
        return res.status(500).json({ success: false, message: "Internal server error during OTP verification." });
    }
});

// Handle login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Username and password are required." });
    }

    try {
        const client = await pool.connect();
        const result = await client.query('SELECT id, password FROM users WHERE username = $1', [username]);

        if (result.rows.length === 0) {
            return res.json({ success: false, message: "Invalid username or password." });
        }

        const hashedPassword = result.rows[0].password;
        const passwordMatch = await bcrypt.compare(password, hashedPassword);

        if (passwordMatch) {
            req.session.userId = result.rows[0].id;
            return res.json({ success: true });
        } else {
            return res.json({ success: false, message: "Invalid username or password." });
        }
    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});

app.post('/signup', async (req, res) => {
    const { username, password, name, id, otp } = req.body;

    if (!username || !password || !name || !otp) {
        console.log('Error: All fields are required.');  // Debug log
        return res.json({ success: false, message: "All fields are required." });
    }

    const storedOTP = req.session.otp;
    console.log('Stored OTP:', storedOTP);  // Debug log
    console.log('Provided OTP:', otp);  // Debug log

    if (otp !== storedOTP) {
        console.log('Error: Invalid OTP.');  // Debug log
        return res.json({ success: false, message: "Invalid OTP. Please try again." });
    }

    delete req.session.otp;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const client = await pool.connect();

        console.log('Data to be inserted:');  // Debug log
        console.log('Username:', username);
        console.log('Hashed Password:', hashedPassword);
        console.log('Name:', name);
        console.log('Email:', id);

        try {
            const result = await client.query(
                'INSERT INTO users (username, password, name, email) VALUES ($1, $2, $3, $4) RETURNING id',
                [username, hashedPassword, name, id]
            );
            console.log('Insert result:', result);  // Debug log
            if (result.rows.length > 0) {
                return res.json({ success: true });
            } else {
                return res.json({ success: false, message: "Failed to signup. Please try again." });
            }
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error during signup:', error);  // Log error
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});

// Route to request password reset
app.post('/request-password-reset', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ success: false, message: "Email is required." });
        }

        const client = await pool.connect();
        try {
            const resetToken = crypto.randomBytes(32).toString('hex');
            const resetTokenExpiry = new Date(Date.now() + 3600000); // Token valid for 1 hour

            // Insert or update reset token in the database
            await client.query(
                'INSERT INTO password_resets (email, token, expiry) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET token = $2, expiry = $3',
                [email, resetToken, resetTokenExpiry]
            );

            const resetLink = `http://gunman.is-a.dev/reset-password?token=${resetToken}`;

            const mailOptions = {
                from: 'a@3pmmsm.onmicrosoft.com',
                to: email,
                subject: 'Password Reset Request',
                text: `You requested a password reset. Click the following link to reset your password: ${resetLink}`,
            };

            try {
                await transporter.sendMail(mailOptions);
                res.json({ success: true, message: "Password reset link sent to your email." });
            } catch (emailError) {
                console.error('Error sending reset email:', emailError);
                res.status(500).json({ success: false, message: "Failed to send reset email. Please try again." });
            }
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error in /request-password-reset:', error);
        return res.status(500).json({ success: false, message: "Internal server error during password reset request." });
    }
});

// Route to reset password
app.post('/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ success: false, message: "Token and new password are required." });
        }

        const client = await pool.connect();
        try {
            // Validate the token
            const { rows: resetRows } = await client.query(
                'SELECT * FROM password_resets WHERE token = $1 AND expiry > NOW()',
                [token]
            );

            if (resetRows.length === 0) {
                return res.status(400).json({ success: false, message: "Invalid or expired token." });
            }

            const { email } = resetRows[0];

            // Hash the new password
            const hashedPassword = await bcrypt.hash(newPassword, 10);

            // Update the user's password
            await client.query(
                'UPDATE users SET password = $1 WHERE email = $2',
                [hashedPassword, email]
            );

            // Delete the reset token from the database
            await client.query('DELETE FROM password_resets WHERE token = $1', [token]);

            res.json({ success: true, message: "Password reset successful." });
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error in /reset-password:', error);
        return res.status(500).json({ success: false, message: "Internal server error during password reset." });
    }
});

// Handle signout request
app.post('/signout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Session destroy error:', err);
            return res.status(500).json({ success: false, message: "Failed to sign out. Please try again." });
        }
        res.json({ success: true, message: "Sign out successful." });
    });
});

// Middleware to check authentication
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'dashboard.html'));
});

app.get('/payment', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'payment.html'));
});

app.listen(PORT, '0.0.0.0', (err) => {
    if (err) {
        console.error('Server startup error:', err);
    } else {
        console.log(`Server is running on http://0.0.0.0:${PORT}`);
    }
});

function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}