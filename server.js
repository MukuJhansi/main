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

            const { name, mobile, password } = req.session;

            const hashedPassword = await bcrypt.hash(password, 10);

            await client.query(
                'INSERT INTO users (username, password, name, email, mobile) VALUES ($1, $2, $3, $4, $5)',
                [name, hashedPassword, name, email, mobile]
            );

            await client.query('DELETE FROM otps WHERE email = $1', [email]);

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
            console.log('Error: Missing email or password');  // Debug log
            return res.status(400).json({ success: false, message: "Email and password are required." });
        }

        const client = await pool.connect();
        try {
            const { rows } = await client.query('SELECT * FROM users WHERE email = $1', [email]);

            if (rows.length === 0) {
                console.log('Error: Invalid email');  // Debug log
                return res.status(401).json({ success: false, message: "Invalid email or password." });
            }

            const user = rows[0];

            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                console.log('Error: Invalid password');  // Debug log
                return res.status(401).json({ success: false, message: "Invalid email or password." });
            }

            req.session.userId = user.id; // Store user ID in session
            res.json({ success: true, message: "Login successful!" });
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error in /login:', error);
        res.status(500).json({ success: false, message: "Internal server error during login." });
    }
});

app.post('/signup', async (req, res) => {
    const { username, password, name, id, otp } = req.body;

    if (!username || !password || !name || !otp) {
        return res.json({ success: false, message: "All fields are required." });
    }

    const storedOTP = req.session.otp;

    if (otp !== storedOTP) {
        return res.json({ success: false, message: "Invalid OTP. Please try again." });
    }

    delete req.session.otp;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const client = await pool.connect();

        try {
            await client.query(
                'INSERT INTO users (username, password, name, email) VALUES ($1, $2, $3, $4)',
                [username, hashedPassword, name, id]
            );

            res.json({ success: true, message: "Signup successful!" });
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error during signup:', error);
        res.json({ success: false, message: "Internal server error during signup." });
    }
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required." });
    }

    try {
        const otp = generateOTP();

        const client = await pool.connect();
        try {
            await client.query('INSERT INTO password_resets (email, otp, created_at) VALUES ($1, $2, NOW()) ON CONFLICT (email) DO UPDATE SET otp = $2, created_at = NOW()', [email, otp]);

            const mailOptions = {
                from: 'a@3pmmsm.onmicrosoft.com',
                to: email,
                subject: 'Password Reset OTP',
                text: `Your OTP for password reset is: ${otp}`,
            };

            try {
                await transporter.sendMail(mailOptions);
                req.session.forgotEmail = email;
                req.session.forgotOTP = otp;
                res.json({ success: true, message: "OTP sent to your email." });
            } catch (emailError) {
                console.error('Error sending OTP:', emailError);
                res.status(500).json({ success: false, message: "Failed to send OTP. Please try again." });
            }
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error in /forgot-password:', error);
        res.status(500).json({ success: false, message: "Internal server error during password reset request." });
    }
});

app.post('/reset-password', async (req, res) => {
    const { otp, newPassword } = req.body;

    if (!otp || !newPassword) {
        return res.status(400).json({ success: false, message: "OTP and new password are required." });
    }

    const storedOTP = req.session.forgotOTP;
    const email = req.session.forgotEmail;

    if (otp !== storedOTP) {
        return res.status(400).json({ success: false, message: "Invalid OTP." });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const client = await pool.connect();

        try {
            await client.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
            await client.query('DELETE FROM password_resets WHERE email = $1', [email]);

            res.json({ success: true, message: "Password reset successful!" });
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error in /reset-password:', error);
        res.status(500).json({ success: false, message: "Internal server error during password reset." });
    }
});

function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.redirect('/login');
}

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
