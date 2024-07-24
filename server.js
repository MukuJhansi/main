const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const path = require('path');
const nodemailer = require('nodemailer');

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

// Session store configuration
app.use(session({
    store: new pgSession({
        pool, // Connection pool
        tableName: 'session' // Use another table-name than the default "session" one
    }),
    secret: 'GRP"mFa`wL9?D%X]etH>k#',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 1 week
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

        const otp = generateOTP();
        req.session.otp = otp;

        console.log('Generated OTP:', otp);  // Debug log
        console.log('Stored OTP in session:', req.session.otp);  // Debug log

        const mailOptions = {
            from: 'a@3pmmsm.onmicrosoft.com',
            to: id,
            subject: 'Verification OTP',
            text: `Your OTP for registration is: ${otp}`,
        };

        try {
            await transporter.sendMail(mailOptions);
            res.json({ success: true, otp }); // Include OTP in the response
        } catch (emailError) {
            console.error('Error sending OTP:', emailError);
            res.status(500).json({ success: false, message: "Failed to send OTP. Please try again." });
        }
    } catch (error) {
        console.error('Error in /generate-otp:', error);
        return res.status(500).json({ success: false, message: "Internal server error during OTP generation." });
    }
});

// Handle OTP verification
app.post('/verify-otp', (req, res) => {
    try {
        const { otp } = req.body;
        const storedOTP = req.session.otp;

        console.log('Received OTP:', otp); // Log received OTP
        console.log('Stored OTP:', storedOTP); // Log stored OTP for debugging

        if (!otp || storedOTP !== otp) {
            return res.status(400).json({ success: false, message: "Invalid OTP. Please try again." });
        }

        // Clear the OTP from session after successful verification
        delete req.session.otp;

        return res.json({ success: true });
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

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
