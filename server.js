const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const session = require('cookie-session');
const path = require('path');
const nodemailer = require('nodemailer');
const { time, timeLog, timeEnd } = require('console');

const app = express();
const PORT = 443;

app.use(express.static('public'));
app.use('/styles', express.static(path.join(__dirname, 'styles')));
app.use('/pic/', express.static(path.join(__dirname, 'pic')));
app.use('/video/', express.static(path.join(__dirname, 'video')));
app.use('/', express.static(path.join(__dirname, 'home')));
app.use('/html/', express.static(path.join(__dirname, 'html')))
app.use('/script/', express.static(path.join(__dirname, 'scripts')))

app.use(bodyParser.json());
app.use(cors());
const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: '12345',
    database: 'userid',
};

app.use(session({
    secret: 'GRP"mFa`wL9?D%X]etH>k#',
    resave: true,
    saveUninitialized: true,
    cookie: {
        maxAge: 7 * 24 * 60 * 60 * 1000,
    },
}));

// Serve the home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'index.html'));
});

// Serve the Rickroll page
app.get('/bamlaJiSmash', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'Rickroll.html'));
});

// Serve the devlopment page
app.get('/devlopment', (req, res) => {
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
        minVersion: 'TLSv1', // Adjust based on server requirements
        maxVersion: 'TLSv1.2', // Adjust based on server requirements
    },
    debug: true
});

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000);
}

// ...

// Function to generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000);
}

app.post('/generate-otp', (req, res) => {
    try {
        const { name, id, mobile, password } = req.body;

        if (!name || !id || !mobile || !password) {
            return res.status(400).json({ success: false, message: "All fields are required." });
        }

        const otp = generateOTP();

        req.session.otp = otp;

        const mailOptions = {
            from: 'a@3pmmsm.onmicrosoft.com',
            to: id,
            subject: 'Verification OTP',
            text: `Your OTP for registration is: ${otp}`,
        };

        transporter.sendMail(mailOptions)
            .then(() => res.json({ success: true, otp }))  // Include OTP in the response
            .catch((error) => {
                console.error('Error sending OTP:', error);
                res.json({ success: false, message: "Failed to send OTP. Please try again." });
            });
    } catch (error) {
        console.error('Error in /generate-otp:', error);
        return res.status(500).json({ success: false, message: "Internal server error during OTP generation." });
    }
});

app.post('/verify-otp', (req, res) => {
    try {
        const { otp } = req.body;
        const storedOTP = req.session.otp;

        if (!otp || storedOTP !== parseInt(otp)) {  // Parse the OTP to an integer for strict comparison
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

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Username and password are required." });
    }

    const connection = await mysql.createConnection(dbConfig);

    try {
        const [rows] = await connection.execute('SELECT id, password FROM users WHERE username = ?', [username]);

        if (rows.length === 0) {
            return res.json({ success: false, message: "Invalid username or password." });
        }

        const hashedPassword = rows[0].password;
        const passwordMatch = await bcrypt.compare(password, hashedPassword);

        if (passwordMatch) {
            req.session.userId = rows[0].id;
            return res.json({ success: true });
        } else {
            return res.json({ success: false, message: "Invalid username or password." });
        }
    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ success: false, message: "Internal server error." });
    } finally {
        await connection.end();
    }
});

// Handle signup request
app.post('/signup', async (req, res) => {
    const { username, password, name, id, otp } = req.body;

    if (!username || !password || !name || !id || !otp) {
        return res.json({ success: false, message: "All fields are required." });
    }

    // Retrieve the stored OTP from session
    const storedOTP = req.session.otp;

    // Check if the OTP provided by the user matches the stored OTP
    if (otp !== storedOTP) {
        return res.json({ success: false, message: "Invalid OTP. Please try again." });
    }

    // Clear the OTP from session after successful verification
    delete req.session.otp;

    const mailOptions = {
        from: 'a@3pmmsm.onmicrosoft.com',
        to: id,
        subject: 'Verification OTP',
        text: `Your OTP for registration is: ${storedOTP}`,
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.response);

        const hashedPassword = await bcrypt.hash(password, 10);

        const connection = await mysql.createConnection(dbConfig);

        try {
            const [result] = await connection.execute('INSERT INTO users (username, password, name, id, otp) VALUES (?, ?, ?, ?, ?)', [username, hashedPassword, name, id, storedOTP]);

            if (result.insertId) {
                res.header('X-Content-Type-Options', 'nosniff');
                return res.json({ success: true });
            } else {
                return res.json({ success: false, message: "Failed to signup. Please try again." });
            }
        } catch (error) {
            console.error('Error:', error);
            return res.status(500).json({ success: false, message: "Internal server error." });
        } finally {
            await connection.end();
        }
    } catch (error) {
        console.error('Error sending OTP:', error);
        return res.json({ success: false, message: "Failed to send OTP. Please try again." });
    }
});

app.post('/signout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Session destroy error:', err);
            return res.status(500).json({ success: false, message: "Failed to sign out. Please try again." });
        }
        res.json({ success: true, message: "Sign out successful." });
    });
});

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'logged', 'dashboard.html'));
});

app.get('/payment', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'logged', 'payment.html'));
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