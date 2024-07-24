document.addEventListener('DOMContentLoaded', function () {
    // Function to generate OTP and show OTP field
    function generateOTPAndShowField() {
        let name = document.getElementById("name").value;
        let id = document.getElementById("id").value;
        let mobile = document.getElementById("mobile").value;
        let password = document.getElementById("password").value;

        // Disable the "Generate OTP & Show OTP Field" button after the first click
        document.getElementById("generateOTPButton").disabled = true;

        // Make an AJAX request to generate OTP
        fetch('/generate-otp', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ name, id, mobile, password }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Display OTP field or handle it as needed
                document.getElementById("otpContainer").style.display = "block";
                alert("OTP generated successfully!");
            } else {
                alert(`Failed to generate OTP. ${data.message}`);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert("An error occurred while generating OTP. Please try again later.");
        });
    }

    // Function to handle OTP verification
    function verifyOTP() {
        let otp = document.getElementById("otp").value;

        // Make an AJAX request to verify OTP
        fetch('/verify-otp', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ otp }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Enable the Signup button and show success message
                document.getElementById("signupButton").style.display = "block";
                alert("OTP verified successfully!");
            } else {
                alert(`Failed to verify OTP. ${data.message}`);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert("An error occurred while verifying OTP. Please try again later.");
        });
    }

    // Function to attempt signup
    function attemptSignup() {
        let username = document.getElementById("name").value;
        let password = document.getElementById("password").value;
        let name = document.getElementById("name").value;
        let id = document.getElementById("id").value;
        let otp = document.getElementById("otp").value;

        // Make an AJAX request to signup
        fetch('/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password, name, id, otp }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert("Signup successful!");
                window.location.href = "/login";  // Redirect to the login page
            } else {
                alert(`Failed to signup. ${data.message}`);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert("An error occurred while signing up. Please try again later.");
        });
    }

    // Attach event listeners to buttons
    document.getElementById("generateOTPButton").addEventListener("click", generateOTPAndShowField);
    document.getElementById("verifyOTPButton").addEventListener("click", verifyOTP);
    document.getElementById("resendOTPButton").addEventListener("click", generateOTPAndShowField);  // Fixed resend OTP function
    document.getElementById("signupButton").addEventListener("click", attemptSignup);  // Added Signup button event listener
});
