document.addEventListener('DOMContentLoaded', function () {
    // Function to generate OTP and show OTP field
    function generateOTPAndShowField() {
        const name = document.getElementById("name").value;
        const id = document.getElementById("id").value;
        const mobile = document.getElementById("mobile").value;
        const password = document.getElementById("password").value;

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
                document.getElementById("signupButton").style.display = "inline";  // Show signup button
                alert("OTP generated successfully!");
            } else {
                alert(`Failed to generate OTP: ${data.message}`);
                document.getElementById("generateOTPButton").disabled = false;  // Re-enable button
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert("An error occurred while generating OTP. Please try again later.");
            document.getElementById("generateOTPButton").disabled = false;  // Re-enable button
        });
    }

    // Function to handle OTP verification
    function verifyOTP() {
        const otp = document.getElementById("otp").value;

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
                // Display signup button and allow user to proceed
                document.getElementById("signupButton").style.display = "inline";
                alert("OTP verified successfully! You can now sign up.");
            } else {
                alert(`Failed to verify OTP: ${data.message}`);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert("An error occurred while verifying OTP. Please try again later.");
        });
    }

    // Function to resend OTP
    function resendOTP() {
        // Call the function to generate OTP and show the OTP field
        generateOTPAndShowField();
    }

    // Function to handle signup submission
    function attemptSignup() {
        const username = document.getElementById("name").value;
        const password = document.getElementById("password").value;
        const name = document.getElementById("name").value;
        const id = document.getElementById("id").value;
        const otp = document.getElementById("otp").value;

        // Make an AJAX request to sign up
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
                alert("Signup successful! Redirecting to login.");
                window.location.href = "/login";  // Redirect to login page
            } else {
                alert(`Failed to sign up: ${data.message}`);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert("An error occurred during signup. Please try again later.");
        });
    }

    // Attach event listeners to buttons
    document.getElementById("generateOTPButton").addEventListener("click", generateOTPAndShowField);
    document.getElementById("verifyOTPButton").addEventListener("click", verifyOTP);
    document.getElementById("resendOTPButton").addEventListener("click", resendOTP);
    document.getElementById("signupButton").addEventListener("click", attemptSignup);
});
