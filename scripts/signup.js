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
                alert("Signup successful!");
                // Optionally redirect to login page or dashboard
                window.location.href = "/login";  // Redirect to the login page
            } else {
                alert(`Failed to signup. ${data.message}`);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert("An error occurred. Please try again later.");
        });
    }

    // Function to resend OTP
    function resendOTP() {
        // Reset the OTP field
        document.getElementById("otp").value = "";

        // Call the function to generate OTP and show the OTP field
        generateOTPAndShowField();
    }

    // Attach event listeners to buttons
    document.getElementById("generateOTPButton").addEventListener("click", generateOTPAndShowField);
    document.getElementById("verifyOTPButton").addEventListener("click", verifyOTP);
    document.getElementById("resendOTPButton").addEventListener("click", resendOTP);
});
