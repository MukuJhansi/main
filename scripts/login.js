function attemptLogin() {
    let email = document.getElementById("username").value; // Ensure field ID matches
    let password = document.getElementById("password").value;

    // Make an AJAX request to the server
    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }), // Ensure keys match server expectations
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            alert("Login successful!");
            window.location.href = "/dashboard"; // Redirect to the /dashboard route
        } else {
            alert("Invalid username or password. Please try again.");
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert("An error occurred. Please try again later.");
    });
}
