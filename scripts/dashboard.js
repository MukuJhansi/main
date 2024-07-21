// /logged/dashboard.js
console.log('working')
document.addEventListener('DOMContentLoaded', function () {
    // Add an event listener to the signout link
    document.getElementById('signout').addEventListener('click', function (event) {
        event.preventDefault();

        // Make an AJAX request to the server to sign out
        fetch('/signout')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    alert("Signout successful!");
                    // Redirect to login page after successful signout
                    window.location.href = "/login";
                } else {
                    alert("Failed to signout. Please try again.");
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert("An error occurred. Please try again later.");
            });
    });

    // Comment out the following code to prevent the 404 error
    /*
    fetch('/some-endpoint')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.text();  // Use text() instead of json()
        })
        .then(data => {
            // Handle the HTML content or perform other actions
            document.getElementById('someElementId').innerHTML = data;
        })
        .catch(error => {
            console.error('Error:', error);
            alert("An error occurred. Please try again later.");
        });
    */
});
