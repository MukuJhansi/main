document.addEventListener('DOMContentLoaded', function () {
    async function resetPassword() {
        const token = document.getElementById('token').value;
        const newPassword = document.getElementById('new-password').value;

        if (!newPassword) {
            alert("Please enter a new password.");
            return;
        }

        try {
            const response = await fetch('/reset-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ token, newPassword }),
            });

            const result = await response.json();
            if (result.success) {
                alert(result.message);
                window.location.href = '/login';  // Redirect to login page after successful reset
            } else {
                alert(result.message);
            }
        } catch (error) {
            console.error('Error:', error);
            alert("An error occurred while resetting your password. Please try again later.");
        }
    }

    document.getElementById('resetButton').addEventListener('click', resetPassword);
});
