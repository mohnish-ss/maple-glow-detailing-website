document.addEventListener('DOMContentLoaded', function () {
    const loginForm = document.querySelector('.login-form form');

    if (loginForm) {
        loginForm.addEventListener('submit', async function (e) {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            if (!username || !password) {
                alert('Please fill in all fields');
                return;
            }

            try {
                const response = await fetch('/check-login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();

                if (data.success) {
                    window.location.href = data.redirect;
                } else {
                    // Show error message
                    const errorLabel = document.querySelector('.error-label') || document.createElement('label');
                    errorLabel.className = 'error-label';
                    errorLabel.style.color = 'red';
                    errorLabel.style.opacity = '1';
                    errorLabel.textContent = data.message || 'Invalid username or password';

                    if (!document.querySelector('.error-label')) {
                        const form = document.querySelector('.login-form form');
                        form.insertBefore(errorLabel, form.querySelector('.form-hyperlink'));
                    }
                }
            } catch (error) {
                console.error('Login error:', error);
                alert('An error occurred during login. Please try again.');
            }
        });
    }
}); 