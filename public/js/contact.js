// Takes content of fields in form
const subject = document.getElementById("subject");
const email = document.getElementById("email");
const text = document.getElementById("text");

function popup() {
    // Creates alert if email address is invalid
    if (!checkValidEmail()) {
        alert("Invalid e-mail address provided.");
    }
    // Sends all contact fields in email
    else if (subject.value !== "" && email.value !== "" && text.value !== "") {
        // Sends alert for proper contact form submission
        alert("Form submitted successfully.");
    }
}

// Checks for proper email ending for validity
function checkValidEmail() {
    const email = document.getElementById('email').value;
    if (
        email.includes("@gmail.com") ||
        email.includes("@yahoo.com") ||
        email.includes("@outlook.com") ||
        email.includes("@icloud.com")
    ) {
        return true;
    }
    return false;
}

// Add event listeners when the DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
    const contactForm = document.getElementById('contact-form');
    if (contactForm) {
        contactForm.addEventListener('submit', function (e) {
            if (!checkValidEmail()) {
                e.preventDefault();
                alert("Invalid e-mail address provided.");
            }
        });
    }
}); 