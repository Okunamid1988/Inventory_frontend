// Example for validating passwords match during signup
document.getElementById("signup-form").addEventListener("submit", function(event) {
    var password = document.getElementById("password").value;
    var confirmPassword = document.getElementById("confirm_password").value;

    if (password !== confirmPassword) {
        alert("Passwords do not match!");
        event.preventDefault();  // Prevent form submission
    }
});
