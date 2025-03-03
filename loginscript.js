document.getElementById("loginForm").addEventListener("submit", function(event) {
    event.preventDefault();
    const role = document.getElementById("role").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    
    if (email === "user@example.com" && password === "password123") {
        alert("Login successful as " + role + "!");
    } else {
        document.getElementById("errorMessage").classList.remove("hidden");
    }
});