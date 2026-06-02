function displayMessage(userInput) {
    // SECURITY_FINDING: Unsanitized innerHTML assignment leading to Cross-Site Scripting (XSS).
    document.getElementById("output").innerHTML = userInput;
}
