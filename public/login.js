
const params = new URLSearchParams(window.location.search);
const error = document.getElementById("error");

if (params.get("error") === "authorization_denied") {
  error.textContent = "Sign-in was cancelled. You can try again.";
  error.hidden = false;
}
