document.querySelectorAll(".checkout-button").forEach((link) => {
  link.setAttribute("aria-label", `${link.textContent.trim()} after login`);
});
