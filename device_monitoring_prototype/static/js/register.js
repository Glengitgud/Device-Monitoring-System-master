document.addEventListener('DOMContentLoaded', () => {
    const successMessage = document.querySelector('[data-registration-success]');
    if (successMessage) {
        alert(successMessage.textContent.trim());
    }

    const form = document.getElementById('registerForm');
    if (!form) return;

    const passwordInput = document.getElementById('password');
    const confirmInput = document.getElementById('confirm_password');

    form.addEventListener('submit', event => {
        const password = passwordInput.value;
        const characters = Array.from(password);

        if (characters.length < 8) {
            event.preventDefault();
            alert('Password must be at least 8 characters long.');
            passwordInput.focus();
            return;
        }

        if (characters.length > 16) {
            event.preventDefault();
            alert('Password must be no more than 16 characters long.');
            passwordInput.focus();
            return;
        }

        if (!characters.some(character => /[A-Z]/.test(character))) {
            event.preventDefault();
            alert('Password must include at least one capital letter.');
            passwordInput.focus();
            return;
        }

        if (!characters.some(character =>
            !/[\p{L}\p{N}]/u.test(character) && !/\s/u.test(character)
        )) {
            event.preventDefault();
            alert('Password must include at least one special character.');
            passwordInput.focus();
            return;
        }

        if (password !== confirmInput.value) {
            event.preventDefault();
            alert('Passwords do not match.');
            confirmInput.focus();
            return;
        }

        if (!form.checkValidity()) {
            event.preventDefault();
            form.reportValidity();
        }
    });
});
