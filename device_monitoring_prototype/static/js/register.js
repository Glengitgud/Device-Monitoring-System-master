document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('registerForm');
    if (!form) return;

    const passwordInput = document.getElementById('password');
    const confirmInput = document.getElementById('confirm_password');

    form.addEventListener('submit', event => {
        const password = passwordInput.value;
        const characters = Array.from(password);

        if (characters.length < 8 || characters.length > 16) {
            event.preventDefault();
            alert('Password must be 8-16 characters long.');
            passwordInput.focus();
            return;
        }

        if (!characters.some(character => /\p{Lu}/u.test(character))) {
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
