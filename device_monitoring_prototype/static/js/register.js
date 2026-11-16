document.addEventListener('DOMContentLoaded', () => {
    const successMessage = document.querySelector('[data-registration-success]');
    if (successMessage) {
        alert(successMessage.textContent.trim());
    }

    const form = document.getElementById('registerForm');
    const loginForm = document.getElementById('loginForm');
    const emailPattern = /^[A-Za-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+\/=?^_`{|}~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

    function validateEmail(input, message, allowUsername = false) {
        const value = input.value.trim();
        if (allowUsername && value && !value.includes('@')) {
            input.setCustomValidity('');
            message.textContent = 'Username sign-in is also available.';
            message.className = 'validation-message';
            return true;
        }
        if (!value) {
            input.setCustomValidity('');
            message.textContent = allowUsername ? 'Enter your username or email address.' : 'Enter your email address.';
            message.className = 'validation-message';
            return allowUsername;
        }
        const valid = emailPattern.test(value);
        input.setCustomValidity(valid ? '' : 'Enter a valid email address.');
        message.textContent = valid ? 'Valid email format.' : 'Invalid email format.';
        message.className = `validation-message ${valid ? 'is-valid' : 'is-invalid'}`;
        return valid;
    }

    const registerEmail = document.getElementById('email');
    const registerEmailMessage = document.getElementById('registerEmailValidation');
    if (registerEmail && registerEmailMessage) {
        registerEmail.addEventListener('input', () =>
            validateEmail(registerEmail, registerEmailMessage)
        );
    }

    const loginIdentifier = document.getElementById('username');
    const loginEmailMessage = document.getElementById('loginEmailValidation');
    if (loginIdentifier && loginEmailMessage) {
        loginIdentifier.addEventListener('input', () =>
            validateEmail(loginIdentifier, loginEmailMessage, true)
        );
    }

    const passwordInput = document.getElementById('password');
    const confirmInput = document.getElementById('confirm_password');

    form?.addEventListener('submit', event => {
        const emailIsValid = validateEmail(registerEmail, registerEmailMessage);
        if (!emailIsValid) {
            event.preventDefault();
            registerEmail.focus();
            return;
        }
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

    loginForm?.addEventListener('submit', event => {
        if (!validateEmail(loginIdentifier, loginEmailMessage, true)) {
            event.preventDefault();
            loginIdentifier.focus();
        }
    });
});
