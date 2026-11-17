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

    const verificationDialog = document.getElementById('registrationVerificationDialog');
    const dialogStatus = document.getElementById('registrationDialogStatus');
    const emailStage = document.getElementById('emailVerificationStage');
    const authenticatorStage = document.getElementById('authenticatorVerificationStage');
    const csrfInput = form?.querySelector('[name="csrf_token"]');

    function setDialogStatus(message, state = 'info') {
        dialogStatus.textContent = message;
        dialogStatus.dataset.state = state;
    }

    async function postRegistration(url, data) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'X-CSRF-Token': csrfInput.value },
            body: data,
        });
        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error || 'Verification could not be completed.');
        }
        return result;
    }

    async function withLoading(button, message, operation) {
        const label = button?.querySelector('.button-label');
        const spinner = button?.querySelector('.button-spinner');
        if (button) {
            button.disabled = true;
            button.setAttribute('aria-busy', 'true');
            if (label) label.textContent = message;
            if (spinner) spinner.hidden = false;
        }
        try {
            return await operation();
        } finally {
            if (button) {
                button.disabled = false;
                button.removeAttribute('aria-busy');
                if (label) label.textContent = label.dataset.defaultLabel;
                if (spinner) spinner.hidden = true;
            }
        }
    }

    form?.addEventListener('submit', async event => {
        event.preventDefault();
        const emailIsValid = validateEmail(registerEmail, registerEmailMessage);
        if (!emailIsValid) {
            registerEmail.focus();
            return;
        }
        const password = passwordInput.value;
        const characters = Array.from(password);

        if (characters.length < 8) {
            alert('Password must be at least 8 characters long.');
            passwordInput.focus();
            return;
        }

        if (characters.length > 16) {
            alert('Password must be no more than 16 characters long.');
            passwordInput.focus();
            return;
        }

        if (!characters.some(character => /[A-Z]/.test(character))) {
            alert('Password must include at least one capital letter.');
            passwordInput.focus();
            return;
        }

        if (!characters.some(character =>
            !/[\p{L}\p{N}]/u.test(character) && !/\s/u.test(character)
        )) {
            alert('Password must include at least one special character.');
            passwordInput.focus();
            return;
        }

        if (password !== confirmInput.value) {
            alert('Passwords do not match.');
            confirmInput.focus();
            return;
        }

        if (!form.checkValidity()) {
            form.reportValidity();
            return;
        }

        verificationDialog.showModal();
        setDialogStatus('Email verification is required. Sending your code...');
        try {
            const button = form.querySelector('button[type="submit"]');
            const result = await withLoading(button, 'Sending code...', () =>
                postRegistration('/api/registration/start', new FormData(form))
            );
            setDialogStatus(result.message, 'success');
            document.getElementById('emailVerificationCode').focus();
        } catch (error) {
            setDialogStatus(error.message, 'error');
        }
    });

    document.getElementById('emailVerificationForm')?.addEventListener('submit', async event => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        try {
            const button = event.currentTarget.querySelector('button[type="submit"]');
            const result = await withLoading(button, 'Verifying...', () =>
                postRegistration('/api/registration/verify-email', data)
            );
            document.getElementById('authenticatorQrCode').src = result.qr_code;
            emailStage.hidden = true;
            authenticatorStage.hidden = false;
            document.getElementById('registrationDialogTitle').textContent =
                'Set up Google Authenticator';
            setDialogStatus(result.message, 'success');
            document.getElementById('authenticatorVerificationCode').focus();
        } catch (error) {
            setDialogStatus(error.message, 'error');
        }
    });

    document.getElementById('resendVerificationCode')?.addEventListener('click', async () => {
        const button = document.getElementById('resendVerificationCode');
        try {
            const result = await withLoading(button, 'Sending...', () =>
                postRegistration('/api/registration/resend-code', new FormData())
            );
            setDialogStatus(result.message, 'success');
        } catch (error) {
            setDialogStatus(error.message, 'error');
        }
    });

    document.getElementById('authenticatorVerificationForm')?.addEventListener(
        'submit',
        async event => {
            event.preventDefault();
            const authenticatorForm = event.currentTarget;
            try {
                const button = authenticatorForm.querySelector('button[type="submit"]');
                const result = await withLoading(button, 'Creating account...', () =>
                    postRegistration(
                        '/api/registration/verify-authenticator',
                        new FormData(authenticatorForm)
                    )
                );
                setDialogStatus(result.message, 'success');
                document.getElementById('registrationDialogTitle').textContent = 'Account created';
                authenticatorForm.hidden = true;
                window.setTimeout(() => {
                    window.location.assign(result.redirect_url);
                }, 1200);
            } catch (error) {
                setDialogStatus(error.message, 'error');
            }
        }
    );

    document.getElementById('closeRegistrationDialog')?.addEventListener('click', async () => {
        const cancelButton = document.getElementById('closeRegistrationDialog');
        cancelButton.disabled = true;
        try {
            await postRegistration('/api/registration/cancel', new FormData());
            verificationDialog.close();
            form.reset();
            document.getElementById('authenticatorQrCode').removeAttribute('src');
            document.getElementById('emailVerificationCode').value = '';
            document.getElementById('authenticatorVerificationCode').value = '';
            document.getElementById('registrationDialogTitle').textContent = 'Verify your email';
            emailStage.hidden = false;
            authenticatorStage.hidden = true;
            setDialogStatus(
                'Email verification is required before account creation.',
                'info'
            );
        } catch (error) {
            setDialogStatus(error.message, 'error');
        } finally {
            cancelButton.disabled = false;
        }
    });

    verificationDialog?.addEventListener('cancel', event => event.preventDefault());

    loginForm?.addEventListener('submit', event => {
        if (!validateEmail(loginIdentifier, loginEmailMessage, true)) {
            event.preventDefault();
            loginIdentifier.focus();
        }
    });
});
