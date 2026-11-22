document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('registerForm');
    const loginForm = document.getElementById('loginForm');
    const emailPattern = /^[A-Za-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+\/=?^_`{|}~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
    const usernamePattern = /^[A-Za-z0-9_.-]{3,64}$/;

    document.querySelectorAll('[data-password-toggle]').forEach(toggle => {
        const input = document.getElementById(toggle.dataset.passwordToggle);
        const icon = toggle.querySelector('i');
        if (!input || !icon) return;
        toggle.addEventListener('click', () => {
            const showPassword = input.type === 'password';
            input.type = showPassword ? 'text' : 'password';
            icon.className = showPassword ? 'bi bi-eye-slash' : 'bi bi-eye';
            toggle.setAttribute('aria-pressed', String(showPassword));
            toggle.setAttribute(
                'aria-label',
                `${showPassword ? 'Hide' : 'Show'} ${
                    input.id === 'confirm_password' ? 'confirmation password' : 'password'
                }`
            );
        });
    });

    function usernameError(value) {
        if (!usernamePattern.test(value)) {
            return 'Use 3-64 letters, numbers, dots, dashes, or underscores.';
        }
        if (value.toLowerCase() === 'admin') {
            return 'The username "admin" is reserved.';
        }
        return '';
    }

    function setFeedback(input, message, text, state = '') {
        if (!input || !message) return;
        message.textContent = text;
        message.className = `validation-message${state ? ` ${state}` : ''}`;
        if (state === 'is-invalid') {
            input.setAttribute('aria-invalid', 'true');
        } else {
            input.removeAttribute('aria-invalid');
        }
    }

    function validateEmail(input, message, allowUsername = false, showEmpty = false) {
        if (!input || !message) return true;
        const value = input.value.trim();
        if (!value) {
            setFeedback(
                input,
                message,
                allowUsername ? 'Enter your username or email address.' : 'Enter your email address.',
                showEmpty ? 'is-invalid' : ''
            );
            return false;
        }
        if (allowUsername && !value.includes('@')) {
            const validUsername = usernamePattern.test(value);
            setFeedback(
                input,
                message,
                validUsername
                    ? 'Valid username format.'
                    : 'Use 3-64 letters, numbers, dots, dashes, or underscores.',
                validUsername ? 'is-valid' : 'is-invalid'
            );
            return validUsername;
        }
        const valid = emailPattern.test(value);
        setFeedback(
            input,
            message,
            valid ? 'Valid email format.' : 'Enter a valid email address.',
            valid ? 'is-valid' : 'is-invalid'
        );
        return valid;
    }

    const loginIdentifier = document.getElementById('username');
    const loginEmailMessage = document.getElementById('loginEmailValidation');
    loginIdentifier?.addEventListener('input', () =>
        validateEmail(loginIdentifier, loginEmailMessage, true)
    );
    loginForm?.addEventListener('submit', event => {
        if (event.submitter?.name === 'back_to_login') return;
        const validIdentifier = validateEmail(
            loginIdentifier,
            loginEmailMessage,
            true,
            true
        );
        if (!validIdentifier) {
            event.preventDefault();
            loginIdentifier.focus();
        }
    });
    const loginTotp = document.getElementById('totp_code');
    const loginTotpMessage = document.getElementById('loginTotpValidation');
    if (loginTotp && loginTotpMessage) {
        const validateTotp = (showEmpty = false) => {
            const value = loginTotp.value.trim();
            const valid = /^[0-9]{6}$/.test(value);
            setFeedback(
                loginTotp,
                loginTotpMessage,
                !value
                    ? 'Enter the current 6-digit code from your authenticator app.'
                    : valid
                        ? '6-digit code entered.'
                        : 'Enter a 6-digit authenticator code.',
                !value ? showEmpty ? 'is-invalid' : '' : valid ? 'is-valid' : 'is-invalid'
            );
            return valid;
        };
        loginTotp.addEventListener('input', () => validateTotp());
        loginForm.addEventListener('submit', event => {
            if (event.submitter?.name === 'back_to_login') return;
            if (!validateTotp(true)) {
                event.preventDefault();
                loginTotp.focus();
            }
        });
    }

    if (!form) return;

    const fullName = document.getElementById('full_name');
    const email = document.getElementById('email');
    const emailMessage = document.getElementById('registerEmailValidation');
    const username = document.getElementById('username');
    const usernameMessage = document.getElementById('registerUsernameValidation');
    const password = document.getElementById('password');
    const confirmPassword = document.getElementById('confirm_password');
    const confirmationMessage = document.getElementById('passwordMatchValidation');
    const verificationDialog = document.getElementById('registrationVerificationDialog');
    const dialogStatus = document.getElementById('registrationDialogStatus');
    const emailStage = document.getElementById('emailVerificationStage');
    const authenticatorStage = document.getElementById('authenticatorVerificationStage');
    const csrfInput = form.querySelector('[name="csrf_token"]');
    const resendButton = document.getElementById('resendVerificationCode');
    const resendCountdown = document.getElementById('resendCodeCountdown');
    const registrationFormStatus = document.getElementById('registrationFormStatus');
    const profileStorageKey = 'devmonitor.registration.profile.v1';
    let activeRegistration = null;
    let registrationStartPending = false;
    let resendTimer = null;

    function setRegistrationFormStatus(message = '') {
        registrationFormStatus.textContent = message;
        registrationFormStatus.hidden = !message;
    }

    function setDialogStatus(message, state = 'info') {
        dialogStatus.textContent = message;
        dialogStatus.dataset.state = state;
    }

    function saveProfile() {
        try {
            sessionStorage.setItem(profileStorageKey, JSON.stringify({
                full_name: fullName.value,
                email: email.value,
                username: username.value,
            }));
        } catch (error) {
            console.error('Registration profile could not be saved in this tab.', error);
        }
    }

    function clearSavedProfile() {
        try {
            sessionStorage.removeItem(profileStorageKey);
        } catch (error) {
            console.error('Saved registration profile could not be removed.', error);
        }
    }

    function restoreProfile() {
        let stored;
        try {
            stored = sessionStorage.getItem(profileStorageKey);
        } catch (error) {
            console.error('Registration profile could not be restored in this tab.', error);
            return;
        }
        if (!stored) return;
        let profile;
        try {
            profile = JSON.parse(stored);
        } catch (error) {
            console.error('Saved registration profile is invalid.', error);
            clearSavedProfile();
            return;
        }
        if (!profile || typeof profile !== 'object') {
            clearSavedProfile();
            return;
        }
        for (const [field, input] of Object.entries({
            full_name: fullName,
            email,
            username,
        })) {
            if (typeof profile[field] === 'string') {
                input.value = profile[field];
            }
        }
    }

    function updateProfileValidation(showEmpty = false) {
        validateEmail(email, emailMessage, false, showEmpty);

        const usernameValue = username.value.trim();
        const usernameProblem = usernameError(usernameValue);
        setFeedback(
            username,
            usernameMessage,
            !usernameValue && showEmpty
                ? 'Enter a username.'
                : usernameValue
                    ? usernameProblem || 'Valid username format.'
                    : 'Use 3-64 letters, numbers, dots, dashes, or underscores.',
            !usernameValue
                ? showEmpty ? 'is-invalid' : ''
                : usernameProblem ? 'is-invalid' : 'is-valid'
        );

        const nameValue = fullName.value.trim();
        setFeedback(
            fullName,
            document.getElementById('fullNameValidation'),
            nameValue ? 'Full name entered.' : 'Enter your full name.',
            nameValue ? 'is-valid' : showEmpty ? 'is-invalid' : ''
        );
    }

    function updatePasswordValidation(showEmpty = false) {
        const characters = Array.from(password.value);
        const rules = {
            length: characters.length >= 8 && characters.length <= 16,
            uppercase: /[A-Z]/.test(password.value),
            special: characters.some(character =>
                !/[\p{L}\p{N}]/u.test(character) && !/\s/u.test(character)
            ),
        };
        for (const [rule, passes] of Object.entries(rules)) {
            const item = document.querySelector(`[data-password-rule="${rule}"]`);
            item.classList.toggle('is-valid', passes);
            item.classList.toggle('is-invalid', password.value.length > 0 && !passes);
        }
        const message = document.getElementById('registerPasswordStrength');
        const validPassword = Object.values(rules).every(Boolean);
        if (password.value && !validPassword || showEmpty && !password.value) {
            password.setAttribute('aria-invalid', 'true');
        } else {
            password.removeAttribute('aria-invalid');
        }
        if (message) {
            message.textContent = password.value
                ? validPassword
                    ? 'Password meets all requirements.'
                    : 'Password does not meet all requirements.'
                : 'Enter a password to see its requirements.';
            message.className = `password-strength${password.value
                ? validPassword ? ' is-strong' : ' is-weak'
                : ''}`;
        }

        const matches = confirmPassword.value === password.value
            && confirmPassword.value.length > 0;
        if (confirmPassword.value || showEmpty) {
            confirmPassword.toggleAttribute('aria-invalid', !matches);
        }
        setFeedback(
            confirmPassword,
            confirmationMessage,
            confirmPassword.value
                ? matches ? 'Passwords match.' : 'Passwords do not match.'
                : 'Re-enter your password to confirm it.',
            confirmPassword.value
                ? matches ? 'is-valid' : 'is-invalid'
                : showEmpty ? 'is-invalid' : ''
        );
    }

    for (const input of [fullName, email, username]) {
        input.addEventListener('input', () => {
            updateProfileValidation();
            saveProfile();
        });
    }
    email.addEventListener('input', () => validateEmail(email, emailMessage));
    username.addEventListener('input', () => {
        const value = username.value.trim();
        const problem = usernameError(value);
        setFeedback(
            username,
            usernameMessage,
            !value
                ? 'Use 3-64 letters, numbers, dots, dashes, or underscores.'
                : problem || 'Valid username format.',
            !value ? '' : problem ? 'is-invalid' : 'is-valid'
        );
    });
    password.addEventListener('input', updatePasswordValidation);
    confirmPassword.addEventListener('input', updatePasswordValidation);

    async function postRegistration(url, data) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'X-CSRF-Token': csrfInput.value },
            body: data,
        });
        const result = await response.json();
        if (!response.ok) {
            const error = new Error(result.error || 'Verification could not be completed.');
            error.restart = Boolean(result.restart);
            throw error;
        }
        return result;
    }

    function resetClosedRegistration(message) {
        activeRegistration = null;
        window.clearInterval(resendTimer);
        emailStage.hidden = true;
        authenticatorStage.hidden = true;
        document.getElementById('authenticatorQrCode').removeAttribute('src');
        document.getElementById('authenticatorVerificationCode').value = '';
        document.getElementById('emailVerificationCode').value = '';
        document.getElementById('registrationDialogTitle').textContent =
            'Start registration again';
        setDialogStatus(
            `${message} Select "Back to sign up", re-enter your password, and submit `
            + 'the form to receive a new code. Remove the old DevMonitor entry from '
            + 'Google Authenticator before scanning the new QR code.',
            'error'
        );
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

    function updateResendCountdown(seconds) {
        window.clearInterval(resendTimer);
        let remaining = Math.max(0, Number(seconds) || 0);
        const renderCountdown = () => {
            resendButton.disabled = remaining > 0;
            resendCountdown.textContent = remaining > 0
                ? `Available in ${remaining} seconds.`
                : 'You can request a new code.';
            if (remaining > 0) remaining -= 1;
            else window.clearInterval(resendTimer);
        };
        renderCountdown();
        if (remaining > 0) resendTimer = window.setInterval(renderCountdown, 1000);
    }

    function showRegistrationState(state, message = '') {
        activeRegistration = state;
        document.getElementById('registrationEmailAddress').textContent = state.email;
        if (state.email_verified) {
            emailStage.hidden = true;
            authenticatorStage.hidden = false;
            document.getElementById('authenticatorQrCode').src = state.qr_code;
            document.getElementById('registrationDialogTitle').textContent =
                'Set up Google Authenticator';
            setDialogStatus(
                message || 'Your email is verified. Complete authenticator setup to continue.',
                'success'
            );
        } else {
            emailStage.hidden = false;
            authenticatorStage.hidden = true;
            document.getElementById('authenticatorQrCode').removeAttribute('src');
            document.getElementById('registrationDialogTitle').textContent = 'Verify your email';
            setDialogStatus(
                message || 'Enter the verification code sent to your email address.',
                'info'
            );
            updateResendCountdown(state.resend_in_seconds);
        }
        if (!verificationDialog.open) verificationDialog.showModal();
    }

    const resumeBanner = document.getElementById('registrationResumeBanner');

    function showResumeBanner() {
        if (!activeRegistration) {
            resumeBanner.hidden = true;
            return;
        }
        document.getElementById('registrationResumeEmail').textContent = activeRegistration.email;
        resumeBanner.hidden = false;
    }

    async function fetchRegistrationStatus() {
        const response = await fetch('/api/registration/status', {
            headers: { Accept: 'application/json' },
            cache: 'no-store',
        });
        if (!response.ok) throw new Error('Registration status could not be restored.');
        return response.json();
    }

    // After a refresh, a closed tab or "Back to sign up", reopen the sign-up that is
    // still in progress on the server: same email code, same authenticator QR code.
    async function resumeRegistrationInProgress() {
        let state;
        try {
            state = await fetchRegistrationStatus();
        } catch (error) {
            console.error(error);
            return;
        }
        if (!state.active) {
            activeRegistration = null;
            showResumeBanner();
            return;
        }
        for (const [field, input] of Object.entries({ full_name: fullName, email, username })) {
            if (!input.value && typeof state[field] === 'string') input.value = state[field];
        }
        showRegistrationState(
            state,
            state.email_verified
                ? 'Welcome back. Your email is already verified. If you already scanned this '
                  + 'QR code, just enter the current code from Google Authenticator.'
                : 'Welcome back. Enter the verification code we sent to your email.'
        );
        resumeBanner.hidden = true;
    }

    document.getElementById('resumeRegistrationBtn').addEventListener('click', () => {
        resumeRegistrationInProgress();
    });

    document.getElementById('startOverRegistrationBtn').addEventListener('click', async event => {
        const button = event.currentTarget;
        button.disabled = true;
        try {
            await postRegistration('/api/registration/cancel', new FormData());
        } catch (error) {
            console.error(error);
        } finally {
            button.disabled = false;
        }
        activeRegistration = null;
        window.clearInterval(resendTimer);
        clearSavedProfile();
        showResumeBanner();
        setRegistrationFormStatus();
        fullName.focus();
    });

    restoreProfile();
    updateProfileValidation();
    updatePasswordValidation();
    resumeRegistrationInProgress();

    form.addEventListener('submit', async event => {
        event.preventDefault();
        if (verificationDialog.open || registrationStartPending) return;
        setRegistrationFormStatus();
        fullName.value = fullName.value.trim();
        email.value = email.value.trim();
        username.value = username.value.trim();
        updateProfileValidation(true);
        updatePasswordValidation(true);
        const emailIsValid = validateEmail(email, emailMessage, false, true);
        const usernameIsValid = Boolean(username.value.trim())
            && !usernameError(username.value.trim());
        const passwordValid = Array.from(password.value).length >= 8
            && Array.from(password.value).length <= 16
            && /[A-Z]/.test(password.value)
            && Array.from(password.value).some(character =>
                !/[\p{L}\p{N}]/u.test(character) && !/\s/u.test(character)
            );
        const passwordsMatch = password.value === confirmPassword.value
            && confirmPassword.value.length > 0;
        if (!fullName.value.trim() || !emailIsValid || !usernameIsValid
            || !passwordValid || !passwordsMatch || !form.checkValidity()) {
            const invalidField = [
                fullName,
                email,
                username,
                password,
                confirmPassword,
            ].find(input => !input.value || input.getAttribute('aria-invalid') === 'true');
            invalidField?.focus();
            return;
        }

        saveProfile();
        document.getElementById('registrationEmailAddress').textContent = email.value.trim();
        registrationStartPending = true;
        try {
            const button = form.querySelector('button[type="submit"]');
            const result = await withLoading(button, 'Sending code...', () =>
                postRegistration('/api/registration/start', new FormData(form))
            );
            const response = await fetch('/api/registration/status', {
                headers: { Accept: 'application/json' },
            });
            if (!response.ok) throw new Error('Registration status could not be restored.');
            const state = await response.json();
            if (!state.active) throw new Error('Registration session expired. Please try again.');
            showRegistrationState(state, result.message);
            setRegistrationFormStatus();
            if (state.email_verified) {
                document.getElementById('authenticatorVerificationCode').focus();
            } else {
                document.getElementById('emailVerificationCode').focus();
            }
        } catch (error) {
            setRegistrationFormStatus(error.message);
        } finally {
            registrationStartPending = false;
        }
    });

    document.getElementById('emailVerificationForm').addEventListener('submit', async event => {
        event.preventDefault();
        const verificationForm = event.currentTarget;
        if (!verificationForm.reportValidity()) return;
        const data = new FormData(verificationForm);
        try {
            const button = verificationForm.querySelector('button[type="submit"]');
            const result = await withLoading(button, 'Verifying...', () =>
                postRegistration('/api/registration/verify-email', data)
            );
            const state = {
                ...activeRegistration,
                email_verified: true,
                qr_code: result.qr_code,
            };
            showRegistrationState(state, result.message);
            document.getElementById('authenticatorVerificationCode').focus();
        } catch (error) {
            if (error.restart) {
                resetClosedRegistration(error.message);
                return;
            }
            setDialogStatus(error.message, 'error');
        }
    });

    resendButton.addEventListener('click', async () => {
        try {
            const result = await withLoading(resendButton, 'Sending...', () =>
                postRegistration('/api/registration/resend-code', new FormData())
            );
            setDialogStatus(result.message, 'success');
            updateResendCountdown(result.resend_in_seconds);
        } catch (error) {
            setDialogStatus(error.message, 'error');
            const cooldown = error.message.match(/wait\s+(\d+)\s+seconds?/i);
            if (cooldown) updateResendCountdown(Number(cooldown[1]));
        }
    });

    document.getElementById('authenticatorVerificationForm').addEventListener(
        'submit',
        async event => {
            event.preventDefault();
            const authenticatorForm = event.currentTarget;
            if (!authenticatorForm.reportValidity()) return;
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
                clearSavedProfile();
                window.setTimeout(() => {
                    window.location.assign(result.redirect_url);
                }, 1200);
            } catch (error) {
                if (error.restart) {
                    resetClosedRegistration(error.message);
                    return;
                }
                setDialogStatus(error.message, 'error');
                const codeInput = document.getElementById('authenticatorVerificationCode');
                codeInput.value = '';
                codeInput.focus();
            }
        }
    );

    document.getElementById('closeRegistrationDialog').addEventListener('click', () => {
        verificationDialog.close();
    });
    verificationDialog.addEventListener('cancel', () => {
        window.clearInterval(resendTimer);
    });
    // Closing the window keeps the sign-up; the banner lets the user continue it.
    verificationDialog.addEventListener('close', () => {
        showResumeBanner();
        if (!resumeBanner.hidden) document.getElementById('resumeRegistrationBtn').focus();
        else form.querySelector('button[type="submit"]').focus();
    });
});
