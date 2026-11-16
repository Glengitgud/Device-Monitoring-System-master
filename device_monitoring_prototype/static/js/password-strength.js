document.addEventListener('DOMContentLoaded', () => {
    const indicators = [
        ['password', 'registerPasswordStrength'],
        ['passwordInput', 'loginPasswordStrength']
    ];

    for (const [inputId, indicatorId] of indicators) {
        const input = document.getElementById(inputId);
        const indicator = document.getElementById(indicatorId);
        if (!input || !indicator) continue;

        const updateStrength = () => {
            const password = input.value;
            const length = Array.from(password).length;
            if (!password) {
                indicator.textContent = 'Enter a password to see its strength.';
                indicator.className = 'password-strength';
                return;
            }

            const hasUppercase = /[A-Z]/.test(password);
            const hasLowercase = /[a-z]/.test(password);
            const hasNumber = /\d/.test(password);
            const hasSpecial = Array.from(password).some(character =>
                !/[\p{L}\p{N}]/u.test(character) && !/\s/u.test(character)
            );
            const meetsMinimum = length >= 8 && length <= 16
                && hasUppercase && hasSpecial;
            const level = !meetsMinimum
                ? 'weak'
                : hasLowercase && hasNumber ? 'strong' : 'medium';
            const labels = {
                weak: 'Weak password — add length and complexity.',
                medium: 'Medium password — meets the minimum requirements.',
                strong: 'Strong password — includes upper/lowercase letters, a number, and a special character.'
            };
            indicator.textContent = labels[level];
            indicator.className = `password-strength is-${level}`;
        };

        input.addEventListener('input', updateStrength);
        updateStrength();
    }
});
