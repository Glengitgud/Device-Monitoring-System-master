// Show/hide toggles for password inputs.
// Markup: <button class="password-toggle" data-password-toggle="<input id>">
document.addEventListener('DOMContentLoaded', () => {
    for (const toggle of document.querySelectorAll('[data-password-toggle]')) {
        const input = document.getElementById(toggle.dataset.passwordToggle);
        if (!input) continue;
        const icon = toggle.querySelector('i');
        const baseLabel = (toggle.getAttribute('aria-label') || 'Show password')
            .replace(/^Show\s+/i, '');

        const render = visible => {
            input.type = visible ? 'text' : 'password';
            const label = `${visible ? 'Hide' : 'Show'} ${baseLabel}`;
            toggle.setAttribute('aria-pressed', String(visible));
            toggle.setAttribute('aria-label', label);
            toggle.title = label;
            if (icon) icon.className = visible ? 'bi bi-eye-slash' : 'bi bi-eye';
        };

        toggle.addEventListener('click', event => {
            render(input.type === 'password');
            // Mouse/touch: return focus to the field so typing can continue.
            // Keyboard (Enter/Space, event.detail === 0): keep focus on the
            // button so it can be toggled again and its focus outline stays.
            if (event.detail > 0) input.focus({ preventScroll: true });
        });

        // Never submit (or let the browser save) a password while it is shown.
        input.form?.addEventListener('submit', () => render(false));
    }
});
