// Visible countdown for 6-digit email codes (they expire after 5 minutes on the
// server). Used by the registration dialog and the administrator sign-in step.
//
//   DevMonitorCodeTimer.start(element, seconds, { onExpire })  -> stop function
//
// Elements with data-code-expires-in start automatically. A button with
// data-resend-in stays disabled until that many seconds have passed.
(function () {
    function format(seconds) {
        const minutes = Math.floor(seconds / 60);
        return `${minutes}:${String(seconds % 60).padStart(2, '0')}`;
    }

    function start(element, seconds, options = {}) {
        if (!element) return () => {};
        window.clearInterval(element._codeTimer);
        let remaining = Math.max(0, Math.floor(Number(seconds) || 0));
        const render = () => {
            element.classList.toggle('is-expiring', remaining > 0 && remaining <= 60);
            element.classList.toggle('is-expired', remaining <= 0);
            if (remaining > 0) {
                element.textContent = `This code expires in ${format(remaining)}.`;
                remaining -= 1;
                return;
            }
            element.textContent = 'This code has expired. Select Resend code to get a new one.';
            window.clearInterval(element._codeTimer);
            if (typeof options.onExpire === 'function') options.onExpire();
        };
        render();
        if (remaining > 0) element._codeTimer = window.setInterval(render, 1000);
        return () => window.clearInterval(element._codeTimer);
    }

    function holdButton(button, seconds) {
        if (!button) return;
        let remaining = Math.max(0, Math.floor(Number(seconds) || 0));
        const label = button.textContent.trim();
        const render = () => {
            button.disabled = remaining > 0;
            button.textContent = remaining > 0 ? `${label} (${remaining}s)` : label;
            if (remaining-- <= 0) window.clearInterval(timer);
        };
        const timer = window.setInterval(render, 1000);
        render();
    }

    window.DevMonitorCodeTimer = { start, holdButton };

    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('[data-code-expires-in]').forEach(element => {
            start(element, element.dataset.codeExpiresIn);
        });
        document.querySelectorAll('[data-resend-in]').forEach(button => {
            holdButton(button, button.dataset.resendIn);
        });
    });
})();
