// DevMonitor public homepage: navigation, reveal effects, the agent "terminal",
// and the Contact us form. The page works fully without this script.
document.addEventListener('DOMContentLoaded', () => {
    document.body.classList.add('hp-js');
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // ----- Sticky nav background -----
    const nav = document.getElementById('hpNav');
    const updateNav = () => nav.classList.toggle('is-scrolled', window.scrollY > 8);
    updateNav();
    window.addEventListener('scroll', updateNav, { passive: true });

    // ----- Mobile menu -----
    const menuButton = document.getElementById('hpMenuBtn');
    const links = document.getElementById('hpLinks');
    const setMenu = open => {
        links.classList.toggle('is-open', open);
        menuButton.setAttribute('aria-expanded', String(open));
        menuButton.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
        menuButton.querySelector('i').className = open ? 'bi bi-x-lg' : 'bi bi-list';
    };
    menuButton.addEventListener('click', () => setMenu(!links.classList.contains('is-open')));
    links.addEventListener('click', event => {
        if (event.target.closest('a')) setMenu(false);
    });
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && links.classList.contains('is-open')) {
            setMenu(false);
            menuButton.focus();
        }
    });

    // ----- Highlight the section in view -----
    const navLinks = [...document.querySelectorAll('.hp-links a[data-section]')];
    if ('IntersectionObserver' in window) {
        const sectionObserver = new IntersectionObserver(entries => {
            entries.forEach(entry => {
                if (!entry.isIntersecting) return;
                navLinks.forEach(link => {
                    const active = link.dataset.section === entry.target.id;
                    link.classList.toggle('is-active', active);
                    if (active) link.setAttribute('aria-current', 'true');
                    else link.removeAttribute('aria-current');
                });
            });
        }, { rootMargin: '-45% 0px -50% 0px' });
        navLinks.forEach(link => {
            const section = document.getElementById(link.dataset.section);
            if (section) sectionObserver.observe(section);
        });

        // ----- Reveal on scroll -----
        const revealObserver = new IntersectionObserver(entries => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('is-visible');
                    revealObserver.unobserve(entry.target);
                }
            });
        }, { threshold: 0.15 });
        document.querySelectorAll('.hp-reveal').forEach((element, index) => {
            element.style.transitionDelay = `${(index % 4) * 80}ms`;
            revealObserver.observe(element);
        });
    } else {
        document.querySelectorAll('.hp-reveal').forEach(element => element.classList.add('is-visible'));
    }

    // ----- Agent terminal: replay the scan line by line -----
    const terminal = document.getElementById('hpTerminal');
    if (terminal && !reduceMotion) {
        const lines = terminal.innerHTML.split('\n');
        const caret = '<span class="hp-caret"></span>';
        const play = () => {
            let shown = 0;
            terminal.innerHTML = caret;
            const step = () => {
                shown += 1;
                terminal.innerHTML = lines.slice(0, shown).join('\n') + (shown < lines.length ? '\n' + caret : ' ' + caret);
                if (shown < lines.length) window.setTimeout(step, shown === lines.length - 2 ? 1100 : 520);
                else window.setTimeout(play, 5200);
            };
            window.setTimeout(step, 600);
        };
        play();
    }

    // ----- Contact us -----
    const form = document.getElementById('hpContactForm');
    const status = document.getElementById('hpContactStatus');
    if (form) {
        const fields = ['name', 'email', 'subject', 'message'].map(name => form.elements[name]);
        const setStatus = (text, state) => {
            status.textContent = text;
            status.className = `hp-form-status${state ? ` is-${state}` : ''}`;
        };
        fields.forEach(field => field.addEventListener('input', () => field.removeAttribute('aria-invalid')));

        form.addEventListener('submit', async event => {
            event.preventDefault();
            const invalid = fields.filter(field => !field.value.trim() || !field.checkValidity());
            fields.forEach(field => field.toggleAttribute('aria-invalid', invalid.includes(field)));
            if (invalid.length) {
                setStatus(
                    invalid[0].name === 'email' && invalid[0].value.trim()
                        ? 'Enter a valid email address so we can reply.'
                        : invalid[0].name === 'message' && invalid[0].value.trim()
                            ? 'Please write a little more in your message.'
                            : 'Please fill in every field.',
                    'error'
                );
                invalid[0].focus();
                return;
            }
            const button = form.querySelector('button[type="submit"]');
            const label = button.querySelector('span');
            button.disabled = true;
            label.textContent = 'Sending...';
            setStatus('', '');
            try {
                const response = await fetch(form.action, {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': form.elements.csrf_token.value, Accept: 'application/json' },
                    body: new FormData(form),
                });
                let result = {};
                try { result = await response.json(); } catch (error) { result = {}; }
                if (!response.ok) throw new Error(result.error || 'Your message could not be sent. Please try again.');
                setStatus(result.message || 'Thanks! Your message has been sent.', 'ok');
                form.elements.subject.value = '';
                form.elements.message.value = '';
            } catch (error) {
                setStatus(error.message, 'error');
            } finally {
                button.disabled = false;
                label.textContent = 'Send message';
            }
        });
    }
});
