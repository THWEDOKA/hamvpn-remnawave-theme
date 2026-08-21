(() => {
    const destination = '/ham-infrastructure/';
    if (location.pathname.startsWith('/ham-infrastructure')) return;

    const icon = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M5 7.5h14M7.5 4v7M16.5 4v7M5 16.5h14M9 13v7M15 13v7" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
        </svg>`;

    function install() {
        if (document.querySelector('[data-hamvpn-infrastructure]')) return true;
        const anchors = [...document.querySelectorAll('a[href]')];
        const reference = anchors.find((item) => /\/nodes(?:\/|$)/.test(item.getAttribute('href') || ''))
            || anchors.find((item) => /\/dashboard(?:\/|$)/.test(item.getAttribute('href') || ''));
        if (!reference || !reference.parentElement) return false;
        const link = reference.cloneNode(false);
        link.href = destination;
        link.dataset.hamvpnInfrastructure = 'true';
        link.setAttribute('aria-label', 'Инфраструктура');
        link.innerHTML = `${icon}<span>Инфраструктура</span>`;
        reference.parentElement.append(link);
        return true;
    }

    if (!install()) {
        const observer = new MutationObserver(() => {
            if (install()) observer.disconnect();
        });
        observer.observe(document.documentElement, { childList: true, subtree: true });
        window.setTimeout(() => observer.disconnect(), 20000);
    }
})();

