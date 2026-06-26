/* SecureNET Control Panel - Keyboard Shortcuts */

document.addEventListener('keydown', function(e) {
    // Don't trigger shortcuts when typing in inputs
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) {
        return;
    }

    // Ctrl+1-9: Open tool dashboards
    if (e.ctrlKey && e.key >= '1' && e.key <= '9') {
        e.preventDefault();
        const toolIndex = parseInt(e.key) - 1;
        const toolUrls = [
            '/command', '/analytics', '/alerts', '/history', '/tools', '/docs'
        ];
        if (toolIndex < toolUrls.length) {
            window.location.href = toolUrls[toolIndex];
        }
        return;
    }

    // Ctrl+0: Open all tools page
    if (e.ctrlKey && e.key === '0') {
        e.preventDefault();
        window.location.href = '/command';
        return;
    }

    // Ctrl+A: Alerts center
    if (e.ctrlKey && e.key === 'a') {
        e.preventDefault();
        window.location.href = '/alerts';
        return;
    }

    // Ctrl+H: Home/Command center
    if (e.ctrlKey && e.key === 'h') {
        e.preventDefault();
        window.location.href = '/command';
        return;
    }

    // Ctrl+S: Scan history
    if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        window.location.href = '/history';
        return;
    }

    // Ctrl+/: Documentation
    if (e.ctrlKey && e.key === '/') {
        e.preventDefault();
        window.location.href = '/docs';
        return;
    }

    // ?: Show shortcuts modal
    if (e.key === '?' || (e.shiftKey && e.key === '/')) {
        e.preventDefault();
        const modal = document.getElementById('shortcuts-modal');
        if (modal) modal.classList.add('visible');
        return;
    }

    // Escape: Close modals
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal.visible').forEach(m => m.classList.remove('visible'));
        return;
    }
});

// Close modals on backdrop click
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal')) {
        e.target.classList.remove('visible');
    }
});
