// Applied before first paint so a remembered theme does not flash.
(function () {
    try {
        var t = localStorage.getItem('drishti-theme');
        if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t);
    } catch (e) { /* storage blocked: follow the OS preference */ }
})();
