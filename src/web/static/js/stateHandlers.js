function loadFindings() {
    setScrollPosition(0);
    sessionStorage.setItem('page', "findings");
    let token = getToken();
    token.start = 0;
    window.history.pushState({"token":token, "page": "findings"}, null, "");
    setToken(token);
    resetFilter();
    setTimeout(() => {
        scrollToTop();
    }, 50)
}

function loadDashboard() {
    sessionStorage.setItem('page', "dashboard");
    window.history.pushState({"token":getToken(), "page": "dashboard"}, null, "");
    resetFilter();
    setTimeout(() => {
        scrollToTop();
    }, 50);
}

function loadFalsePositives() {
    setScrollPosition(0);
    sessionStorage.setItem('page', "trash");
    let token = getToken();
    token.start = 0;
    window.history.pushState({"token":token, "page": "findings"}, null, "");
    setToken(token);
    resetFilter();
    setTimeout(() => {
        scrollToTop();
    }, 50);
}

function loadFindingsFromDashboard() {
    setScrollPosition(0);
    sessionStorage.setItem('page', "findings");
    let token = getToken();
    token.start = 0;
    window.history.pushState({"token":token, "page": "findings"}, null, "");
    setToken(token);
    render();
    setTimeout(() => {
        scrollToTop();
    }, 50);
}
