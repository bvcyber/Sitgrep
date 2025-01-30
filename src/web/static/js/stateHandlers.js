function loadFindings() {
    setScrollPosition(0);
    sessionStorage.setItem('page', "findings");
    let token = getToken();
    token.start = 0;
    window.history.pushState({"token":token, "page": "findings"}, null, "");
    setToken(token);
    resetFilter();
}

function loadDashboard() {
    sessionStorage.setItem('page', "dashboard");
    window.history.pushState({"token":getToken(), "page": "dashboard"}, null, "");
    resetFilter();
}

function loadFalsePositives() {
    setScrollPosition(0);
    sessionStorage.setItem('page', "trash");
    let token = getToken();
    token.start = 0;
    window.history.pushState({"token":token, "page": "findings"}, null, "");
    setToken(token);
    resetFilter();
}

function loadFindingsFromDashboard() {
    setScrollPosition(0);
    sessionStorage.setItem('page', "findings");
    let token = getToken();
    token.start = 0;
    window.history.pushState({"token":token, "page": "findings"}, null, "");
    setToken(token);
    render();
}
