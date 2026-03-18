function getToken() {
    let token = localStorage.getItem(getFileName());
    let sortKey = document.getElementById("sortSelect").value;
   
    if (token != null) {
        token = JSON.parse(token)
    }
    else {
        token = { 
            "filters":{
                "impact":[],
                "likelihood": [],
                "confidence": [],
                "package": [],
                "owasp": [],
                "rule_id": []
            },
            "start": 0, 
            "sort": sortKey, 
            "maxResults": 5,
            "id": getFileName(),
            "deleted":[]
        };
    }

    if (token.sort == "NA" ){
        token.sort = null;
    }
    if (sortKey != "NA"){
        token.sort = sortKey;
    }

    localStorage.setItem(getFileName(), JSON.stringify(token))
    return token;
}

function setToken(tokenToUpdate){
    let token = getToken()
    if (token != null) {
        token.filters = structuredClone(tokenToUpdate.filters);
        token.start = tokenToUpdate.start;
        token.sort = tokenToUpdate.sort;
        token.maxResults = tokenToUpdate.maxResults;
        token.id = tokenToUpdate.id
        token.expires = tokenToUpdate.expires,
        token.deleted = structuredClone(tokenToUpdate.deleted)
    }
    else {
        token = { 
            "filters": structuredClone(tokenToUpdate.filters), 
            "start": tokenToUpdate.start, 
            "sort": tokenToUpdate.sortKey, 
            "maxResults": tokenToUpdate.maxResults,
            "id": getFileName(),
            "deleted": structuredClone(tokenToUpdate.deleted)
            
        };
    }
    localStorage.setItem(getFileName(), JSON.stringify(token))
}

function getNextPage(){
    scrollPosition = 0;
    let token = getToken();
    if (token.start + token.maxResults <= MAX_INDEX && getCurrentPageNumber() < MAX_PAGES){
        token.start += token.maxResults;
        setToken(token);
    }

    window.history.pushState({"token":token, "page": sessionStorage.getItem("page")}, null, "");
    render(sitgrep_results);
    setTimeout(() => {
        scrollToTop();
    }, 50)
}

function getPreviousPage(){
    scrollPosition = 0;
    let token = getToken();
    if (token.start - token.maxResults >= 0){
        token.start -= token.maxResults;
        setToken(token);
    }

    window.history.pushState({"token":token, "page": sessionStorage.getItem("page")}, null, "");
    render(sitgrep_results);
    setTimeout(() => {
        scrollToTop();
    }, 50)
}
1 
function getPage(page){
    scrollPosition = 0;
    let token = getToken();
    let page_index = parseInt(page) * token.maxResults - token.maxResults;
    if (page_index >= 0 && page_index <= MAX_INDEX){
        token.start = page_index
        setToken(token);
    }

    window.history.pushState({"token":token, "page": sessionStorage.getItem("page")}, null, "");
    render(sitgrep_results);
    setTimeout(() => {
        scrollToTop();
    }, 50)
}

function getCurrentPageNumber() {
    return Math.ceil(Math.floor(getToken().start + getToken().maxResults - 1) / getToken().maxResults);
}

function getPageNumbers(MAX_PAGES){
    return Array.from({ length: MAX_PAGES }, (_, index) => index + 1);

}

function getPaginatedFindings(results) {
    let token = getToken();
    let findings = [];

    // Ensure start doesn't go below 0
    if (token.start < 0) {
        token.start = 0;
    }

    // Ensure end doesn't exceed MAX_INDEX
    let end = token.start + token.maxResults;
    if (end > MAX_INDEX + 1) {
        end = MAX_INDEX + 1;
    }

    // Loop through the results based on the pagination parameters
    for (let i = token.start; i < end && i < results.length; i++) {
        findings.push(results[i]);
    }

    return findings;
}
