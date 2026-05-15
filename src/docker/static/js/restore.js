function restoreRule(ruleGroupId) {
    scrollPosition = getScrollPosition();
    const resultsCopy = structuredClone(RESULTS);
    let group = getFindingsByRuleId(ruleGroupId.split(":").pop(), resultsCopy);
    let token = getToken();
    for (var i = 0; i < group.length; i++) {
        let finding = group[i];
        let tokenIndex = token.deleted.indexOf(finding.id);
        if (tokenIndex > -1) {
            token.deleted.splice(tokenIndex, 1);
            setToken(token);
        }
    }

    let groupElement = document.getElementById(ruleGroupId);
    groupElement.remove();

    if (document.querySelectorAll(".context").length < 1 ){
        if (token.start - token.maxResults >= 0) {
            token.start -= token.maxResults;
            setToken(token);
        }
    }
    render(); 
}

function restoreContext(contextID, ruleID) {
    scrollPosition = getScrollPosition();
    let token = getToken();
    let tokenIndex = token.deleted.indexOf(contextID);
    token.deleted.splice(tokenIndex, 1);
    setToken(token);
    let contextElement = document.getElementById(contextID);
    contextElement.remove();

    console.log(ruleID);
    let groupElement = document.getElementById(ruleID);
    if (groupElement.querySelectorAll(".context").length <= 0){
        groupElement.remove(); 
    }

    if (document.querySelectorAll(".context").length < 1 ){
        if (token.start - token.maxResults >= 0) {
            token.start -= token.maxResults;
            setToken(token);
        }
        render();
    }
}

function restoreAllFindings() {
    scrollPosition = 0;
    document.getElementById('loading-animation').style.display = 'block';
    document.getElementById("main-content").style.display = "none";
    const userConfirmation = window.confirm('Are you sure you want to restore all findings?');

    if (userConfirmation) {
        let token = getToken();
        token.deleted = [];
        token.start = 0;
        setToken(token);
        render();
    }
}