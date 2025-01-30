function restoreRuleGroup(ruleGroupId) {
    scrollPosition = getScrollPosition();
    const resultsCopy = structuredClone(RESULTS);
    ruleGroupId = parseInt(ruleGroupId);
    let groupIndex = getIndexById(ruleGroupId, resultsCopy);
    let group = resultsCopy[groupIndex];
    let token = getToken();
    for (var i = 0; i < group.findings.length; i++) {
        let finding = group.findings[i];
        let tokenIndex = token.deleted.indexOf(finding.id);
        token.deleted.splice(tokenIndex, 1);
        setToken(token);
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

function restoreContext(contextID) {
    scrollPosition = getScrollPosition();
    let token = getToken();
    let tokenIndex = token.deleted.indexOf(contextID);
    token.deleted.splice(tokenIndex, 1);
    setToken(token);
    let contextElement = document.getElementById(contextID.toString());
    contextElement.remove();

    let groupElement = document.getElementById(contextID.split("::")[0].toString());
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