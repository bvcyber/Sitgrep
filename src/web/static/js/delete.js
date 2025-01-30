function deleteContext(contextId) {
    scrollPosition = getScrollPosition();
    let token = getToken();
    if (!token.deleted.includes(contextId)) {
        token.deleted.push(contextId);
    }
    setToken(token);
    let contextElement = document.getElementById(contextId.toString());
    contextElement.remove();

    let groupElement = document.getElementById(contextId.split("::")[0].toString());
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
function deleteRuleGroup(ruleGroupId) {
    scrollPosition = getScrollPosition();
    const resultsCopy = structuredClone(RESULTS);
    ruleGroupId = parseInt(ruleGroupId);
    let groupIndex = getIndexById(ruleGroupId, resultsCopy);
    let group = resultsCopy[groupIndex];
    let token = getToken();
    for (var i = 0; i < group.findings.length; i++) {
        
        let finding = group.findings[i];
        if (!token.deleted.includes(finding.id)) {
            token.deleted.push(finding.id);
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

    setToken(token);
    render();
}