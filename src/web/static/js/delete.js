function deleteContext(contextId, ruleGroupId) {
    scrollPosition = getScrollPosition();
    let token = getToken();
    if (!token.deleted.includes(contextId)) {
        token.deleted.push(contextId);
    }
    setToken(token);
    let contextElement = document.getElementById(contextId);
    contextElement.remove();

    let groupElement = document.getElementById(ruleGroupId);
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
function deleteRule(ruleGroupId) {
    scrollPosition = getScrollPosition();
    const resultsCopy = structuredClone(RESULTS);
    let group = getFindingsByRuleId(ruleGroupId.split(":").pop(), resultsCopy);
    let token = getToken();
    for (var i = 0; i < group.length; i++) {
        
        let finding = group[i];
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