
function updateSort(className){
    let token = getToken();
    if (token){
        token.sort = className;
    }
    setToken(token);
    window.scrollTo({ top: 0, behavior: "smooth" });
}

function sortFindings(findings) {
    let token = getToken();
    let sortedFindings = findings;
    let sortKey = token.sort
    if (sortKey != null && sortKey != "NA") {
        sortedFindings.sort((a, b) => {
            const aText = a[sortKey];
            const bText = b[sortKey];
            const customOrder = { "HIGH": 1, "MEDIUM": 2, "LOW": 3 };

            if (customOrder[aText] !== undefined && customOrder[bText] !== undefined) {
                return customOrder[aText] - customOrder[bText];
            } else {
                let aText1 = extractLastPart(aText);
                let bText1 = extractLastPart(bText);
                return aText1.localeCompare(bText1);
            }
        });
    }

    return sortedFindings
}
