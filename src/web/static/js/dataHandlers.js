function seperateFindings(results) {

    let deletedFindings = [];
    let token = getToken();

    for (var dFinding of token.deleted) {

        let groupIndex = parseInt(dFinding.split('::')[0]);
        let realGroupIndex = getIndexById(groupIndex, results);
        let realFindingIndex = getIndexById(dFinding, results[realGroupIndex].findings)

        if (realFindingIndex > -1 && realGroupIndex > -1) {
            let finding = results[realGroupIndex].findings[realFindingIndex];
            let deletedGroupIndex = getIndexById(groupIndex, deletedFindings);

            if (deletedGroupIndex > -1) {
                deletedFindings[deletedGroupIndex].findings.push(finding)
            }
            else {
                let tempGroup = structuredClone(results[realGroupIndex]);
                tempGroup.findings = [];
                tempGroup.findings.push(structuredClone(results[realGroupIndex].findings[realFindingIndex]));
                deletedFindings.push(tempGroup);
            }
            results[realGroupIndex].findings.splice(realFindingIndex, 1);
            if (results[realGroupIndex].findings.length == 0) {
                results.splice(realGroupIndex, 1);
            }
        }
        else {
            // console.log('realGroupIndex: ', realGroupIndex)
            // console.log("realFindingIndex: ", realFindingIndex)
            // console.log(results[realGroupIndex].findings)
            // console.log('dFinding: ', dFinding)
            // console.log('------------------------------')
        }
    }

    return [results, deletedFindings]
}

function GetPackages() {
    var packages = sitgrep_results["packages"].map(package => package.project.trim());
    return packages
}

function GetOWASPsList() {
    var owasps = [];

    sitgrep_results["results"].forEach(result => {
        if (Array.isArray(result["owasp"])) {
            result["owasp"].forEach(item => {
                if (!isCutValueExists(owasps, item)) {
                    owasps.push(item);
                }
            });
        } else {
            if (!isCutValueExists(owasps, result["owasp"])) {
                owasps.push(result["owasp"]);
            }
        }
    });
    return _.uniq(owasps, true);
}

function getPackageNames() {
    let packages = [];
    packageList.forEach(element => {
        packages.push(element.package)
    });
    return packages
}

function GetRules() {
    var rules = [];

    sitgrep_results["results"].forEach(result => {
        rules.push(result["rule_id"]);
    });
    return _.uniq(rules, true);
}