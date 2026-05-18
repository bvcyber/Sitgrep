function seperateFindings(results) {

    let deletedFindings = [];
    let token = getToken();

    for (var dFinding of token.deleted) {

        const finding = results.find(result => result.id === dFinding);
        deletedFindings.push(finding)
        const index = results.findIndex(result => result.id === finding.id)
        if (index > -1) {
            results.splice(index, 1);
        }
    }
    return [results, deletedFindings]
}

function GetPackages() {
    return sitgrep_results["packages"].map(package => package.project.trim());
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