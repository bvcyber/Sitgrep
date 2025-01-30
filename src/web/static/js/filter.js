function applyFilter() {
    scrollPosition = 0;
    let token = getToken();
    let filterOptions = document.querySelectorAll('.filter-options');
    filterOptions.forEach(filterGroup => {
        let filters = filterGroup.querySelectorAll('.filter-option');
        let filterKey = filterGroup.getAttribute('value');
        filters.forEach(filterOption => {

            let filterValue = filterOption.querySelector('input').value.toUpperCase();

            if (filterOption.querySelector('input').checked) {
                if (!token.filters[filterKey].includes(sha256(filterValue))) {
                    token.filters[filterKey].push(sha256(filterValue))
                }
            }
            else {
                if (token.filters[filterKey].includes(sha256(filterValue))) {
                    token.filters[filterKey].splice(token.filters[filterKey].indexOf(sha256(filterValue)), 1);
                }
            }

        });
    });
    var owaspSelect = document.getElementById("owasp-select");
    var owaspSelectIndex = owaspSelect.selectedIndex;
    var selectedOwasp = owaspSelect.options[owaspSelectIndex];
    var owaspValue = sha256(selectedOwasp.value);

    var packageSelect = document.getElementById("package-select");

    let packageValue;
    if (packageSelect) {
        var packageSelectIndex = packageSelect.selectedIndex;
        if (packageSelect.options.length > 0) {
            var selectedPackage = packageSelect.options[packageSelectIndex];
            packageValue = sha256(selectedPackage.value);
        }
    }

    var ruleSelect = document.getElementById("rule-select");
    var ruleSelectIndex = ruleSelect.selectedIndex;
    var selectedRule = ruleSelect.options[ruleSelectIndex];
    var ruleValue = sha256(selectedRule.value);

    if (owaspValue != undefined && owaspValue != "20ef0f0c8d0eea98772412cea9b3b92612e3e53cb5e59152b5703165f56e8a53" && !token.filters.owasp.includes(owaspValue)) {
        token.filters.owasp.length = 0;
        token.filters.owasp.push(owaspValue);
    }

    if (packageValue != undefined && packageValue != "20ef0f0c8d0eea98772412cea9b3b92612e3e53cb5e59152b5703165f56e8a53" && !token.filters.package.includes(packageValue)) {
        token.filters.package.length = 0;
        token.filters.package.push(packageValue);
    }

    if (ruleValue != undefined && ruleValue != "20ef0f0c8d0eea98772412cea9b3b92612e3e53cb5e59152b5703165f56e8a53" && !token.filters.rule_id.includes(ruleValue)) {
        token.filters.rule_id.length = 0;
        token.filters.rule_id.push(ruleValue);
    }

    token.start = 0;
    setToken(token);
}

function resetFilter() {
    token = getToken()

    if (token != null) {

        token.filters = {
            "impact": [],
            "likelihood": [],
            "confidence": [],
            "package": [],
            "owasp": [],
            "rule_id": []
        }


        let filterOptions = document.querySelectorAll('.filter-options');
        filterOptions.forEach(filterGroup => {
            let filters = filterGroup.querySelectorAll('.filter-option');
            filters.forEach(filterOption => {
                filterOption.querySelector('input').checked = false;
            });
        });

        var owaspSelect = document.getElementById("owasp-select");
        owaspSelect.selectedIndex = 0;
        var packageSelect = document.getElementById("package-select");
        if (packageSelect) {
            packageSelect.selectedIndex = 0;
        }
        var ruleSelect = document.getElementById("rule-select");
        ruleSelect.selectedIndex = 0;
        var sortSelect = document.getElementById('sortSelect');
        sortSelect.selectedIndex = 0;

        setToken(token)
    }

    render();
    scrollToTop()
}

function loadOWASPFilter() {
    const selectFilter = document.getElementById('owasp-select');

    var owasps = GetOWASPsList();

    selectFilter.innerHTML = '';
    var select = document.createElement('option');
    select.value = "NA";
    select.textContent = "--OWASP--";
    selectFilter.appendChild(select);
    owasps.forEach((owasp) => {
        var newDiv = document.createElement('option');
        newDiv.value = owasp;
        newDiv.textContent = owasp;
        selectFilter.appendChild(newDiv);
    });
}

function loadRuleFilter(rule) {
    const selectFilter = document.getElementById('rule-select');

    var rules = GetRules();

    selectFilter.innerHTML = '';
    var select = document.createElement('option');
    select.value = "NA";
    select.textContent = "--Rule--";
    selectFilter.appendChild(select);
    rules.forEach((rule) => {
        var newDiv = document.createElement('option');
        newDiv.value = rule;
        newDiv.textContent = rule;
        selectFilter.appendChild(newDiv);
    });
    if (rule){
        selectFilter.selectedIndex = rules.indexOf(rule) + 1;
    }
}

function loadPackageFilter(package) {
    const selectFilter = document.getElementById('package-select');

    var packages = GetPackages();

    if (packages.length == 0) {
        document.getElementById('package-filter').style.display = "none";
    }
    else {
        PACKAGES = true;
        selectFilter.innerHTML = '';
        var select = document.createElement('option');
        select.value = "NA";
        select.textContent = "--Package--";
        selectFilter.appendChild(select);
        packages.forEach((package) => {
            var newDiv = document.createElement('option');
            newDiv.value = package;
            newDiv.textContent = package;
            selectFilter.appendChild(newDiv);
        });
        if (package){
            selectFilter.selectedIndex = packages.indexOf(package) + 1;
        }
    }
}


function getFilteredFindings(data) {
    let filters = getToken().filters;
    let filteredGroups = data.filter(function (group) {
        for (var key in filters) {
            // Filters OWASPs
            if (filters[key].length > 0 && Array.isArray(group[key])) {
                if (!filters[key].some(filterValue => {
                    return group[key].some(element => {
                        return sha256(element).includes(filterValue);
                    });
                })) {
                    return false;
                }
            } 
            // Filters Rules
            else if (filters[key].length > 0 && group[key] !== undefined && !filters[key].includes(sha256(group[key]))) {
                return false;
            }
            else {
            }
        }
        return true;
    });


    // Filters packages
    if (filters.package.length > 0) {
        for (var i = 0; i < filteredGroups.length; i++) {
            let group = filteredGroups[i];
            group.findings = group.findings.filter(finding =>
                sha256(finding.package) === filters.package[0]
            )
        }
        // Remove empty groups if no findings have matching packages
        filteredGroups = filteredGroups.filter(function (group) {
            if (group.findings.length == 0) {
                return false;
            }
            return true;
        });
    }
    return filteredGroups
}

function applyRuleFilter(rule) {
    let token = getToken();
    let ruleText = rule;
    let ruleHash = sha256(rule);
    token.filters.rule_id = [ruleHash.toString()];

    setToken(token);
    loadFindingsFromDashboard();
    loadRuleFilter(ruleText);
}

function applyPackageFilter(package) {
    let token = getToken();
    let packageText = package;
    let packageHash = sha256(package);
    token.filters.package = [packageHash.toString()];

    setToken(token);
    loadFindingsFromDashboard();
    loadPackageFilter(packageText);
}