let MAX_INDEX = sitgrep_results["results"].length - 1;
let MAX_PAGES = 1;
const RESULTS = structuredClone(sitgrep_results["results"]);
const packageList = sitgrep_results["packages"];
const contextLength = sitgrep_results["contextLength"];
let PACKAGES = false;
let scrollPosition = 0;
let pageContents;

function render() {
    document.getElementById('loading-animation').style.display = 'block';

    let main = document.getElementById("main-content");
    main.style.display = "none";
    main.innerHTML = ""

    let results = structuredClone(sitgrep_results["results"]);
    let seperatedFindings = seperateFindings(results);
    let activeFindings = seperatedFindings[0];
    let deletedFindings = seperatedFindings[1];
    let sortedFindings, filteredFindings;
    let page = sessionStorage.getItem("page");

    if (page == "trash") {
        pageContents = deletedFindings;
        document.getElementById('opts').style.display = "block";
        document.getElementById("trash-nav").style.color = "#0094d4";
        document.getElementById("dashboard-nav").style.color = "white";
        document.getElementById("findings-nav").style.color = "white";
        filteredFindings = getFilteredFindings(pageContents);
        sortedFindings = sortFindings(filteredFindings);
        pageContents = getPaginatedFindings(sortedFindings);
    }
    else if (page == "dashboard") {
        scrollPosition = 0;
        document.getElementById('opts').style.display = "none";
        document.getElementById("trash-nav").style.color = "white";
        document.getElementById("dashboard-nav").style.color = "#0094d4";
        document.getElementById("findings-nav").style.color = "white";
    }
    else if (page == "findings") {
        pageContents = activeFindings;
        document.getElementById('opts').style.display = "block";
        document.getElementById("trash-nav").style.color = "white";
        document.getElementById("dashboard-nav").style.color = "white";
        document.getElementById("findings-nav").style.color = "#0094d4";
        filteredFindings = getFilteredFindings(pageContents);
        sortedFindings = sortFindings(filteredFindings);
        pageContents = getPaginatedFindings(sortedFindings);
    }

    let cap = page.toLocaleLowerCase().split('');
    cap[0] = cap[0].toUpperCase();
    let title = cap.join("");
    document.getElementById("page-title").textContent = title;

    if (sortedFindings && sortedFindings.length < 1) {
        main.appendChild(empty_page());
        document.getElementById('loading-animation').style.display = 'none';
        main.style.display = 'block';
    }
    else if (page == "dashboard") {
        main.appendChild(buildDashboard());
        let ruleList = GetRules();
        ruleList.forEach(rule => {
            document.getElementById('rule-list').appendChild(rule_list_item(rule));
        });
        packageList.forEach(package => {
            document.getElementById('package-list').appendChild(package_list_item(package));
        });

        createPieChart('confidenceChart', confidenceData, ['High', 'Medium', 'Low']);
        createPieChart('impactChart', impactData, ['High', 'Medium', 'Low']);
        createPieChart('likelihoodChart', likelihoodData, ['High', 'Medium', 'Low']);
        createBarGraph('ruleIdChart', ruleIdData, "rule");
        if (packageList.length > 0) {
            createBarGraph('packageNameChart', packageNameData, "package");
        }
        else {
            main.querySelector('.chart-container-packages').style.display = "none";
            main.querySelector('#package-list').style.display = "none";
            main.querySelector('#dashboard-meta-row').style.width = "75%";
        }

        document.getElementById('loading-animation').style.display = 'none';
        main.style.display = 'block';
    }
    else {
        setTimeout(() => {
            buildAllFindings(main, sortedFindings, pageContents);
            setScrollPosition(scrollPosition);
        }, 20);
    }
}

function buildAllFindings(main, sortedFindings, pageContents) {
    if (main) {
        MAX_PAGES = Math.ceil(sortedFindings.length / getToken().maxResults);
        for (var i = 0; i < pageContents.length; i++) {

            let findingGroup = pageContents[i];

            if (findingGroup.findings.length < 1) {
                continue;
            }

            main.appendChild(buildGroup(findingGroup));
            var group = document.getElementById(findingGroup["id"].toString());
            var owasps = group.querySelector(".owasp-list")
            var cwes = group.querySelector(".cwe-list")
            var resultsDiv = group.querySelector(".results");

            owasps.appendChild(buildOWASP(findingGroup["owasp"]));
            cwes.appendChild(buildCWE(findingGroup["cwe"]));

            if (sessionStorage.getItem("page") == "trash") {
                let ruleContent = group.querySelector('.rule-content');
                let button = ruleContent.querySelector('.delete-button');
                button.setAttribute('onclick', `restoreRuleGroup(${findingGroup["id"].toString()})`);
                button.classList.remove('delete-button');
                button.classList.add('restore-button');

                let icon = button.querySelector('i');
                icon.classList.remove('material-icons');
                icon.classList.add('fa', 'fa-undo');
                icon.innerHTML = "";
                buildFindingsContexts(findingGroup, resultsDiv);
            }
            else {
                let ruleContent = group.querySelector('.rule-content');
                let button = ruleContent.querySelector('.delete-button');
                button.setAttribute('onclick', `deleteRuleGroup(${findingGroup["id"].toString()})`);
                buildFindingsContexts(findingGroup, resultsDiv);
            }
        }
        if (MAX_PAGES > 1) {
            main.appendChild(buildPagination());
        }
        document.getElementById('loading-animation').style.display = 'none';
        main.style.display = 'block';

    }
}

function buildFinding(finding, resultsDiv, shouldHide) {

    const start = finding["start"];
    const end = finding["end"];
    const file_size = finding["file-size"];
    const file = finding["file"];
    const findingId = finding["id"];
    const fullFile = finding["fullFile"];


    let span = end - start;
    let start_line = Math.max(start - contextLength, 1);
    let end_line = Math.min(start + contextLength + span + 1, file_size + 1);
    let line = start === end ? `${start}` : `${start}-${end}`;
    let linkLine = start === end ? `L${start}` : `L${start}-L${end}`;
    const link = generatePackageUrl(packageList, file, linkLine, fullFile);

    resultsDiv.appendChild(PACKAGES ? finding_template_linked(file, line, findingId, link) : finding_template(file, line, findingId));

    let contextDivs = resultsDiv.querySelectorAll(".context");
    let latestFinding = contextDivs[contextDivs.length - 1];
    let codeLinesHTML = latestFinding.querySelector(".code-lines");
    let codeContextHTML = latestFinding.querySelector(".code-content");

    if (shouldHide) {
        latestFinding.style.display = "none";
    }

    for (let i = start_line; i <= end_line; i++) {
        if (i == start && i == end) {
            codeLinesHTML.appendChild(highlighted_line_template(i, true, true));

        }
        else if (i == start) {
            codeLinesHTML.appendChild(highlighted_line_template(i, true, false));
        }
        else if (i == end) {
            codeLinesHTML.appendChild(highlighted_line_template(i, false, true));
        }
        else if (i > start && i < end) {
            codeLinesHTML.appendChild(highlighted_line_template(i, false, false));
        }
        else {
            codeLinesHTML.appendChild(line_template(i));
        }
    }

    codeContextHTML.appendChild(code_template(finding["context"], line, start_line, end_line, file));
    if (sessionStorage.getItem("page") == "trash") {
        let buttons = latestFinding.querySelector('.contextBtns');
        let button = buttons.querySelector('.delete-button');
        button.setAttribute('onclick', `restoreContext("${findingId.toString()}")`);
        button.classList.remove('delete-button');
        button.classList.add('restore-button');

        let icon = button.querySelector('i');
        icon.innerHTML = ""
        icon.classList.remove('material-icons');
        icon.classList.add('fa', 'fa-undo');
    }

}

function buildFindingsContexts(findingGroup, resultsDiv) {
    var i = 0;
    const maxContexts = 5;
    for (const finding of findingGroup.findings) {
        if (i >= maxContexts) {
            resultsDiv.appendChild(loadMoreTemplate(findingGroup.findings.length - maxContexts, findingGroup.id));
            break;
        }
        buildFinding(finding, resultsDiv, false);
        i++;
    };


}
function loadMoreTemplate(count, groupID) {
    // Create main container div
    var contextDiv = document.createElement('div');
    contextDiv.classList.add('context', 'bordered');
    contextDiv.id = 'more';

    // Load more button
    var findingLoadingElement = document.createElement("div");
    findingLoadingElement.classList.add('loading');
    findingLoadingElement.style.display = "none";
    contextDiv.appendChild(findingLoadingElement);

    // Create inner div for the clickable area
    var moreDiv = document.createElement('div');
    moreDiv.classList.add('more');
    moreDiv.textContent = `Load ${count} more findings`;
    moreDiv.onclick = function () {
        findingLoadingElement.style.display = "block";
        moreDiv.remove()

        setTimeout(() => {
            loadMore(groupID);
        }, 0);
        

    };

    // Append inner div to main container div
    contextDiv.appendChild(moreDiv);

    return contextDiv;
}


function buildGroup(result) {

    // Create main container div
    var groupDiv = document.createElement('div');
    groupDiv.classList.add('rule-group');
    groupDiv.id = result["id"];

    // Create group color div
    var groupColorDiv = document.createElement('div');
    groupColorDiv.classList.add('group-color');
    groupDiv.appendChild(groupColorDiv);

    // Create rule content div
    var ruleContentDiv = document.createElement('div');
    ruleContentDiv.classList.add('rule-content');
    groupDiv.appendChild(ruleContentDiv);

    // Create delete button
    var deleteButton = document.createElement('button');
    deleteButton.classList.add('delete-button', 'group-btn');
    deleteButton.setAttribute('onclick', `deleteRuleGroup(${result["id"]})`);
    var deleteIcon = document.createElement('i');
    deleteIcon.classList.add('material-icons');
    deleteIcon.textContent = 'delete';
    deleteButton.appendChild(deleteIcon);
    ruleContentDiv.appendChild(deleteButton);

    // Create rule name div
    var ruleNameDiv = document.createElement('div');
    ruleNameDiv.classList.add('rule-name');
    var ruleNameHeader = document.createElement('h1');
    ruleNameHeader.textContent = result["rule_id"];
    ruleNameDiv.appendChild(ruleNameHeader);
    ruleContentDiv.appendChild(ruleNameDiv);

    // Create group header div
    var groupHeaderDiv = document.createElement('div');
    groupHeaderDiv.classList.add('group-header');
    ruleContentDiv.appendChild(groupHeaderDiv);

    // Create description div
    var descripDiv = document.createElement('div');
    descripDiv.classList.add('descrip');
    descripDiv.textContent = result["description"];
    groupHeaderDiv.appendChild(descripDiv);

    // Create hr element
    var hrElement = document.createElement('hr');
    hrElement.classList.add('solid');
    ruleContentDiv.appendChild(hrElement);

    // Create scores div
    var scoresDiv = document.createElement('div');
    scoresDiv.classList.add('scores');
    ruleContentDiv.appendChild(scoresDiv);

    // Create confidence div
    var confidenceDiv = document.createElement('div');
    confidenceDiv.classList.add('confidence');
    scoresDiv.appendChild(confidenceDiv);
    var confidenceTitleDiv = document.createElement('div');
    confidenceTitleDiv.classList.add('metadata-title');

    // Create metadata title for Confidence
    var confidenceTitleDiv = document.createElement('div');
    confidenceTitleDiv.classList.add('metadata-title');

    // Create h3 element for Confidence title
    var confidenceTitle = document.createElement('h3');
    confidenceTitle.textContent = 'Confidence';

    // Append the h3 element to the metadata title div
    confidenceTitleDiv.appendChild(confidenceTitle);
    confidenceDiv.appendChild(confidenceTitleDiv);
    var confidenceValueDiv = document.createElement('div');
    confidenceValueDiv.classList.add('metadata-value');
    confidenceValueDiv.textContent = result["confidence"];
    confidenceDiv.appendChild(confidenceValueDiv);

    // Create metadata title for Impact
    var impactMetadataTitle = document.createElement('div');
    impactMetadataTitle.classList.add('metadata-title');
    var impactTitle = document.createElement('h3');
    impactTitle.textContent = 'Impact';
    impactMetadataTitle.appendChild(impactTitle);

    // Create metadata value for Impact
    var impactMetadataValue = document.createElement('div');
    impactMetadataValue.classList.add('metadata-value');
    impactMetadataValue.textContent = result["impact"];

    // Create metadata title for Likelihood
    var likelihoodMetadataTitle = document.createElement('div');
    likelihoodMetadataTitle.classList.add('metadata-title');
    var likelihoodTitle = document.createElement('h3');
    likelihoodTitle.textContent = 'Likelihood';
    likelihoodMetadataTitle.appendChild(likelihoodTitle);

    // Create metadata value for Likelihood
    var likelihoodMetadataValue = document.createElement('div');
    likelihoodMetadataValue.classList.add('metadata-value');
    likelihoodMetadataValue.textContent = result["likelihood"];

    // Create container for Impact
    var impactContainer = document.createElement('div');
    impactContainer.classList.add('impact');
    impactContainer.appendChild(impactMetadataTitle);
    impactContainer.appendChild(impactMetadataValue);

    // Create container for Likelihood
    var likelihoodContainer = document.createElement('div');
    likelihoodContainer.classList.add('likelihood');
    likelihoodContainer.appendChild(likelihoodMetadataTitle);
    likelihoodContainer.appendChild(likelihoodMetadataValue);

    scoresDiv.appendChild(impactContainer);
    scoresDiv.appendChild(likelihoodContainer);

    // Create ratings div
    var ratingsDiv = document.createElement('div');
    ratingsDiv.classList.add('ratings');
    scoresDiv.appendChild(ratingsDiv);
    var owaspListDiv = document.createElement('div');
    owaspListDiv.classList.add('owasp-list');
    ratingsDiv.appendChild(owaspListDiv);
    var cweListDiv = document.createElement('div');
    cweListDiv.classList.add('cwe-list');
    ratingsDiv.appendChild(cweListDiv);

    // Create results div
    var resultsDiv = document.createElement('div');
    resultsDiv.classList.add('results');
    ruleContentDiv.appendChild(resultsDiv);

    return groupDiv;
}
function buildOWASP(owasps) {
    let newWasp = document.createElement('div');
    newWasp.classList.add('owasp');

    let metadataTitleDiv = document.createElement('div');
    metadataTitleDiv.classList.add('metadata-title');

    let heading3 = document.createElement('h3');
    heading3.textContent = 'OWASP';

    metadataTitleDiv.appendChild(heading3);
    newWasp.appendChild(metadataTitleDiv);

    if (Array.isArray(owasps)) {
        owasps.forEach(wasp => {
            newWasp.appendChild(owasp_template(wasp));
        });
    }
    else {
        newWasp.appendChild(owasp_template(owasps));
    }

    return newWasp

}
function buildCWE(cwes) {
    let newCWE = document.createElement('div');
    newCWE.classList.add('cwe');

    let metadataTitleDiv = document.createElement('div');
    metadataTitleDiv.classList.add('metadata-title');

    let heading3 = document.createElement('h3');
    heading3.textContent = 'CWE';

    metadataTitleDiv.appendChild(heading3);
    newCWE.appendChild(metadataTitleDiv);

    if (Array.isArray(cwes)) {
        cwes.forEach(cwe => {
            newCWE.appendChild(cwe_template(cwe));
        });
    }
    else {
        newCWE.appendChild(cwe_template(cwes));
    }

    return newCWE
}
function owasp_template(wasp) {
    // Create metadata value div
    var metadataValueDiv = document.createElement('div');
    metadataValueDiv.classList.add('metadata-value');
    metadataValueDiv.textContent = wasp;

    return metadataValueDiv;
}

function cwe_template(cwe) {
    // Create metadata value div
    var metadataValueDiv = document.createElement('div');
    metadataValueDiv.classList.add('metadata-value');
    metadataValueDiv.textContent = cwe;

    return metadataValueDiv;
}


function finding_template(file, line, findingId) {
    // Create main container div
    var contextDiv = document.createElement('div');
    contextDiv.classList.add('context', 'bordered');
    contextDiv.id = findingId;

    // Create context options div
    var contextOptsDiv = document.createElement('div');
    contextOptsDiv.classList.add('context-opts');
    contextDiv.appendChild(contextOptsDiv);

    // Create context file div
    var contextFileDiv = document.createElement('div');
    contextFileDiv.classList.add('context-file');
    var fileFindingP = document.createElement('p');
    fileFindingP.classList.add('file-finding');
    fileFindingP.textContent = file + ":" + line;
    contextFileDiv.appendChild(fileFindingP);
    contextOptsDiv.appendChild(contextFileDiv);

    // Create context buttons div
    var contextBtnsDiv = document.createElement('div');
    contextBtnsDiv.classList.add('contextBtns');
    contextOptsDiv.appendChild(contextBtnsDiv);

    // Create delete button
    var deleteButton = document.createElement('button');
    deleteButton.classList.add('delete-button', 'context-btn');
    deleteButton.setAttribute('onclick', `deleteContext('${findingId}')`);
    var deleteIcon = document.createElement('i');
    deleteIcon.classList.add('material-icons');
    deleteIcon.textContent = 'delete';
    deleteButton.appendChild(deleteIcon);
    contextBtnsDiv.appendChild(deleteButton);

    // Create copy button
    var copyButton = document.createElement('button');
    copyButton.classList.add('context-btn');
    copyButton.setAttribute('onclick', 'copy_code_block(this)');
    var copyIcon = document.createElement('i');
    copyIcon.classList.add('fa-regular', 'fa-copy');
    copyButton.appendChild(copyIcon);
    contextBtnsDiv.appendChild(copyButton);

    // Create context table div
    var contextTableDiv = document.createElement('div');
    contextTableDiv.classList.add('context_table');
    contextDiv.appendChild(contextTableDiv);

    // Create code lines div
    var codeLinesDiv = document.createElement('div');
    codeLinesDiv.classList.add('code-lines');
    codeLinesDiv.innerHTML = '\n';
    contextTableDiv.appendChild(codeLinesDiv);

    // Create code content div
    var codeContentDiv = document.createElement('div');
    codeContentDiv.classList.add('code-content');
    contextTableDiv.appendChild(codeContentDiv);

    return contextDiv;
}

function finding_template_linked(file, line, findingId, link) {
    // Create main container div
    var contextDiv = document.createElement('div');
    contextDiv.classList.add('context', 'bordered');
    contextDiv.id = findingId;

    // Create context options div
    var contextOptsDiv = document.createElement('div');
    contextOptsDiv.classList.add('context-opts');
    contextDiv.appendChild(contextOptsDiv);

    // Create context file div
    var contextFileDiv = document.createElement('div');
    contextFileDiv.classList.add('context-file');
    var fileFindingP = document.createElement('p');
    fileFindingP.classList.add('file-finding');

    // Creating elements
    var content = document.createElement("div");
    var linkSpan = document.createElement("span");
    var fileSpan = document.createElement("span");
    var linkAnchor = document.createElement("a");

    // Setting attributes and content
    content.style.display = "flex";
    content.style.flexDirection = "row"
    fileSpan.style.marginRight = "5px"
    fileSpan.textContent = file + ":" + line;
    linkAnchor.href = link;
    linkAnchor.target = "_blank";
    linkAnchor.style.color = "#95d1e7";
    linkAnchor.textContent = "view";

    // Appending elements
    content.append(fileSpan)
    linkSpan.appendChild(linkAnchor);
    content.appendChild(linkSpan);
    fileFindingP.appendChild(content);

    contextFileDiv.appendChild(fileFindingP);
    contextOptsDiv.appendChild(contextFileDiv);

    // Create context buttons div
    var contextBtnsDiv = document.createElement('div');
    contextBtnsDiv.classList.add('contextBtns');
    contextOptsDiv.appendChild(contextBtnsDiv);

    // Create delete button
    var deleteButton = document.createElement('button');
    deleteButton.classList.add('delete-button', 'context-btn');
    deleteButton.setAttribute('onclick', `deleteContext('${findingId}')`);
    var deleteIcon = document.createElement('i');
    deleteIcon.classList.add('material-icons');
    deleteIcon.textContent = 'delete';
    deleteButton.appendChild(deleteIcon);
    contextBtnsDiv.appendChild(deleteButton);

    // Create copy button
    var copyButton = document.createElement('button');
    copyButton.classList.add('context-btn');
    copyButton.setAttribute('onclick', 'copy_code_block(this)');
    var copyIcon = document.createElement('i');
    copyIcon.classList.add('fa-regular', 'fa-copy');
    copyButton.appendChild(copyIcon);
    contextBtnsDiv.appendChild(copyButton);

    // Create context table div
    var contextTableDiv = document.createElement('div');
    contextTableDiv.classList.add('context_table');
    contextDiv.appendChild(contextTableDiv);

    // Create code lines div
    var codeLinesDiv = document.createElement('div');
    codeLinesDiv.classList.add('code-lines');
    codeLinesDiv.innerHTML = '\n';
    contextTableDiv.appendChild(codeLinesDiv);

    // Create code content div
    var codeContentDiv = document.createElement('div');
    codeContentDiv.classList.add('code-content');
    contextTableDiv.appendChild(codeContentDiv);

    return contextDiv;
}
function highlighted_code_line_template(code, top, bottom) {
    // Create highlighted code div
    var highlightedCodeDiv = document.createElement('div');
    if (top || bottom){
        if (top) {
            highlightedCodeDiv.classList.add('highlighted-top');
        }
        if (bottom) {
            highlightedCodeDiv.classList.add('highlighted-bottom');
        }
    }
    else {
        highlightedCodeDiv.classList.add('highlighted');
    }

    highlightedCodeDiv.classList.add('code-line');
    highlightedCodeDiv.innerHTML = code + "\n";

    return highlightedCodeDiv;
}

function code_line_template(code) {
    var highlightedCodeDiv = document.createElement('div');
    highlightedCodeDiv.classList.add('code-line');
    highlightedCodeDiv.innerHTML = code + "\n";
    return highlightedCodeDiv;
}

function code_template(code, lineNumber, start_line, end_line, filePath) {
    // Create <pre> element
    var preElement = document.createElement('pre');
    preElement.classList.add('codepre');

    let lineStart = lineNumber;
    let lineEnd = lineNumber;
    if (lineNumber.includes("-")) {
        lineStart = lineNumber.split("-")[0];
        lineEnd = lineNumber.split("-")[1];
    }

    // Create <code> element
    var codeElement = document.createElement('code');
    const lines = code.split('\n');

    for (let i = start_line; i < end_line; i++) {
        let index = i - start_line
        const lang = getLanguageByExtension(filePath);
        lines[index] = hljs.highlight(lines[index], {language:lang, ignoreIllegals:true}).value;
        if (i == lineStart && i == lineEnd){
            codeElement.appendChild(highlighted_code_line_template(lines[index], true, true))
        }
        else if (i == lineStart) {
            codeElement.appendChild(highlighted_code_line_template(lines[index], true, false))
        }
        else if (i == lineEnd) {
            codeElement.appendChild(highlighted_code_line_template(lines[index], false, true))
        }
        else if (i > lineStart && i < lineEnd) {
            codeElement.appendChild(highlighted_code_line_template(lines[index], false, false))
        }
        else {
            codeElement.appendChild(code_line_template(lines[index]))
        }
    }

    // Append <code> element to <pre> element
    preElement.appendChild(codeElement);

    // Return <pre> element
    return preElement;
}

function line_template(num) {
    // Create line number div
    var lineNumberDiv = document.createElement('div');
    lineNumberDiv.classList.add('line-number');
    lineNumberDiv.textContent = num + '\n';

    return lineNumberDiv;
}

function highlighted_line_template(num, top, bottom) {
    // Create highlighted line number div
    var highlightedLineNumberDiv = document.createElement('div');
    highlightedLineNumberDiv.classList.add('line-number');

    if (top || bottom) {
        if (top){
            highlightedLineNumberDiv.classList.add('highlighted-top');
        }
        if (bottom) {
            highlightedLineNumberDiv.classList.add('highlighted-bottom');
        }
    }
    else {
        highlightedLineNumberDiv.classList.add('highlighted');
    }
    highlightedLineNumberDiv.textContent = num + '\n';

    return highlightedLineNumberDiv;
}

function buildPagination() {
    // Create pagination div
    var paginationDiv = document.createElement('div');
    paginationDiv.classList.add('pagination');

    var pages = getPageNumbers(MAX_PAGES);
    var currentPage = getCurrentPageNumber();

    if (currentPage > 1) {
        // Create previous page link
        var prevPageLink = document.createElement('a');
        prevPageLink.classList.add('inactivePage', 'page-button');
        prevPageLink.setAttribute('onclick', 'getPreviousPage()');
        var prevPageIcon = document.createElement('i');
        prevPageIcon.classList.add('fas', 'fa-angle-left');
        prevPageLink.appendChild(prevPageIcon);
        paginationDiv.appendChild(prevPageLink);
    }
    // Create pages
    pages.forEach(page => {
        var pageLink;
        if (page == currentPage) {
            pageLink = active_page_link(page);
        } else {
            pageLink = page_link(page);
        }
        paginationDiv.appendChild(pageLink);
    });

    if (currentPage < MAX_PAGES) {
        // Create next page link
        var nextPageLink = document.createElement('a');
        nextPageLink.classList.add('inactivePage', 'page-button');
        nextPageLink.setAttribute('onclick', 'getNextPage()');
        var nextPageIcon = document.createElement('i');
        nextPageIcon.classList.add('fas', 'fa-angle-right');
        nextPageLink.appendChild(nextPageIcon);
        paginationDiv.appendChild(nextPageLink);
    }

    return paginationDiv;
}

function loadMore(groupID) {
    groupID = parseInt(groupID);
    let groupIndex = getIndexById(groupID, pageContents)
    let group = pageContents[groupIndex];
    let groupHTML = document.getElementById(group.id);
    let contexts = groupHTML.querySelector('.results');

    for (let i = 5; i < group.findings.length; i++) {
        buildFinding(group.findings[i], contexts, true);
    }

    let more = contexts.querySelector("#more");
    more.remove();

    contexts.querySelectorAll(".context").forEach(element => {
        if (element.style.display == "none") {
            element.style.display = "";
        }
    });
}
function buildDashboard() {
    let findingsCount = countFindings(RESULTS);
    let highFindingsCount = countHighSeverityFindings(RESULTS);
    let ruleCount = RESULTS.length;

    // Create container div
    var containerDiv = document.createElement('div');
    containerDiv.classList.add('container');

    // Create row div
    var rowDiv = document.createElement('div');
    rowDiv.style.display = 'flex';
    rowDiv.style.flexDirection = 'row';
    rowDiv.style.fontFamily = 'system-ui';

    // Total Findings
    var totalFindingsDiv = document.createElement('div');
    totalFindingsDiv.classList.add('row-item', 'row');
    totalFindingsDiv.textContent = 'Total Findings: ' + findingsCount;
    rowDiv.appendChild(totalFindingsDiv);

    // High Severity Findings
    var highSeverityDiv = document.createElement('div');
    highSeverityDiv.classList.add('row-item', 'row');
    highSeverityDiv.textContent = 'High Severity Findings: ' + highFindingsCount;
    rowDiv.appendChild(highSeverityDiv);

    // Total Rules Found
    var totalRulesDiv = document.createElement('div');
    totalRulesDiv.classList.add('row-item', 'row');
    totalRulesDiv.textContent = 'Total Rules Found: ' + ruleCount;
    rowDiv.appendChild(totalRulesDiv);

    containerDiv.appendChild(rowDiv);

    // Create row empty div
    var rowEmptyDiv = document.createElement('div');
    rowEmptyDiv.classList.add('row-empty');

    // Create col div for dashboard meta row
    var dashboardMetaRowDiv = document.createElement('div');
    dashboardMetaRowDiv.classList.add('col');
    dashboardMetaRowDiv.id = 'dashboard-meta-row';

    // Create row div for charts
    var chartsRowDiv = document.createElement('div');
    chartsRowDiv.classList.add('row');

    // Impact Chart
    var impactChartDiv = document.createElement('div');
    impactChartDiv.classList.add('chart-container');
    impactChartDiv.innerHTML = '<h2>Impact</h2><canvas id="impactChart"></canvas>';
    chartsRowDiv.appendChild(impactChartDiv);

    // Likelihood Chart
    var likelihoodChartDiv = document.createElement('div');
    likelihoodChartDiv.classList.add('chart-container');
    likelihoodChartDiv.innerHTML = '<h2>Likelihood</h2><canvas id="likelihoodChart"></canvas>';
    chartsRowDiv.appendChild(likelihoodChartDiv);

    // Confidence Chart
    var confidenceChartDiv = document.createElement('div');
    confidenceChartDiv.classList.add('chart-container');
    confidenceChartDiv.innerHTML = '<h2>Confidence</h2><canvas id="confidenceChart"></canvas>';
    chartsRowDiv.appendChild(confidenceChartDiv);

    dashboardMetaRowDiv.appendChild(chartsRowDiv);

    // Create row div for charts
    var chartsRowDiv2 = document.createElement('div');
    chartsRowDiv2.classList.add('row');

    // Rule ID Chart
    var ruleIdChartDiv = document.createElement('div');
    ruleIdChartDiv.classList.add('chart-container-rules');
    ruleIdChartDiv.innerHTML = '<h2>Rule ID</h2><div id="ruleIdChart"></div>';
    chartsRowDiv2.appendChild(ruleIdChartDiv);

    // Create row div for charts
    var chartsRowDiv3 = document.createElement('div');
    chartsRowDiv3.classList.add('row');

    // Package Name Chart
    var packageNameChartDiv = document.createElement('div');
    packageNameChartDiv.classList.add('chart-container-packages');
    packageNameChartDiv.innerHTML = '<h2>Packages</h2><div id="packageNameChart"></div>';
    chartsRowDiv3.appendChild(packageNameChartDiv);

    dashboardMetaRowDiv.appendChild(chartsRowDiv2);
    dashboardMetaRowDiv.appendChild(chartsRowDiv3);
    rowEmptyDiv.appendChild(dashboardMetaRowDiv);

    // Rule List
    var ruleListDiv = document.createElement('div');
    ruleListDiv.classList.add('col');
    ruleListDiv.id = 'rule-list';
    ruleListDiv.innerHTML = '<span><h2>Rules</h2></span><hr style="border: none; border-top: 1px solid #000; width: 100%; margin-bottom: 0; margin-top: 0;">';
    rowEmptyDiv.appendChild(ruleListDiv);

    // Package List
    var packageListDiv = document.createElement('div');
    packageListDiv.classList.add('col');
    packageListDiv.id = 'package-list';
    packageListDiv.innerHTML = '<span><h2>Packages</h2></span><hr style="border: none; border-top: 1px solid #000; width: 100%; margin-bottom: 0; margin-top: 0;">';
    rowEmptyDiv.appendChild(packageListDiv);

    containerDiv.appendChild(rowEmptyDiv);

    return containerDiv;
}

function rule_list_item(rule) {
    // Create div for dashboard rule list item
    var ruleListItemDiv = document.createElement('div');
    ruleListItemDiv.classList.add('dashboard-rule-list-item');
    ruleListItemDiv.onclick = function () {
        applyRuleFilter(rule);
    };

    // Create div for rule list item contents
    var ruleListItemContentsDiv = document.createElement('div');
    ruleListItemContentsDiv.classList.add('db-rule-list-item-contents');
    ruleListItemDiv.appendChild(ruleListItemContentsDiv);

    // Rule Name
    var ruleNameSpan = document.createElement('span');
    ruleNameSpan.textContent = rule;
    ruleListItemContentsDiv.appendChild(ruleNameSpan);

    // Right arrow icon
    var rightArrowSpan = document.createElement('span');
    rightArrowSpan.innerHTML = "<i class='fas fa-angle-right'></i>";
    ruleListItemContentsDiv.appendChild(rightArrowSpan);

    return ruleListItemDiv;
}

function package_list_item(package) {
    // Check if branch is empty
    if (package.branch.trim() == '') {
        if (package.site == "github" || package.site == "gitlab") {
            package.branch = 'master';
        }
    }

    // Create div for dashboard rule list item
    var packageListItemDiv = document.createElement('div');
    packageListItemDiv.classList.add('dashboard-rule-list-item');
    packageListItemDiv.onclick = function () {
        applyPackageFilter(package.project);
    };

    // Create div for rule list item contents
    var packageListItemContentsDiv = document.createElement('div');
    packageListItemContentsDiv.classList.add('db-rule-list-item-contents');
    packageListItemDiv.appendChild(packageListItemContentsDiv);

    // Package and Branch
    var packageBranchSpan = document.createElement('span');
    packageBranchSpan.textContent = package.project + ':' + package.branch;
    packageListItemContentsDiv.appendChild(packageBranchSpan);

    // Right arrow icon
    var rightArrowSpan = document.createElement('span');
    rightArrowSpan.innerHTML = "<i class='fas fa-angle-right'></i>";
    packageListItemContentsDiv.appendChild(rightArrowSpan);

    return packageListItemDiv;
}

function empty_page() {
    // Create div for no results found message
    var noResultsDiv = document.createElement('div');
    noResultsDiv.id = 'no-results';
    noResultsDiv.classList.add('no-results');
    noResultsDiv.textContent = 'No results found';

    return noResultsDiv;
}

function page_link(number) {
    // Create anchor tag for page link
    var pageLink = document.createElement('a');
    pageLink.onclick = function () {
        getPage(number);
    };
    pageLink.classList.add('inactivePage', 'page-button');
    pageLink.textContent = number
    return pageLink;
}

function active_page_link(number) {
    // Create anchor tag for active page link
    var activePageLink = document.createElement('a');
    activePageLink.onclick = function () {
        getPage(number);
    };
    activePageLink.classList.add('activePage', 'page-button');
    activePageLink.textContent = number;

    return activePageLink;
}



function generatePackageUrl(packages, file, line, fullFile) {
    let fileOg = file;
    let fileUrl = "";
    try {
        if (packages && packages.length > 0) {
            for (let package of packages) {
                let fileSplit = file.split("/");
                let packageIndex = fileSplit.findIndex(item => item === package.project);
                if (file.includes(package.project) && packageIndex !== -1) {
                    if (package.site == "github") {
                        let branch = package.branch !== "" ? package.branch : "master";
                        file = fileSplit.slice(packageIndex + 1).join("/");
                        fileUrl = `https://github.com/${package.path}/${package.project}/blob/${branch}/${file}#${line}`;
                    }
                    else if (package.site == "gitlab") {
                        let branch = package.branch !== "" ? package.branch : "master";
                        file = fileSplit.slice(packageIndex + 1).join("/");
                        fileUrl = `https://gitlab.com/${package.path}/${package.project}/-/blob/${branch}/${file}#${line}`;
                    }
                    else if (package.site == "unknown") {

                        let lineNumber = line.replace("L", "")
                        let lineSplit = line.split("-")

                        if(lineSplit.length == 2){
                            lineNumber = lineSplit[0].replace("L", "")
                        }

                        fileUrl = `vscode://file/${fullFile}:${lineNumber}`
                    }
                }
                else {
                }
            }
        }
        else {
            //console.log(file)
        }
    } catch (e) {
        console.error(`There was an issue generating package links for filepath ${fileOg} : ${e}`);
    }
    return fileUrl;
}


