function download(json) {
    const jsonData = JSON.stringify(json);
    const blob = new Blob([jsonData], { type: 'application/json' });

    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `sitgrep_output-${getCurrentDateTime()}.json`;

    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function exportToJson() {
    let json = { results: []}

    let ruleGroups = seperateFindings(structuredClone(RESULTS))[0];

    ruleGroups.forEach((ruleGroup, index) => {

        let finding = {}
        finding.name = ruleGroup.rule_id.trim();
        finding.findings = ruleGroup.findings
        finding.cwes = ruleGroup.cwe
        finding.wasps = ruleGroup.owasp

        finding.findings.forEach((context, index) => {

            let line = context.start.toString();
            if (context.start != context.end){
                line = `${context.start}-${context.end}`
            }
            context.line = line;
        });

        json.results.push(finding)
    });

    download(json);
}