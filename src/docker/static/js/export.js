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

    let findings = seperateFindings(structuredClone(RESULTS))[0];
    findings.forEach((findingObject, index) => {

        let finding = {}
        finding.id = findingObject.id;
        finding.name = findingObject.rule_id.trim();
        finding.cwes = findingObject.cwe
        finding.wasps = findingObject.owasp

        let line = findingObject.finding.start.toString();
        if (findingObject.finding.start != findingObject.finding.end){
            line = `${findingObject.finding.start}-${findingObject.finding.end}`
        }
        finding.line = line;
        finding.file = findingObject.finding.file;
        finding.context = findingObject.finding.context;

        json.results.push(finding)
    });

    download(json);
}