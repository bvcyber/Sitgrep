function countFindings(results) {
  let count = 0;

  for (let rule of results) {
    count += rule.findings.length;
  }

  return count;
}

function countHighSeverityFindings(results) {
  let count = 0;

  for (let rule of results) {
    if (
      (rule.impact.toLowerCase() == "high" &&
        rule.likelihood.toLowerCase() == "high") ||
      (rule.impact.toLowerCase() == "high" &&
        rule.likelihood.toLowerCase() == "medium") ||
      (rule.impact.toLowerCase() == "medium" &&
        rule.likelihood.toLowerCase() == "high")
    ) {
      count += rule.findings.length;
    }
  }

  return count;
}

function getLanguageByExtension(filePath) {
  const languageMap = {
    sh: "bash",
    bash: "bash",
    c: "c",
    cpp: "cpp",
    cc: "cpp",
    cs: "csharp",
    css: "css",
    diff: "diff",
    go: "go",
    graphql: "graphql",
    ini: "ini",
    java: "java",
    js: "javascript",
    mjs: "javascript",
    json: "json",
    kt: "kotlin",
    less: "less",
    lua: "lua",
    makefile: "makefile",
    md: "markdown",
    m: "objectivec",
    pl: "perl",
    php: "php",
    phtml: "php-template",
    txt: "plaintext",
    py: "python",
    rb: "ruby",
    rs: "rust",
    scss: "scss",
    sql: "sql",
    swift: "swift",
    ts: "typescript",
    tsx: "typescript",
    vb: "vbnet",
    wasm: "wasm",
    xml: "xml",
    yaml: "yaml",
    yml: "yaml",
    html: "html",
    htm: "html",
  };

  const ext = filePath.split(".").pop().toLowerCase();
  return languageMap[ext] || "cs";
}

function isCutValueExists(list, cutValue) {
  return list.some(function (item) {
    return item.full === cutValue;
  });
}

function getFileName() {
  return location.pathname.split("/").pop().split("#")[0];
}

function sha256(message) {
  const shaObj = new jsSHA("SHA-256", "TEXT");
  shaObj.update(message);
  return shaObj.getHash("HEX");
}

function getIndexById(id, list) {
  const normalizedId = String(id).toLowerCase();
  return list.findIndex(
    (item) => String(item.id).toLowerCase() === normalizedId,
  );
}

function getIndexByRuleId(ruleid, list) {
  return list.findIndex((item) => item.rule_id === ruleid);
}

function indexOfDict(dictionary, list) {
  return list.findIndex((item) => {
    return JSON.stringify(item) === JSON.stringify(dictionary);
  });
}

function dictExists(dictionary, list) {
  return list.some((item) => {
    return JSON.stringify(item) === JSON.stringify(dictionary);
  });
}

function resetDisplay() {
  var elementsWithDisplayNone = document.querySelectorAll(
    '[style*="display: none"]',
  );
  elementsWithDisplayNone.forEach((element, index) => {
    element.style.display = "block";
  });
}

function getCurrentDateTime() {
  const currentDate = new Date();
  const year = currentDate.getFullYear();
  const month = (currentDate.getMonth() + 1).toString().padStart(2, "0");
  const day = currentDate.getDate().toString().padStart(2, "0");
  const hours = currentDate.getHours().toString().padStart(2, "0");
  const minutes = currentDate.getMinutes().toString().padStart(2, "0");
  const seconds = currentDate.getSeconds().toString().padStart(2, "0");
  const formattedDateTime = `${year}${month}${day}-${hours}${minutes}${seconds}`;
  return formattedDateTime;
}

function getNextWeekDateTime() {
  const currentDate = new Date();
  return new Date(currentDate.getTime() + 7 * 24 * 60 * 60 * 1000).getTime();
}

function scrollToTop() {
  document
    .getElementById("main-content")
    .scrollTo({ top: 0, behavior: "smooth" });
}

function redirectToRuleGroup(ruleGroupId) {
  return function (event) {
    location.href = `#${ruleGroupId}`;
  };
}

// TODO: Determine if no longer needed
function extractLastPart(text) {
  const parts = text.split(".");
  const lastPart = parts[parts.length - 1];
  return lastPart.trim();
}

function getScrollPosition() {
  return document.getElementById("contentContainer").scrollTop;
}
function setScrollPosition(newPosition) {
  scrollPosition = newPosition;
  document.getElementById("contentContainer").scrollTop = newPosition;
}

function copy_code_block(button) {
  const context = button.parentNode.parentNode.parentNode;
  var code = context.querySelector("code");

  code = code.innerHTML;
  code = code.replace(/<\/?(span|div)(?:\s+[^>]*)?>/g, "");

  navigator.clipboard
    .writeText(code)
    .then(() => {
      showCopiedNotification(button);
    })
    .catch((err) => {
      console.error("Unable to copy:", err);
    });
}

function showCopiedNotification(button) {
  const notification = document.createElement("div");
  notification.textContent = "Copied to clipboard!";
  notification.classList.add("copied-notification");
  const rect = button.getBoundingClientRect();
  notification.style.left = `${rect.left + window.scrollX - 140}px`;
  notification.style.top = `${rect.top + window.scrollY - 50}px`;
  document.body.appendChild(notification);

  setTimeout(() => {
    document.body.removeChild(notification);
  }, 2000);
}
