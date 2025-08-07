const sitgrepResults = structuredClone(sitgrep_results["results"]);

function createPieChart(chartId, data, labels) {
  const ctx = document.getElementById(chartId).getContext('2d');

  new Chart(ctx, {
    type: 'pie',
    data: {
      labels: labels,
      datasets: [{
        data: data,
        backgroundColor: generateColors(data.length),
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false
    }
  });
}

function createBarGraph(chartId, data, type) {
  var colors = generateColors(data.length);
  var chart = new ej.charts.Chart({
    tooltip: { enable: true},
    //Initializing Primary X Axis
    primaryXAxis: {
      valueType: "Category",
      title: "",
      labelStyle: {
        color: 'white',
        size: '12px',
        fontFamily:'Arial',
      }
    },

    //Initializing Primary Y Axis
    primaryYAxis: {
      title: "Number of findings",
      titleStyle: {
        color: '#BBBBBB',
        fontFamily:'Arial',
      },
      majorGridLines: {
        width: 0
      },
      labelStyle: {
        color: 'white',
        size:'12px',
        fontFamily:'Arial',
      }
    },
    background: 'transparent',
    chartArea: {
      //width: '60%'
    },
    //Initializing Chart Series
    series: [
      {
        type: "Bar",
        dataSource: data,
        xName: type,
        yName: "findings",
        marker: { 
          dataLabel: { 
              visible: true,
              position: 'Top',
              font: { 
                fontWeight: '600', 
                color: 'white',
                size:'12px',
                fontFamily:'Arial',
                fontStyle: 'Normal' 
              }
          } 
        },
        pointColorMapping: 'color',
      },
      
    ],
    pointRender: (args) => {
      args.fill = colors[args.point.index];
  },
   
  });
  
  chart.appendTo(`#${chartId}`);

}
const confidenceData = getConfidenceData();
const impactData = getImpactData();
const likelihoodData = getLikelihoodData();
const ruleIdData = getRuleIdData();
const packageNameData = getPackageData();


function getImpactData() {

  let data = {
    high: 0,
    medium: 0,
    low: 0
  };

  sitgrepResults.forEach(element => {
    data[element.impact.toString().toLowerCase()] += element.findings.length;
  });
  return [data.high, data.medium, data.low]

}

function getRuleIdData() {

  let result = []
  
  sitgrepResults.forEach(element => {
    let data = {};
    data["rule"] = element.rule_id.toString().trim();
    data["findings"] = element.findings.length;
    result.push(data)
  });

  return result;
}

function getPackageData() {

  let result = []
  let tempData = {};
  sitgrepResults.forEach(group => {
    group.findings.forEach(finding => {
      for (let obj of packageList) {
        if (finding.package == obj.project) {
          if (tempData.hasOwnProperty(obj.project)){
            tempData[obj.project] += 1;
          }
          else {
            tempData[obj.project] = 1;
          }
       
        }
      }
    });
  });
  for(var key in tempData){
    result.push({"package": key, "findings": tempData[key]})
  }
  return result;
}

function getConfidenceData() {

  let data = {
    high: 0,
    medium: 0,
    low: 0
  };

  sitgrepResults.forEach(element => {
    data[element.confidence.toString().toLowerCase()] += element.findings.length;
  });
  return [data.high, data.medium, data.low]
}

function getLikelihoodData() {

  let data = {
    high: 0,
    medium: 0,
    low: 0
  };

  sitgrepResults.forEach(element => {
    data[element.likelihood.toString().toLowerCase()] += element.findings.length;
  });
  return [data.high, data.medium , data.low ]
}


function generateColors(numColors) {
  const colors = [];
  const goldenRatioConjugate = 0.618033988749895;
  let hue = Math.random();

  for (let i = 0; i < numColors; i++) {
    hue += goldenRatioConjugate;
    hue %= 1;
    const color = hslToHex(hue * 360, 50, 50);
    colors.push(color);
  }

  return colors;
}

function hslToHex(h, s, l) {
  h /= 360;
  s /= 100;
  l /= 100;
  let r, g, b;
  if (s === 0) {
    r = g = b = l;
  } else {
    const hue2rgb = (p, q, t) => {
      if (t < 0) t += 1;
      if (t > 1) t -= 1;
      if (t < 1 / 6) return p + (q - p) * 6 * t;
      if (t < 1 / 2) return q;
      if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
      return p;
    };
    const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
    const p = 2 * l - q;
    r = hue2rgb(p, q, h + 1 / 3);
    g = hue2rgb(p, q, h);
    b = hue2rgb(p, q, h - 1 / 3);
  }
  const toHex = (x) => {
    const hex = Math.round(x * 255).toString(16);
    return hex.length === 1 ? '0' + hex : hex;
  };
  return '#' + toHex(r) + toHex(g) + toHex(b);
}


