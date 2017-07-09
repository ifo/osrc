// Load CSS for debugging
var lowerLoc = window.location.search.toLowerCase();
if (lowerLoc.indexOf("cssdebug") !== -1 || lowerLoc.indexOf("cd") !== -1) {
  var head = document.getElementsByTagName("head")[0];
  var debug = document.createElement("link");
  debug.rel = "stylesheet";
  debug.href = "/assets/css/debug.css";
  head.appendChild(debug);
}
