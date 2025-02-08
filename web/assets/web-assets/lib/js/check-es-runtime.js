// JS-Script (UM): check-es-runtime.js @ 2025-02-07 03:11:52 +0000
(function(){"use strict";var t=function(){try{var t=()=>{const t=Function("const testES6 = new class{constructor(){ let es6Test = true; const Es6Test = () => { return !! es6Test; }; this.Es6Test = Es6Test; }}; return testES6;");if(typeof t!="function"){return"Cannot define ES6 Function"}let n=t();if(typeof t!="function"){return"ES6 Function Class is not accesible"}return n.Es6Test()};return t()}catch(t){return String(t)}};window.checkJsRuntime=t})();
// #END
