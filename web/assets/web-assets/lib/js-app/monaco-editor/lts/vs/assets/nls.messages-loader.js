// JS-Script (UM): nls.messages-loader.js @ 2026-08-30 06:27:03 +0000
define("vs/assets/nls.messages-loader",["exports"],function(e){"use strict";function s(e,s,n,a){const l=a["vs/nls"]?.availableLanguages?.["*"];if(!l||l==="en"){n({})}else{s([`vs/nls.messages.${l}`],()=>{n({})})}}e.load=s;Object.defineProperty(e,Symbol.toStringTag,{value:"Module"})});
// #END
