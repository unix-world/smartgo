// JS-Script (UM): foldcode.js @ 2023-12-03 00:03:56 +0000
(function(e){if(typeof exports=="object"&&typeof module=="object"){e(require("../../lib/codemirror"))}else if(typeof define=="function"&&define.amd){define(["../../lib/codemirror"],e)}else{e(CodeMirror)}})(function(u){"use strict";function t(t,i,e,f){if(e&&e.call){var l=e;e=null}else{var l=s(t,e,"rangeFinder")}if(typeof i=="number"){i=u.Pos(i,0)}var d=s(t,e,"minFoldSize");function n(e){var n=l(t,i);if(!n||n.to.line-n.from.line<d){return null}if(f==="fold"){return n}var o=t.findMarksAt(n.from);for(var r=0;r<o.length;++r){if(o[r].__isFold){if(!e){return null}n.cleared=true;o[r].clear()}}return n}var o=n(true);if(s(t,e,"scanUp")){while(!o&&i.line>t.firstLine()){i=u.Pos(i.line-1,0);o=n(false)}}if(!o||o.cleared||f==="unfold"){return}var r=c(t,e,o);u.on(r,"mousedown",function(e){a.clear();u.e_preventDefault(e)});var a=t.markText(o.from,o.to,{replacedWith:r,clearOnEnter:s(t,e,"clearOnEnter"),__isFold:true});a.on("clear",function(e,n){u.signal(t,"unfold",t,e,n)});u.signal(t,"fold",t,o.from,o.to)}function c(e,n,o){var r=s(e,n,"widget");if(typeof r=="function"){r=r(o.from,o.to)}if(typeof r=="string"){var t=document.createTextNode(r);r=document.createElement("span");r.appendChild(t);r.className="CodeMirror-foldmarker"}else if(r){r=r.cloneNode(true)}return r}u.newFoldFunction=function(o,r){return function(e,n){t(e,n,{rangeFinder:o,widget:r})}};u.defineExtension("foldCode",function(e,n,o){t(this,e,n,o)});u.defineExtension("isFolded",function(e){var n=this.findMarksAt(e);for(var o=0;o<n.length;++o){if(n[o].__isFold){return true}}});u.commands.toggleFold=function(e){e.foldCode(e.getCursor())};u.commands.fold=function(e){e.foldCode(e.getCursor(),null,"fold")};u.commands.unfold=function(e){e.foldCode(e.getCursor(),{scanUp:false},"unfold")};u.commands.foldAll=function(o){o.operation(function(){for(var e=o.firstLine(),n=o.lastLine();e<=n;e++){o.foldCode(u.Pos(e,0),{scanUp:false},"fold")}})};u.commands.unfoldAll=function(o){o.operation(function(){for(var e=o.firstLine(),n=o.lastLine();e<=n;e++){o.foldCode(u.Pos(e,0),{scanUp:false},"unfold")}})};u.registerHelper("fold","combine",function(){var t=Array.prototype.slice.call(arguments,0);return function(e,n){for(var o=0;o<t.length;++o){var r=t[o](e,n);if(r){return r}}}});u.registerHelper("fold","auto",function(e,n){var o=e.getHelpers(n,"fold");for(var r=0;r<o.length;r++){var t=o[r](e,n);if(t){return t}}});var i={rangeFinder:u.fold.auto,widget:"\u2194",minFoldSize:0,scanUp:false,clearOnEnter:true};u.defineOption("foldOptions",null);function s(e,n,o){if(n&&n[o]!==undefined){return n[o]}var r=e.options.foldOptions;if(r&&r[o]!==undefined){return r[o]}return i[o]}u.defineExtension("foldOption",function(e,n){return s(this,e,n)})});
// #END