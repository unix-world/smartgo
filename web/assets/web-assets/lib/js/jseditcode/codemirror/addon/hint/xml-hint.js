// JS-Script (UM): xml-hint.js @ 2023-12-03 00:03:53 +0000
(function(t){if(typeof exports=="object"&&typeof module=="object"){t(require("../../lib/codemirror"))}else if(typeof define=="function"&&define.amd){define(["../../lib/codemirror"],t)}else{t(CodeMirror)}})(function(H){"use strict";var R=H.Pos;function z(t,e,r){if(r){return t.indexOf(e)>=0}else{return t.lastIndexOf(e,0)==0}}function t(t,e){var r=e&&e.schemaInfo;var n=e&&e.quoteChar||'"';var i=e&&e.matchInMiddle;if(!r){return}var s=t.getCursor(),a=t.getTokenAt(s);if(a.end>s.ch){a.end=s.ch;a.string=a.string.slice(0,s.ch-a.start)}var f=H.innerMode(t.getMode(),a.state);if(!f.mode.xmlCurrentTag){return}var o=[],l=false,u;var g=/\btag\b/.test(a.type)&&!/>$/.test(a.string);var c=g&&/^\w/.test(a.string),h;if(c){var v=t.getLine(s.line).slice(Math.max(0,a.start-2),a.start);var d=/<\/$/.test(v)?"close":/<$/.test(v)?"open":null;if(d){h=a.start-(d=="close"?2:1)}}else if(g&&a.string=="<"){d="open"}else if(g&&a.string=="</"){d="close"}var p=f.mode.xmlCurrentTag(f.state);if(!g&&!p||d){if(c){u=a.string}l=d;var m=f.mode.xmlCurrentContext?f.mode.xmlCurrentContext(f.state):[];var f=m.length&&m[m.length-1];var y=f&&r[f];var x=f?y&&y.children:r["!top"];if(x&&d!="close"){for(var C=0;C<x.length;++C){if(!u||z(x[C],u,i)){o.push("<"+x[C])}}}else if(d!="close"){for(var b in r){if(r.hasOwnProperty(b)&&b!="!top"&&b!="!attrs"&&(!u||z(b,u,i))){o.push("<"+b)}}}if(f&&(!u||d=="close"&&z(f,u,i))){o.push("</"+f+">")}}else{var y=p&&r[p.name],O=y&&y.attrs;var w=r["!attrs"];if(!O&&!w){return}if(!O){O=w}else if(w){var A={};for(var M in w){if(w.hasOwnProperty(M)){A[M]=w[M]}}for(var M in O){if(O.hasOwnProperty(M)){A[M]=O[M]}}O=A}if(a.type=="string"||a.string=="="){var v=t.getRange(R(s.line,Math.max(0,s.ch-60)),R(s.line,a.type=="string"?a.start:a.end));var P=v.match(/([^\s\u00a0=<>\"\']+)=$/),$;if(!P||!O.hasOwnProperty(P[1])||!($=O[P[1]])){return}if(typeof $=="function"){$=$.call(this,t)}if(a.type=="string"){u=a.string;var I=0;if(/['"]/.test(a.string.charAt(0))){n=a.string.charAt(0);u=a.string.slice(1);I++}var T=a.string.length;if(/['"]/.test(a.string.charAt(T-1))){n=a.string.charAt(T-1);u=a.string.substr(I,T-2)}if(I){var j=t.getLine(s.line);if(j.length>a.end&&j.charAt(a.end)==n){a.end++}}l=true}var q=function(t){if(t){for(var e=0;e<t.length;++e){if(!u||z(t[e],u,i)){o.push(n+t[e]+n)}}}return k()};if($&&$.then){return $.then(q)}return q($)}else{if(a.type=="attribute"){u=a.string;l=true}for(var L in O){if(O.hasOwnProperty(L)&&(!u||z(L,u,i))){o.push(L)}}}}function k(){return{list:o,from:l?R(s.line,h==null?a.start:h):s,to:l?R(s.line,a.end):s}}return k()}H.registerHelper("hint","xml",t)});
// #END