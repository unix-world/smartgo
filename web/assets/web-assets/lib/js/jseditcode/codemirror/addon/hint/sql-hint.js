// JS-Script (UM): sql-hint.js @ 2023-12-03 00:03:52 +0000
(function(r){if(typeof exports=="object"&&typeof module=="object"){r(require("../../lib/codemirror"),require("../../mode/sql/sql"))}else if(typeof define=="function"&&define.amd){define(["../../lib/codemirror","../../mode/sql/sql"],r)}else{r(CodeMirror)}})(function(t){"use strict";var d;var g;var c;var h;var x={QUERY_DIV:";",ALIAS_KEYWORD:"AS"};var m=t.Pos,b=t.cmpPos;function s(r){return Object.prototype.toString.call(r)=="[object Array]"}function v(r){var e=r.doc.modeOption;if(e==="sql"){e="text/x-sql"}return t.resolveMode(e).keywords}function p(r){var e=r.doc.modeOption;if(e==="sql"){e="text/x-sql"}return t.resolveMode(e).identifierQuote||"`"}function a(r){return typeof r=="string"?r:r.text}function o(r,e){if(s(e)){e={columns:e}}if(!e.text){e.text=r}return e}function y(r){var e={};if(s(r)){for(var t=r.length-1;t>=0;t--){var n=r[t];e[a(n).toUpperCase()]=o(a(n),n)}}else if(r){for(var i in r){e[i.toUpperCase()]=o(i,r[i])}}return e}function C(r){return d[r.toUpperCase()]}function A(r){var e={};for(var t in r){if(r.hasOwnProperty(t)){e[t]=r[t]}}return e}function f(r,e){var t=r.length;var n=a(e).substr(0,t);return r.toUpperCase()===n.toUpperCase()}function q(r,e,t,n){if(s(t)){for(var i=0;i<t.length;i++){if(f(e,t[i])){r.push(n(t[i]))}}}else{for(var a in t){if(t.hasOwnProperty(a)){var o=t[a];if(!o||o===true){o=a}else{o=o.displayText?{text:o.text,displayText:o.displayText}:o.text}if(f(e,o)){r.push(n(o))}}}}}function w(r){if(r.charAt(0)=="."){r=r.substr(1)}var e=r.split(h+h);for(var t=0;t<e.length;t++){e[t]=e[t].replace(new RegExp(h,"g"),"")}return e.join(h)}function U(r){var e=a(r).split(".");for(var t=0;t<e.length;t++){e[t]=h+e[t].replace(new RegExp(h,"g"),h+h)+h}var n=e.join(".");if(typeof r=="string"){return n}r=A(r);r.text=n;return r}function j(r,e,t,n){var i=false;var a=[];var o=e.start;var s=true;while(s){s=e.string.charAt(0)==".";i=i||e.string.charAt(0)==h;o=e.start;a.unshift(w(e.string));e=n.getTokenAt(m(r.line,e.start));if(e.string=="."){s=true;e=n.getTokenAt(m(r.line,e.start))}}var f=a.join(".");q(t,f,d,function(r){return i?U(r):r});q(t,f,g,function(r){return i?U(r):r});f=a.pop();var l=a.join(".");var u=false;var c=l;if(!C(l)){var v=l;l=L(l,n);if(l!==v){u=true}}var p=C(l);if(p&&p.columns){p=p.columns}if(p){q(t,f,p,function(r){var e=l;if(u==true){e=c}if(typeof r=="string"){r=e+"."+r}else{r=A(r);r.text=e+"."+r.text}return i?U(r):r})}return o}function O(r,e){var t=r.split(/\s+/);for(var n=0;n<t.length;n++){if(t[n]){e(t[n].replace(/[`,;]/g,""))}}}function L(r,e){var t=e.doc;var n=t.getValue();var i=r.toUpperCase();var a="";var o="";var s=[];var f={start:m(0,0),end:m(e.lastLine(),e.getLineHandle(e.lastLine()).length)};var l=n.indexOf(x.QUERY_DIV);while(l!=-1){s.push(t.posFromIndex(l));l=n.indexOf(x.QUERY_DIV,l+1)}s.unshift(m(0,0));s.push(m(e.lastLine(),e.getLineHandle(e.lastLine()).text.length));var u=null;var c=e.getCursor();for(var v=0;v<s.length;v++){if((u==null||b(c,u)>0)&&b(c,s[v])<=0){f={start:u,end:s[v]};break}u=s[v]}if(f.start){var p=t.getRange(f.start,f.end,false);for(var v=0;v<p.length;v++){var d=p[v];O(d,function(r){var e=r.toUpperCase();if(e===i&&C(a)){o=a}if(e!==x.ALIAS_KEYWORD){a=r}});if(o){break}}}return o}t.registerHelper("hint","sql",function(r,e){d=y(e&&e.tables);var t=e&&e.defaultTable;var n=e&&e.disableKeywords;g=t&&C(t);c=v(r);h=p(r);if(t&&!g){g=L(t,r)}g=g||[];if(g.columns){g=g.columns}var i=r.getCursor();var a=[];var o=r.getTokenAt(i),s,f,l;if(o.end>i.ch){o.end=i.ch;o.string=o.string.slice(0,i.ch-o.start)}if(o.string.match(/^[.`"'\w@][\w$#]*$/g)){l=o.string;s=o.start;f=o.end}else{s=f=i.ch;l=""}if(l.charAt(0)=="."||l.charAt(0)==h){s=j(i,o,a,r)}else{var u=function(r,e){if(typeof r==="object"){r.className=e}else{r={text:r,className:e}}return r};q(a,l,g,function(r){return u(r,"CodeMirror-hint-table CodeMirror-hint-default-table")});q(a,l,d,function(r){return u(r,"CodeMirror-hint-table")});if(!n){q(a,l,c,function(r){return u(r.toUpperCase(),"CodeMirror-hint-keyword")})}}return{list:a,from:m(i.line,s),to:m(i.line,f)}})});
// #END