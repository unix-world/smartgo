// JS-Script (UM): jquery.json-viewer.js @ 2023-12-03 00:04:21 +0000
(function(n){function o(s){return s instanceof Object&&Object.keys(s).length>0}function r(s){var e=/^(ftp|http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?/;return e.test(s)}function c(s){s=s||"";s=String(s);s=s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");return String(s)}function f(s,e){var l="";if(typeof s==="string"){s=c(s);if(e.urlLink&&r(s)){l+='<a href="'+s+'" class="json-string">'+s+"</a>"}else{l+='<span class="json-string">&quot;'+s+"&quot;</span>"}}else if(typeof s==="number"){l+='<span class="json-numeric">'+s+"</span>"}else if(typeof s==="boolean"){l+='<span class="json-boolean">'+s+"</span>"}else if(s===null){l+='<span class="json-null">null</span>'}else if(s instanceof Array){if(s.length>0){l+='[<ol class="json-array">';for(var n=0;n<s.length;++n){l+="<li>";if(o(s[n])){l+='<a href class="json-toggle"></a>'}l+=f(s[n],e);if(n<s.length-1){l+=","}l+="</li>"}l+="</ol>]"}else{l+="[]"}}else if(typeof s==="object"){var t=Object.keys(s).length;if(t>0){l+='{<ul class="json-dict">';for(var i in s){if(s.hasOwnProperty(i)){l+="<li>";var a=e.withQuotes?'<span class="json-key">&quot;'+c(i.replace(/"/g,'\\"'))+"&quot;</span>":'<span class="json-key">'+c(i)+"</span>";if(o(s[i])){l+='<a href class="json-toggle">'+a+"</a>"}else{l+=a}l+=": "+f(s[i],e);if(--t>0){l+=","}l+="</li>"}}l+="</ul>}"}else{l+="{}"}}return l}n.fn.jsonViewer=function(e,l){l=l||{};return this.each(function(){var s=f(e,l);if(o(e)){s='<a href class="json-toggle"></a>'+s}n(this).html(s);n(this).off("click");n(this).on("click","a.json-toggle",function(){var s=n(this).toggleClass("collapsed").siblings("ul.json-dict, ol.json-array");s.toggle();if(s.is(":visible")){s.siblings(".json-placeholder").remove()}else{var e=s.children("li").length;var l=e+(e>1?" fields":" field");s.after('<a href class="json-placeholder">'+l+"</a>")}return false});n(this).on("click","a.json-placeholder",function(){n(this).siblings("a.json-toggle").click();return false});if(l.collapsed===true){n(this).find("a.json-toggle").click()}else if(l.collapsed===-1){n(this).find("a.json-toggle").not(":first").click()}else if(l.collapsed===1){n(this).find("a.json-toggle").first().click()}})}})(jQuery);
// #END