// JS-Script (UM): slimbox_scanner.js @ 2025-12-16 17:19:16 +0200
$(function(){if(!/ipod|series60|symbian|windows ce|blackberry/i.test(navigator.userAgent)){$("body").on("click","a[data-slimbox]",function(s){var e=[];var n=-1;$("a[data-slimbox]").each(function(t){var i=$(this).attr("href");if(!i){return}var r=$(this).attr("title");if($(this)[0]===s.currentTarget){n=t}var a=[];a.push(i);a.push(r?r:"");e.push(a)});if(n>=0){return $.slimbox(e,n,{})}})}});
// #END
