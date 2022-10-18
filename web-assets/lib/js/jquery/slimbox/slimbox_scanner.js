// JS-Script (US): slimbox_scanner.js @ 2022-10-18 14:27:00 +0000
$(function(){if(!/ipod|series60|symbian|windows ce|blackberry/i.test(navigator.userAgent)){$("body").on("click","a[data-slimbox]",function(el){var SFSlimBox__Data=[];var crrIndex=-1;$("a[data-slimbox]").each(function(index){var href=$(this).attr("href");if(!href){return}var title=$(this).attr("title");if($(this)[0]===el.currentTarget){crrIndex=index}var arr=[];arr.push(href);arr.push(title?title:"");SFSlimBox__Data.push(arr)});if(crrIndex>=0){return $.slimbox(SFSlimBox__Data,crrIndex,{})}})}});
// #END
