// JS-Script (US): ifmodalbox_scanner.js @ 2022-04-04 22:54:14 +0000
(()=>{const _p$=console;const $=jQuery;const _Utils$=smartJ$Utils;const _BwUtils$=smartJ$Browser;const _ModalBox$=smartJ$ModalBox;$(()=>{const version=_ModalBox$.getVersion();$("body").on("click","a[data-smart]",el=>{const $el=$(el.currentTarget);const dataSmart=$el.attr("data-smart");if(!dataSmart){return true}const isModal=RegExp(/^open.modal/i).test(dataSmart);const isPopup=RegExp(/^open.popup/i).test(dataSmart);if(isModal!==true&&isPopup!==true){return true}const attrHref=_Utils$.stringPureVal($el.attr("href"),true);if(attrHref==""){_p$.error("iFrmBox Scanner ("+version+")","The Clicked Data-Smart ["+dataSmart+"] Link has no Href Attribute: `"+_Utils$.stringTrim($el.text())+"`");return false}let attrTarget=_Utils$.stringPureVal($el.attr("target"),true);if(attrTarget==""){attrTarget="_blank"}let winWidth=_Utils$.format_number_int(parseInt($(window).width()),false);if(winWidth<200){winWidth=200}let winHeight=parseInt($(window).height());if(winHeight<100){winHeight=100}const aDim=dataSmart.match(/[0-9]+(\.[0-9][0-9]?)?/g);let w=winWidth;let h=winHeight;let u=aDim&&aDim[2]>0?aDim[2]:0;if(aDim){if(aDim[0]>0){if(aDim[0]<1){w=aDim[0]*winWidth}else{w=aDim[0]}}if(aDim[1]>0){if(aDim[1]<1){h=aDim[1]*winHeight}else{h=aDim[1]}}}w=_Utils$.format_number_int(parseInt(w),false);h=_Utils$.format_number_int(parseInt(h),false);u=_Utils$.format_number_int(parseInt(u),false);if(w>winWidth){w=_Utils$.format_number_int(parseInt(winWidth*.9),false)}if(w<200){w=200}if(h>winHeight){h=_Utils$.format_number_int(parseInt(winHeight*.9),false)}if(h<100){h=100}let mode=0;switch(u){case 1:mode=-1;break;default:mode=0}if(isModal===true){_BwUtils$.PopUpLink(attrHref,attrTarget,w,h,mode,1)}else if(isPopup===true){_BwUtils$.PopUpLink(attrHref,attrTarget,w,h,1,1)}return false})})})();
// #END