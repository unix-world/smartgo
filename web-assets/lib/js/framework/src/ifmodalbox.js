// JS-Script (US): ifmodalbox.js @ 2022-04-04 22:54:14 +0000
const smartJ$ModalBox=new class{constructor(){const _N$="smartJ$ModalBox";const VER="r.20210608";const _C$=this;const _p$=console;let SECURED=false;_C$.secureClass=()=>{if(SECURED===true){_p$.warn(_N$,"Class is already SECURED")}else{SECURED=true;Object.freeze(_C$)}};const $=jQuery;const _Option$=typeof smartJ$Options!="undefined"&&smartJ$Options&&typeof smartJ$Options==="object"&&smartJ$Options.ModalBox!=undefined&&typeof smartJ$Options.ModalBox==="object"?smartJ$Options.ModalBox:null;const _Utils$=smartJ$Utils;let iFBoxStatus="";let iFBoxRefreshState=0;let iFBoxRefreshURL="";let iFBoxWidth=200;let iFBoxHeight=100;let iFBoxBeforeUnload=null;const iFBoxPrefix="smart__iFModalBox_";const iFBoxName=iFBoxPrefix+"_iFrame";const iFBoxBackground=iFBoxPrefix+"_Bg";const iFBoxDiv=iFBoxPrefix+"_Div";const iFBoxBtnClose=iFBoxPrefix+"_X";const iFBoxLoader=iFBoxPrefix+"_Ldr";const iFBoxBtnTTlClose="[X]";let param_UseProtection=_Option$&&!!_Option$.UseProtection?1:0;const param_LoaderImg=_Option$&&typeof _Option$.LoaderImg=="string"&&_Option$.LoaderImg?_Utils$.stringTrim(_Option$.LoaderImg):"lib/js/framework/img/loading.svg";const param_LoaderBlank=_Option$&&typeof _Option$.LoaderBlank=="string"&&_Option$.LoaderBlank?_Utils$.stringTrim(_Option$.LoaderBlank):"lib/js/framework/loading.html";const param_CloseImg=_Option$&&typeof _Option$.CloseImg=="string"&&_Option$.CloseImg?_Utils$.stringTrim(_Option$.CloseImg):"lib/js/framework/img/close.svg";const param_CloseAlign=_Option$&&_Option$.CloseAlign==="left"?"left":"right";const param_CloseBtnAltHtml=_Option$&&typeof _Option$.CloseBtnAltHtml=="string"&&_Option$.CloseBtnAltHtml?_Utils$.stringTrim(_Option$.CloseBtnAltHtml):"";const param_vAlign=_Option$&&typeof _Option$.vAlign=="string"&&(_Option$.vAlign=="middle"||_Option$.vAlign=="center")?String(_Option$.vAlign):"top";const param_DelayOpen=_Option$&&typeof _Option$.DelayOpen=="number"&&_Option$.DelayOpen&&_Utils$.isFiniteNumber(_Option$.DelayOpen)?_Utils$.format_number_int(_Option$.DelayOpen,false):850;const param_DelayClose=_Option$&&typeof _Option$.DelayClose=="number"&&_Option$.DelayClose&&_Utils$.isFiniteNumber(_Option$.DelayClose)?_Utils$.format_number_int(_Option$.DelayClose,false):500;const param_CssOverlayBgColor=_Option$&&typeof _Option$.CssOverlayBgColor=="string"&&_Option$.CssOverlayBgColor&&String(_Option$.CssOverlayBgColor).match(/^\#([0-9a-f]{6})$/i)?_Utils$.stringTrim(_Option$.CssOverlayBgColor):"#333333";const param_CssOverlayOpacity=_Option$&&typeof _Option$.CssOverlayOpacity=="number"&&_Utils$.isFiniteNumber(_Option$.CssOverlayOpacity)&&_Utils$.format_number_float(_Option$.CssOverlayOpacity,false)>=0&&_Utils$.format_number_float(_Option$.CssOverlayOpacity,false)<=1?_Utils$.format_number_dec(_Option$.CssOverlayOpacity,2,false,true):.85;const getName=()=>{return String(iFBoxName)};_C$.getName=getName;const getStatus=()=>{return String(iFBoxStatus)};_C$.getStatus=getStatus;const getVersion=()=>{return String(VER)};_C$.getVersion=getVersion;const setRefreshParent=(state,yURL)=>{yURL=_Utils$.stringPureVal(yURL,true);if(!!state){iFBoxRefreshState=1;iFBoxRefreshURL=String(yURL)}else{iFBoxRefreshState=0;iFBoxRefreshURL=""}};_C$.setRefreshParent=setRefreshParent;const setHandlerOnBeforeUnload=fx=>{if(typeof fx==="function"){iFBoxBeforeUnload=fx;return true}_p$.error(_N$,"ERR: setHandlerOnBeforeUnload","fx is not a function");return false};_C$.setHandlerOnBeforeUnload=setHandlerOnBeforeUnload;const LoadURL=function(yURL,yProtect=null,windowWidth=0,windowHeight=0){yURL=_Utils$.stringPureVal(yURL,true);iFBoxStatus="visible";if(yProtect!==null){param_UseProtection=yProtect?1:0}iFBoxWidth=_Utils$.format_number_int(parseInt(windowWidth),false);iFBoxHeight=_Utils$.format_number_int(parseInt(windowHeight),false);$("body").css({overflow:"hidden"});$("#"+iFBoxLoader).empty();if(param_LoaderImg){$("#"+iFBoxLoader).html('<br><br><img src="'+_Utils$.escape_html(param_LoaderImg)+'" alt="..." title="...">')}executePositioning(param_UseProtection,iFBoxWidth,iFBoxHeight);const UrlTime=(new Date).getTime();if(yURL.indexOf("?")!=-1){yURL+="&"}else{yURL+="?"}yURL+=String(iFBoxName+"="+_Utils$.escape_url(UrlTime));$("#"+iFBoxName).show().css({width:"100%",height:"100%",visibility:"hidden"}).attr("src",String(yURL));let the_closebtn;if(param_CloseBtnAltHtml===""){the_closebtn='<img id="ifrm-close" src="'+_Utils$.escape_html(param_CloseImg)+'" alt="'+_Utils$.escape_html(iFBoxBtnTTlClose)+'" title="'+_Utils$.escape_html(iFBoxBtnTTlClose)+'">'}else{the_closebtn=String(param_CloseBtnAltHtml)}let the_align_left="auto";let the_align_right="auto";if(param_CloseAlign==="left"){the_align_left="-20px"}else{the_align_right="-20px"}$("#"+iFBoxBtnClose).show().css({position:"absolute","z-index":2111111099,cursor:"pointer",top:"-12px",left:the_align_left,right:the_align_right,"min-width":"32px","max-width":"64px","min-height":"32px","max-height":"64px",visibility:"hidden"}).empty().html(the_closebtn).click(()=>{UnloadURL()});if(!yProtect){$("#"+iFBoxBackground).click(()=>{UnloadURL()})}else{$("#"+iFBoxBackground).unbind("click")}let openDelay=_Utils$.format_number_int(param_DelayOpen,false);if(openDelay<500){openDelay=500}if(openDelay>1e3){openDelay=1e3}setTimeout(()=>{makeVisible()},openDelay);return false};_C$.LoadURL=LoadURL;const UnloadURL=function(){let test_unload=true;try{test_unload=!!getHandlerOnBeforeUnload()}catch(err){_p$.error(_N$,"ERR: UnloadURL",err);test_unload=true}if(!test_unload){return false}executeUnload();let closeDelay=_Utils$.format_number_int(param_DelayClose,false);if(closeDelay<250){closeDelay=250}if(closeDelay>750){closeDelay=750}setTimeout(()=>{initialize()},closeDelay);return false};_C$.UnloadURL=UnloadURL;const initialize=function(){$("#"+iFBoxDiv).css({position:"absolute",width:"1px",height:"1px",left:"0px",top:"0px"}).hide();$("#"+iFBoxBackground).css({position:"absolute",width:"1px",height:"1px",left:"0px",top:"0px"}).hide();if(iFBoxRefreshState){const url=_Utils$.stringTrim(iFBoxRefreshURL);if(url==""){self.location=self.location}else{self.location=String(url)}iFBoxRefreshState=0;iFBoxRefreshURL=""}return false};const makeVisible=()=>{$("#"+iFBoxBtnClose).css({visibility:"visible"});$("#"+iFBoxName).css({"background-color":"#FFFFFF",visibility:"visible"});$("#"+iFBoxLoader).empty().html("");return false};const getHandlerOnBeforeUnload=()=>{if(typeof iFBoxBeforeUnload==="function"){return!!iFBoxBeforeUnload()}return true};const getWindowWidth=windowWidth=>{windowWidth=_Utils$.format_number_int(parseInt(windowWidth),false);if(windowWidth<=0){windowWidth=_Utils$.format_number_int(parseInt($(window).width())-40,false)}if(windowWidth<200){windowWidth=200}return windowWidth};const getWindowHeight=windowHeight=>{windowHeight=_Utils$.format_number_int(parseInt(windowHeight),false);if(windowHeight<=0){windowHeight=_Utils$.format_number_int(parseInt($(window).height())-20,false)}if(windowHeight<100){windowHeight=100}return windowHeight};const executeUnload=function(){$("#"+iFBoxBackground).unbind("click");$("#"+iFBoxBtnClose).unbind("click");$("#"+iFBoxLoader).empty().html("");let the_align_left="auto";let the_align_right="auto";if(param_CloseAlign==="left"){the_align_left="0px"}else{the_align_right="0px"}$("#"+iFBoxBtnClose).css({position:"absolute",width:"1px",height:"1px",left:the_align_left,right:the_align_right,top:"0px"}).empty().html("").hide();$("#"+iFBoxName).css({width:"1px",height:"1px"});if(param_LoaderBlank){$("#"+iFBoxName).attr("src",_Utils$.escape_html(param_LoaderBlank))}$("#"+iFBoxName).attr("src","").hide();$("#"+iFBoxDiv).css({position:"absolute",width:"1px",height:"1px",left:"0px",top:"0px"}).hide();$("body").css({overflow:"auto"});iFBoxStatus="";return false};const calculatePosition=function(windowWidth,windowHeight){let the_h_align=_Utils$.format_number_int(parseInt($(window).scrollLeft())+(parseInt($(window).width())-windowWidth)/2)+"px";let the_v_align=_Utils$.format_number_int(parseInt($(window).scrollTop())+10)+"px";if(param_vAlign==="center"||param_vAlign==="middle"){the_v_align=_Utils$.format_number_int(parseInt($(window).scrollTop())+(parseInt($(window).height())-windowHeight)/2)+"px"}$("#"+iFBoxDiv).css({position:"absolute","z-index":2111111098,"text-align":"center",left:the_h_align,top:the_v_align,width:windowWidth+"px",height:windowHeight+"px"}).show()};const executePositioning=function(yProtect,windowWidth,windowHeight){let the_wWidth=getWindowWidth(windowWidth);let the_wHeight=getWindowHeight(windowHeight);const the_wRealWidth=getWindowWidth(0);if(the_wRealWidth<windowWidth){the_wWidth=the_wRealWidth}const the_wRealHeight=getWindowHeight(0);if(the_wRealHeight<windowHeight){the_wHeight=the_wRealHeight}let the_style_cursor="auto";if(yProtect!=1){the_style_cursor="pointer"}$("#"+iFBoxBackground).css({position:"fixed","z-index":2111111097,cursor:the_style_cursor,"text-align":"center",left:"0px",top:"0px",width:"100%",height:"100%"}).show();calculatePosition(the_wWidth,the_wHeight);return false};$(()=>{$("body").append('\x3c!-- SmartJS.Modal.Loader :: Start --\x3e<div id="'+_Utils$.escape_html(iFBoxBackground)+'" data-info-smartframework="SmartFramework.Js.ModalBox: '+_Utils$.escape_html(VER)+'" style="background-color:'+_Utils$.escape_html(param_CssOverlayBgColor)+"; position:absolute; top:0px; left:0px; width:1px; height:1px; opacity: "+_Utils$.escape_html(_Utils$.format_number_dec(param_CssOverlayOpacity,2,false,true))+';"></div><div id="'+_Utils$.escape_html(iFBoxDiv)+'" style="position:absolute; top:0px; left:0px; width:1px; height:1px;"><center><div id="'+_Utils$.escape_html(iFBoxLoader)+'"></div></center><div id="'+_Utils$.escape_html(iFBoxBtnClose)+'" title="[X]"></div><iframe name="'+_Utils$.escape_html(iFBoxName)+'" id="'+_Utils$.escape_html(iFBoxName)+'" width="1" height="1" scrolling="auto" src="" marginwidth="5" marginheight="5" hspace="0" vspace="0" frameborder="0"></iframe></div>\x3c!-- END: SmartJS.Modal.Loader --\x3e');initialize();$(window).on("resize scroll",ev=>{if(getStatus()==="visible"){executePositioning(param_UseProtection,iFBoxWidth,iFBoxHeight)}})})}};smartJ$ModalBox.secureClass();window.smartJ$ModalBox=smartJ$ModalBox;
// #END