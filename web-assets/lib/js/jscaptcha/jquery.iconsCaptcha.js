// JS-Script (US): jquery.iconsCaptcha.js @ 2022-04-04 22:54:32 +0000
jQuery.fn.iconsCaptcha||($=>{$.fn.extend({iconsCaptcha:function(options){const _Y$=this;const _p$=console;const defaults={clickDelay:2500,iconsURL:"css/sf-icons.txt",loaderImg:"img/loading-spokes.svg",loaderEImg:"img/sign-crit-warn.svg",hintText:"Select the icon that does not belong in the series ...",doneText:"An icon has already been selected !",fxHandler:(attainment,expr,done,obj)=>{_p$.log("iCaptcha Selection Done",obj,attainment,done)}};const $opts=$.extend(defaults,options);const escapeHtml=text=>{const map={"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"};return String(text.replace(/[&\<\>"]/g,m=>map[m]))};const tags=['<div class="iCaptcha-box" title="'+escapeHtml($opts.hintText)+'">','<div class="iCaptcha-line">','<div class="iCaptcha-icon"></div>','<div class="iCaptcha-icon"></div>','<div class="iCaptcha-icon"></div>','<div class="iCaptcha-icon"></div>','<div class="iCaptcha-icon"></div>','<div class="iCaptcha-icon"></div>',"</div>","</div>"];const getArrRandVal=arr=>{return arr[Math.floor(Math.random()*arr.length)]};let captchaInitialized=false;let captchaRunTime=null;const initCaptcha=(arr,$id,$container)=>{$container.empty();if(typeof arr=="string"){$container.html('<div class="iCaptcha-error"><img src="'+escapeHtml($opts.loaderEImg)+'" alt="ERR" title="'+escapeHtml(String(arr))+'"></div>');_p$.warn("iCaptcha:","initCaptcha:",String(arr));return}if(!Array.isArray(arr)||arr.length<=0){_p$.error("iCaptcha:","initCaptcha:","Invalid Array");return}$container.html(tags.join(""));let i1=getArrRandVal(arr);let i2=null;for(let i=0;i<arr.length;i++){i2=getArrRandVal(arr);if(i2===i1){i2=null}else{break}}if(!i2){_p$.error("iCaptcha Random UID Selection Failed:",$id);return}const numIcns=6;const i3=Math.floor(Math.random()*numIcns);if(i3<0||i3>numIcns-1){_p$.error("iCaptcha Invalid Icon Index:",i3,$id);return}$container.find("div.iCaptcha-icon").each((ix,elm)=>{let icon=null;if(ix===i3){icon=i2}else{icon=i1}if(icon){$(elm).attr("data-icaptcha-idx",ix).data("icaptcha-icn",icon).addClass(String(icon)+" sfi-2x")}})};const selectionDone=($id,$container,$selected)=>{$container.addClass("iCaptcha-overlay");$container.find("div.iCaptcha-box").eq(0).attr("title",$opts.doneText);$container.find("div.iCaptcha-icon").each((index,element)=>{$(element).addClass("iCaptcha-disabled")});$selected.addClass("iCaptcha-selected");const obj={id:$id,"!":0,"&":2,"#":0,"%":3,".":0,"@":4};$container.find("div.iCaptcha-icon").filter((Ix,El)=>{$selected.data("icaptcha-icn")===$(El).data("icaptcha-icn")?obj["."]++:obj["#"]++});obj["!"]=(obj["!"]+Math.random())/10;obj["&"]=(obj["&"]+Math.random())/10;obj["%"]=(obj["%"]+Math.random())/10;obj["#"]=(obj["#"]+Math.random())/10;obj["."]=(obj["."]+Math.random())/10;obj["@"]=(obj["@"]+Math.random())/10;const expr=Math.round(Math.exp(obj["."]));const done=!!(1<=expr&&expr<2);const attainment=expr*(Math.PI/10*3)+Math.random()/10*.7;if(typeof $opts.fxHandler=="function"){$opts.fxHandler(attainment,expr,done,obj)}};let $fX=_Y$.each((idx,el)=>{$(el).empty().html('<div class="iCaptcha-ldr"><center><img src="'+escapeHtml($opts.loaderImg)+'"></center></div>')});captchaRunTime=()=>{captchaInitialized=true;if(!$opts.iconsURL){_p$.error("iCaptcha Empty Icons URL");return}$.get($opts.iconsURL,null,null,"text").done(txt=>{txt=String(txt||"").trim();if(txt.substr(0,8)!=="sfi sfi-"){txt=null}const arr=txt?txt.split("\n"):[];txt=null;$fX=_Y$.each((idx,el)=>{const $container=$(el);const $id=$container.attr("id");if(!$id){_p$.warn("iCaptcha have no ID:",idx);return}if(arr.length<=0){initCaptcha("iCaptcha: FAILED to process the icons list",$id,$container);return}const iTime=new Date;let iconSelected=false;let mOver=false;$container.on("click",".iCaptcha-line > .iCaptcha-icon",evt=>{if(iconSelected){return}if(new Date-iTime<=225){return}if(!mOver){return}const $selected=$(evt.currentTarget);$selected.trigger("mouseenter");let pointEv=evt;if(evt.touches&&evt.touches.length>0){pointEv=evt.touches[0]}let _x=Math.round(pointEv.pageX||-1);let _y=Math.round(pointEv.pageY||-1);if(_x<0){_x=0}if(_y<0){_y=0}_x=Math.round(_x-Math.round($selected.offset().left));_y=Math.round(_y-Math.round($selected.offset().top));if(!_x||!_y){return}iconSelected=true;selectionDone($id,$container,$selected)}).on("mouseenter touchenter touchstart",()=>{if(!mOver){mOver=true}}).on("mouseleave touchleave",()=>{if(mOver){mOver=false}});initCaptcha(arr,$id,$container)})}).fail((data,status)=>{$fX=_Y$.each((idx,el)=>{const $container=$(el);const $id=$container.attr("id");if(!$id){_p$.warn("iCaptcha have no ID:",idx);return}initCaptcha("iCaptcha Failed to get the Icons List: "+String(status),$id,$container)})})};if($opts.clickDelay<0){$(window).on("captcha.iconsCaptcha",()=>{captchaRunTime()})}else{setTimeout(()=>{captchaRunTime()},$opts.clickDelay)}return $fX}})})(jQuery);
// #END