// JS-Script (UM): Chart.Core.js @ 2023-12-03 00:04:28 +0000
(function(){"use strict";var t=this,i=t.Chart;var a=function(t){var i=this;this.canvas=t.canvas;this.ctx=t;var e=this.width=t.canvas.width;var n=this.height=t.canvas.height;this.aspectRatio=this.width/this.height;f.retinaScale(this);return this};a.defaults={global:{animation:true,animationSteps:60,animationEasing:"easeOutQuart",showScale:true,scaleOverride:false,scaleSteps:null,scaleStepWidth:null,scaleStartValue:null,scaleLineColor:"rgba(0,0,0,.1)",scaleLineWidth:1,scaleShowLabels:true,scaleLabel:"<%=value%>",scaleIntegersOnly:true,scaleBeginAtZero:false,scaleFontFamily:"inherit",scaleFontSize:12,scaleFontStyle:"normal",scaleFontColor:"#666",responsive:false,maintainAspectRatio:true,showTooltips:true,customTooltips:false,tooltipEvents:["mousemove","touchstart","touchmove","mouseout"],tooltipFillColor:"rgba(0,0,0,0.8)",tooltipFontFamily:"inherit",tooltipFontSize:12,tooltipFontStyle:"normal",tooltipFontColor:"#fff",tooltipTitleFontFamily:"inherit",tooltipTitleFontSize:14,tooltipTitleFontStyle:"bold",tooltipTitleFontColor:"#fff",tooltipYPadding:6,tooltipXPadding:6,tooltipCaretSize:8,tooltipCornerRadius:6,tooltipXOffset:10,tooltipTemplate:"<%if (label){%><%=label%>: <%}%><%= value %>",multiTooltipTemplate:"<%= value %>",multiTooltipKeyBackground:"#fff",onAnimationProgress:function(){},onAnimationComplete:function(){}}};a.types={};var f=a.helpers={};var d=f.each=function(t,i,e){var n=Array.prototype.slice.call(arguments,3);if(t){if(t.length===+t.length){var s;for(s=0;s<t.length;s++){i.apply(e,[t[s],s].concat(n))}}else{for(var o in t){i.apply(e,[t[o],o].concat(n))}}}},o=f.clone=function(e){var n={};d(e,function(t,i){if(e.hasOwnProperty(i)){n[i]=t}});return n},h=f.extend=function(n){d(Array.prototype.slice.call(arguments,1),function(e){d(e,function(t,i){if(e.hasOwnProperty(i)){n[i]=t}})});return n},r=f.merge=function(t,i){var e=Array.prototype.slice.call(arguments,0);e.unshift({});return h.apply(null,e)},p=f.indexOf=function(t,i){if(Array.prototype.indexOf){return t.indexOf(i)}else{for(var e=0;e<t.length;e++){if(t[e]===i){return e}}return-1}},e=f.where=function(t,i){var e=[];f.each(t,function(t){if(i(t)){e.push(t)}});return e},O=f.findNextWhere=function(t,i,e){if(!e){e=-1}for(var n=e+1;n<t.length;n++){var s=t[n];if(i(s)){return s}}},E=f.findPreviousWhere=function(t,i,e){if(!e){e=t.length}for(var n=e-1;n>=0;n--){var s=t[n];if(i(s)){return s}}},s=f.inherits=function(t){var i=this;var e=t&&t.hasOwnProperty("constructor")?t.constructor:function(){return i.apply(this,arguments)};var n=function(){this.constructor=e};n.prototype=i.prototype;e.prototype=new n;e.extend=s;if(t){h(e.prototype,t)}e.__super__=i.prototype;return e},n=f.noop=function(){},l=f.uid=function(){var t=0;return function(){return"chart-"+t++}}(),u=f.warn=function(t){if(window.console&&typeof window.console.warn=="function"){console.warn(t)}},c=f.amd=typeof define=="function"&&define.amd,x=f.isNumber=function(t){return!isNaN(parseFloat(t))&&isFinite(t)},v=f.max=function(t){return Math.max.apply(Math,t)},y=f.min=function(t){return Math.min.apply(Math,t)},B=f.cap=function(t,i,e){if(x(i)){if(t>i){return i}}else if(x(e)){if(t<e){return e}}return t},g=f.getDecimalPlaces=function(t){if(t%1!==0&&x(t)){return t.toString().split(".")[1].length}else{return 0}},m=f.radians=function(t){return t*(Math.PI/180)},H=f.getAngleFromPoint=function(t,i){var e=i.x-t.x,n=i.y-t.y,s=Math.sqrt(e*e+n*n);var o=Math.PI*2+Math.atan2(n,e);if(e<0&&n<0){o+=Math.PI*2}return{angle:o,distance:s}},w=f.aliasPixel=function(t){return t%2===0?0:.5},X=f.splineCurve=function(t,i,e,n){var s=Math.sqrt(Math.pow(i.x-t.x,2)+Math.pow(i.y-t.y,2)),o=Math.sqrt(Math.pow(e.x-i.x,2)+Math.pow(e.y-i.y,2)),a=n*s/(s+o),h=n*o/(s+o);return{inner:{x:i.x-a*(e.x-t.x),y:i.y-a*(e.y-t.y)},outer:{x:i.x+h*(e.x-t.x),y:i.y+h*(e.y-t.y)}}},b=f.calculateOrderOfMagnitude=function(t){return Math.floor(Math.log(t)/Math.LN10)},Y=f.calculateScaleRange=function(t,i,e,n,s){var o=2,a=Math.floor(i/(e*1.5)),h=o>=a;var r=v(t),l=y(t);if(r===l){r+=.5;if(l>=.5&&!n){l-=.5}else{r+=.5}}var u=Math.abs(r-l),c=b(u),f=Math.ceil(r/(1*Math.pow(10,c)))*Math.pow(10,c),d=n?0:Math.floor(l/(1*Math.pow(10,c)))*Math.pow(10,c),p=f-d,g=Math.pow(10,c),x=Math.round(p/g);while((x>a||x*2<a)&&!h){if(x>a){g*=2;x=Math.round(p/g);if(x%1!==0){h=true}}else{if(s&&c>=0){if(g/2%1===0){g/=2;x=Math.round(p/g)}else{break}}else{g/=2;x=Math.round(p/g)}}}if(h){x=o;g=p/x}return{steps:x,stepValue:g,min:d,max:d+x*g}},P=f.template=function(t,i){if(t instanceof Function){return t(i)}var n={};function e(t,i){var e=!/\W/.test(t)?n[t]=n[t]:new Function("obj","var p=[],print=function(){p.push.apply(p,arguments);};"+"with(obj){p.push('"+t.replace(/[\r\t\n]/g," ").split("<%").join("\t").replace(/((^|%>)[^\t]*)'/g,"$1\r").replace(/\t=(.*?)%>/g,"',$1,'").split("\t").join("');").split("%>").join("p.push('").split("\r").join("\\'")+"');}return p.join('');");return i?e(i):e}return e(t,i)},q=f.generateLabels=function(e,t,n,s){var o=new Array(t);if(labelTemplateString){d(o,function(t,i){o[i]=P(e,{value:n+s*(i+1)})})}return o},S=f.easingEffects={linear:function(t){return t},easeInQuad:function(t){return t*t},easeOutQuad:function(t){return-1*t*(t-2)},easeInOutQuad:function(t){if((t/=1/2)<1){return 1/2*t*t}return-1/2*(--t*(t-2)-1)},easeInCubic:function(t){return t*t*t},easeOutCubic:function(t){return 1*((t=t/1-1)*t*t+1)},easeInOutCubic:function(t){if((t/=1/2)<1){return 1/2*t*t*t}return 1/2*((t-=2)*t*t+2)},easeInQuart:function(t){return t*t*t*t},easeOutQuart:function(t){return-1*((t=t/1-1)*t*t*t-1)},easeInOutQuart:function(t){if((t/=1/2)<1){return 1/2*t*t*t*t}return-1/2*((t-=2)*t*t*t-2)},easeInQuint:function(t){return 1*(t/=1)*t*t*t*t},easeOutQuint:function(t){return 1*((t=t/1-1)*t*t*t*t+1)},easeInOutQuint:function(t){if((t/=1/2)<1){return 1/2*t*t*t*t*t}return 1/2*((t-=2)*t*t*t*t+2)},easeInSine:function(t){return-1*Math.cos(t/1*(Math.PI/2))+1},easeOutSine:function(t){return 1*Math.sin(t/1*(Math.PI/2))},easeInOutSine:function(t){return-1/2*(Math.cos(Math.PI*t/1)-1)},easeInExpo:function(t){return t===0?1:1*Math.pow(2,10*(t/1-1))},easeOutExpo:function(t){return t===1?1:1*(-Math.pow(2,-10*t/1)+1)},easeInOutExpo:function(t){if(t===0){return 0}if(t===1){return 1}if((t/=1/2)<1){return 1/2*Math.pow(2,10*(t-1))}return 1/2*(-Math.pow(2,-10*--t)+2)},easeInCirc:function(t){if(t>=1){return t}return-1*(Math.sqrt(1-(t/=1)*t)-1)},easeOutCirc:function(t){return 1*Math.sqrt(1-(t=t/1-1)*t)},easeInOutCirc:function(t){if((t/=1/2)<1){return-1/2*(Math.sqrt(1-t*t)-1)}return 1/2*(Math.sqrt(1-(t-=2)*t)+1)},easeInElastic:function(t){var i=1.70158;var e=0;var n=1;if(t===0){return 0}if((t/=1)==1){return 1}if(!e){e=1*.3}if(n<Math.abs(1)){n=1;i=e/4}else{i=e/(2*Math.PI)*Math.asin(1/n)}return-(n*Math.pow(2,10*(t-=1))*Math.sin((t*1-i)*(2*Math.PI)/e))},easeOutElastic:function(t){var i=1.70158;var e=0;var n=1;if(t===0){return 0}if((t/=1)==1){return 1}if(!e){e=1*.3}if(n<Math.abs(1)){n=1;i=e/4}else{i=e/(2*Math.PI)*Math.asin(1/n)}return n*Math.pow(2,-10*t)*Math.sin((t*1-i)*(2*Math.PI)/e)+1},easeInOutElastic:function(t){var i=1.70158;var e=0;var n=1;if(t===0){return 0}if((t/=1/2)==2){return 1}if(!e){e=1*(.3*1.5)}if(n<Math.abs(1)){n=1;i=e/4}else{i=e/(2*Math.PI)*Math.asin(1/n)}if(t<1){return-.5*(n*Math.pow(2,10*(t-=1))*Math.sin((t*1-i)*(2*Math.PI)/e))}return n*Math.pow(2,-10*(t-=1))*Math.sin((t*1-i)*(2*Math.PI)/e)*.5+1},easeInBack:function(t){var i=1.70158;return 1*(t/=1)*t*((i+1)*t-i)},easeOutBack:function(t){var i=1.70158;return 1*((t=t/1-1)*t*((i+1)*t+i)+1)},easeInOutBack:function(t){var i=1.70158;if((t/=1/2)<1){return 1/2*(t*t*(((i*=1.525)+1)*t-i))}return 1/2*((t-=2)*t*(((i*=1.525)+1)*t+i)+2)},easeInBounce:function(t){return 1-S.easeOutBounce(1-t)},easeOutBounce:function(t){if((t/=1)<1/2.75){return 1*(7.5625*t*t)}else if(t<2/2.75){return 1*(7.5625*(t-=1.5/2.75)*t+.75)}else if(t<2.5/2.75){return 1*(7.5625*(t-=2.25/2.75)*t+.9375)}else{return 1*(7.5625*(t-=2.625/2.75)*t+.984375)}},easeInOutBounce:function(t){if(t<1/2){return S.easeInBounce(t*2)*.5}return S.easeOutBounce(t*2-1)*.5+1*.5}},C=f.requestAnimFrame=function(){return window.requestAnimationFrame||window.webkitRequestAnimationFrame||window.mozRequestAnimationFrame||window.oRequestAnimationFrame||window.msRequestAnimationFrame||function(t){return window.setTimeout(t,1e3/60)}}(),_=f.cancelAnimFrame=function(){return window.cancelAnimationFrame||window.webkitCancelAnimationFrame||window.mozCancelAnimationFrame||window.oCancelAnimationFrame||window.msCancelAnimationFrame||function(t){return window.clearTimeout(t,1e3/60)}}(),Q=f.animationLoop=function(e,n,t,s,o,a){var h=0,r=S[t]||S.linear;var l=function(){h++;var t=h/n;var i=r(t);e.call(a,i,t,h);s.call(a,i,t);if(h<n){a.animationFrame=C(l)}else{o.apply(a)}};C(l)},V=f.getRelativePosition=function(t){var i,e;var n=t.originalEvent||t,s=t.currentTarget||t.srcElement,o=s.getBoundingClientRect();if(n.touches){i=n.touches[0].clientX-o.left;e=n.touches[0].clientY-o.top}else{i=n.clientX-o.left;e=n.clientY-o.top}return{x:i,y:e}},M=f.addEvent=function(t,i,e){if(t.addEventListener){t.addEventListener(i,e)}else if(t.attachEvent){t.attachEvent("on"+i,e)}else{t["on"+i]=e}},L=f.removeEvent=function(t,i,e){if(t.removeEventListener){t.removeEventListener(i,e,false)}else if(t.detachEvent){t.detachEvent("on"+i,e)}else{t["on"+i]=n}},j=f.bindEvents=function(i,t,e){if(!i.events){i.events={}}d(t,function(t){i.events[t]=function(){e.apply(i,arguments)};M(i.chart.canvas,t,i.events[t])})},T=f.unbindEvents=function(e,t){d(t,function(t,i){L(e.chart.canvas,i,t)})},F=f.getMaximumWidth=function(t){var i=t.parentNode;return i.clientWidth},A=f.getMaximumHeight=function(t){var i=t.parentNode;return i.clientHeight},N=f.getMaximumSize=f.getMaximumWidth,R=f.retinaScale=function(t){var i=t.ctx,e=t.canvas.width,n=t.canvas.height;if(window.devicePixelRatio){i.canvas.style.width=e+"px";i.canvas.style.height=n+"px";i.canvas.height=n*window.devicePixelRatio;i.canvas.width=e*window.devicePixelRatio;i.scale(window.devicePixelRatio,window.devicePixelRatio)}},z=f.clear=function(t){t.ctx.clearRect(0,0,t.width,t.height)},k=f.fontString=function(t,i,e){return i+" "+t+"px "+e},I=f.longestText=function(e,t,i){e.font=t;var n=0;d(i,function(t){var i=e.measureText(t).width;n=i>n?i:n});return n},W=f.drawRoundedRectangle=function(t,i,e,n,s,o){t.beginPath();t.moveTo(i+o,e);t.lineTo(i+n-o,e);t.quadraticCurveTo(i+n,e,i+n,e+o);t.lineTo(i+n,e+s-o);t.quadraticCurveTo(i+n,e+s,i+n-o,e+s);t.lineTo(i+o,e+s);t.quadraticCurveTo(i,e+s,i,e+s-o);t.lineTo(i,e+o);t.quadraticCurveTo(i,e,i+o,e);t.closePath()};a.instances={};a.Type=function(t,i,e){this.options=i;this.chart=e;this.id=l();a.instances[this.id]=this;if(i.responsive){this.resize()}this.initialize.call(this,t)};h(a.Type.prototype,{initialize:function(){return this},clear:function(){z(this.chart);return this},stop:function(){f.cancelAnimFrame.call(t,this.animationFrame);return this},resize:function(t){this.stop();var i=this.chart.canvas,e=F(this.chart.canvas),n=this.options.maintainAspectRatio?e/this.chart.aspectRatio:A(this.chart.canvas);i.width=this.chart.width=e;i.height=this.chart.height=n;R(this.chart);if(typeof t==="function"){t.apply(this,Array.prototype.slice.call(arguments,1))}return this},reflow:n,render:function(t){if(t){this.reflow()}if(this.options.animation&&!t){f.animationLoop(this.draw,this.options.animationSteps,this.options.animationEasing,this.options.onAnimationProgress,this.options.onAnimationComplete,this)}else{this.draw();this.options.onAnimationComplete.call(this)}return this},generateLegend:function(){return P(this.options.legendTemplate,this)},destroy:function(){this.clear();T(this,this.events);var t=this.chart.canvas;t.width=this.chart.width;t.height=this.chart.height;if(t.style.removeProperty){t.style.removeProperty("width");t.style.removeProperty("height")}else{t.style.removeAttribute("width");t.style.removeAttribute("height")}delete a.instances[this.id]},showTooltip:function(t,i){if(typeof this.activeElements==="undefined"){this.activeElements=[]}var e=function(t){var e=false;if(t.length!==this.activeElements.length){e=true;return e}d(t,function(t,i){if(t!==this.activeElements[i]){e=true}},this);return e}.call(this,t);if(!e&&!i){return}else{this.activeElements=t}this.draw();if(this.options.customTooltips){this.options.customTooltips(false)}if(t.length>0){if(this.datasets&&this.datasets.length>1){var n,l;for(var s=this.datasets.length-1;s>=0;s--){n=this.datasets[s].points||this.datasets[s].bars||this.datasets[s].segments;l=p(n,t[0]);if(l!==-1){break}}var u=[],c=[],o=function(t){var i=[],e,n=[],s=[],o,a,h,r;f.each(this.datasets,function(t){e=t.points||t.bars||t.segments;if(e[l]&&e[l].hasValue()){i.push(e[l])}});f.each(i,function(t){n.push(t.x);s.push(t.y);u.push(f.template(this.options.multiTooltipTemplate,t));c.push({fill:t._saved.fillColor||t.fillColor,stroke:t._saved.strokeColor||t.strokeColor})},this);r=y(s);a=v(s);h=y(n);o=v(n);return{x:h>this.chart.width/2?h:o,y:(r+a)/2}}.call(this,l);new a.MultiTooltip({x:o.x,y:o.y,xPadding:this.options.tooltipXPadding,yPadding:this.options.tooltipYPadding,xOffset:this.options.tooltipXOffset,fillColor:this.options.tooltipFillColor,textColor:this.options.tooltipFontColor,fontFamily:this.options.tooltipFontFamily,fontStyle:this.options.tooltipFontStyle,fontSize:this.options.tooltipFontSize,titleTextColor:this.options.tooltipTitleFontColor,titleFontFamily:this.options.tooltipTitleFontFamily,titleFontStyle:this.options.tooltipTitleFontStyle,titleFontSize:this.options.tooltipTitleFontSize,cornerRadius:this.options.tooltipCornerRadius,labels:u,legendColors:c,legendColorBackground:this.options.multiTooltipKeyBackground,title:t[0].label,chart:this.chart,ctx:this.chart.ctx,custom:this.options.customTooltips}).draw()}else{d(t,function(t){var i=t.tooltipPosition();new a.Tooltip({x:Math.round(i.x),y:Math.round(i.y),xPadding:this.options.tooltipXPadding,yPadding:this.options.tooltipYPadding,fillColor:this.options.tooltipFillColor,textColor:this.options.tooltipFontColor,fontFamily:this.options.tooltipFontFamily,fontStyle:this.options.tooltipFontStyle,fontSize:this.options.tooltipFontSize,caretHeight:this.options.tooltipCaretSize,cornerRadius:this.options.tooltipCornerRadius,text:P(this.options.tooltipTemplate,t),chart:this.chart,custom:this.options.customTooltips}).draw()},this)}}return this},toBase64Image:function(){return this.chart.canvas.toDataURL.apply(this.chart.canvas,arguments)}});a.Type.extend=function(t){var i=this;var n=function(){return i.apply(this,arguments)};n.prototype=o(i.prototype);h(n.prototype,t);n.extend=a.Type.extend;if(t.name||i.prototype.name){var s=t.name||i.prototype.name;var e=a.defaults[i.prototype.name]?o(a.defaults[i.prototype.name]):{};a.defaults[s]=h(e,t.defaults);a.types[s]=n;a.prototype[s]=function(t,i){var e=r(a.defaults.global,a.defaults[s],i||{});return new n(t,e,this)}}else{u("Name not provided for this chart, so it hasn't been registered")}return i};a.Element=function(t){h(this,t);this.initialize.apply(this,arguments);this.save()};h(a.Element.prototype,{initialize:function(){},restore:function(t){if(!t){h(this,this._saved)}else{d(t,function(t){this[t]=this._saved[t]},this)}return this},save:function(){this._saved=o(this);delete this._saved._saved;return this},update:function(t){d(t,function(t,i){this._saved[i]=this[i];this[i]=t},this);return this},transition:function(t,e){d(t,function(t,i){this[i]=(t-this._saved[i])*e+this._saved[i]},this);return this},tooltipPosition:function(){return{x:this.x,y:this.y}},hasValue:function(){return x(this.value)}});a.Element.extend=s;a.Point=a.Element.extend({display:true,inRange:function(t,i){var e=this.hitDetectionRadius+this.radius;return Math.pow(t-this.x,2)+Math.pow(i-this.y,2)<Math.pow(e,2)},draw:function(){if(this.display){var t=this.ctx;t.beginPath();t.arc(this.x,this.y,this.radius,0,Math.PI*2);t.closePath();t.strokeStyle=this.strokeColor;t.lineWidth=this.strokeWidth;t.fillStyle=this.fillColor;t.fill();t.stroke()}}});a.Arc=a.Element.extend({inRange:function(t,i){var e=f.getAngleFromPoint(this,{x:t,y:i});var n=e.angle>=this.startAngle&&e.angle<=this.endAngle,s=e.distance>=this.innerRadius&&e.distance<=this.outerRadius;return n&&s},tooltipPosition:function(){var t=this.startAngle+(this.endAngle-this.startAngle)/2,i=(this.outerRadius-this.innerRadius)/2+this.innerRadius;return{x:this.x+Math.cos(t)*i,y:this.y+Math.sin(t)*i}},draw:function(t){var i=t||1;var e=this.ctx;e.beginPath();e.arc(this.x,this.y,this.outerRadius,this.startAngle,this.endAngle);e.arc(this.x,this.y,this.innerRadius,this.endAngle,this.startAngle,true);e.closePath();e.strokeStyle=this.strokeColor;e.lineWidth=this.strokeWidth;e.fillStyle=this.fillColor;e.fill();e.lineJoin="bevel";if(this.showStroke){e.stroke()}}});a.Rectangle=a.Element.extend({draw:function(){var t=this.ctx,i=this.width/2,e=this.x-i,n=this.x+i,s=this.base-(this.base-this.y),o=this.strokeWidth/2;if(this.showStroke){e+=o;n-=o;s+=o}t.beginPath();t.fillStyle=this.fillColor;t.strokeStyle=this.strokeColor;t.lineWidth=this.strokeWidth;t.moveTo(e,this.base);t.lineTo(e,s);t.lineTo(n,s);t.lineTo(n,this.base);t.fill();if(this.showStroke){t.stroke()}},height:function(){return this.base-this.y},inRange:function(t,i){return t>=this.x-this.width/2&&t<=this.x+this.width/2&&(i>=this.y&&i<=this.base)}});a.Tooltip=a.Element.extend({draw:function(){var t=this.chart.ctx;t.font=k(this.fontSize,this.fontStyle,this.fontFamily);this.xAlign="center";this.yAlign="above";var i=this.caretPadding=2;var e=t.measureText(this.text).width+2*this.xPadding,n=this.fontSize+2*this.yPadding,s=n+this.caretHeight+i;if(this.x+e/2>this.chart.width){this.xAlign="left"}else if(this.x-e/2<0){this.xAlign="right"}if(this.y-s<0){this.yAlign="below"}var o=this.x-e/2,a=this.y-s;t.fillStyle=this.fillColor;if(this.custom){this.custom(this)}else{switch(this.yAlign){case"above":t.beginPath();t.moveTo(this.x,this.y-i);t.lineTo(this.x+this.caretHeight,this.y-(i+this.caretHeight));t.lineTo(this.x-this.caretHeight,this.y-(i+this.caretHeight));t.closePath();t.fill();break;case"below":a=this.y+i+this.caretHeight;t.beginPath();t.moveTo(this.x,this.y+i);t.lineTo(this.x+this.caretHeight,this.y+i+this.caretHeight);t.lineTo(this.x-this.caretHeight,this.y+i+this.caretHeight);t.closePath();t.fill();break}switch(this.xAlign){case"left":o=this.x-e+(this.cornerRadius+this.caretHeight);break;case"right":o=this.x-(this.cornerRadius+this.caretHeight);break}W(t,o,a,e,n,this.cornerRadius);t.fill();t.fillStyle=this.textColor;t.textAlign="center";t.textBaseline="middle";t.fillText(this.text,o+e/2,a+n/2)}}});a.MultiTooltip=a.Element.extend({initialize:function(){this.font=k(this.fontSize,this.fontStyle,this.fontFamily);this.titleFont=k(this.titleFontSize,this.titleFontStyle,this.titleFontFamily);this.height=this.labels.length*this.fontSize+(this.labels.length-1)*(this.fontSize/2)+this.yPadding*2+this.titleFontSize*1.5;this.ctx.font=this.titleFont;var t=this.ctx.measureText(this.title).width,i=I(this.ctx,this.font,this.labels)+this.fontSize+3,e=v([i,t]);this.width=e+this.xPadding*2;var n=this.height/2;if(this.y-n<0){this.y=n}else if(this.y+n>this.chart.height){this.y=this.chart.height-n}if(this.x>this.chart.width/2){this.x-=this.xOffset+this.width}else{this.x+=this.xOffset}},getLineHeight:function(t){var i=this.y-this.height/2+this.yPadding,e=t-1;if(t===0){return i+this.titleFontSize/2}else{return i+(this.fontSize*1.5*e+this.fontSize/2)+this.titleFontSize*1.5}},draw:function(){if(this.custom){this.custom(this)}else{W(this.ctx,this.x,this.y-this.height/2,this.width,this.height,this.cornerRadius);var e=this.ctx;e.fillStyle=this.fillColor;e.fill();e.closePath();e.textAlign="left";e.textBaseline="middle";e.fillStyle=this.titleTextColor;e.font=this.titleFont;e.fillText(this.title,this.x+this.xPadding,this.getLineHeight(0));e.font=this.font;f.each(this.labels,function(t,i){e.fillStyle=this.textColor;e.fillText(t,this.x+this.xPadding+this.fontSize+3,this.getLineHeight(i+1));e.fillStyle=this.legendColorBackground;e.fillRect(this.x+this.xPadding,this.getLineHeight(i+1)-this.fontSize/2,this.fontSize,this.fontSize);e.fillStyle=this.legendColors[i].fill;e.fillRect(this.x+this.xPadding,this.getLineHeight(i+1)-this.fontSize/2,this.fontSize,this.fontSize)},this)}}});a.Scale=a.Element.extend({initialize:function(){this.fit()},buildYLabels:function(){this.yLabels=[];var t=g(this.stepValue);for(var i=0;i<=this.steps;i++){this.yLabels.push(P(this.templateString,{value:(this.min+i*this.stepValue).toFixed(t)}))}this.yLabelWidth=this.display&&this.showLabels?I(this.ctx,this.font,this.yLabels):0},addXLabel:function(t){this.xLabels.push(t);this.valuesCount++;this.fit()},removeXLabel:function(){this.xLabels.shift();this.valuesCount--;this.fit()},fit:function(){this.startPoint=this.display?this.fontSize:0;this.endPoint=this.display?this.height-this.fontSize*1.5-5:this.height;this.startPoint+=this.padding;this.endPoint-=this.padding;var t=this.endPoint-this.startPoint,i;this.calculateYRange(t);this.buildYLabels();this.calculateXLabelRotation();while(t>this.endPoint-this.startPoint){t=this.endPoint-this.startPoint;i=this.yLabelWidth;this.calculateYRange(t);this.buildYLabels();if(i<this.yLabelWidth){this.calculateXLabelRotation()}}},calculateXLabelRotation:function(){this.ctx.font=this.font;var t=this.ctx.measureText(this.xLabels[0]).width,i=this.ctx.measureText(this.xLabels[this.xLabels.length-1]).width,e,n;this.xScalePaddingRight=i/2+3;this.xScalePaddingLeft=t/2>this.yLabelWidth+10?t/2:this.yLabelWidth+10;this.xLabelRotation=0;if(this.display){var s=I(this.ctx,this.font,this.xLabels),o,a;this.xLabelWidth=s;var h=Math.floor(this.calculateX(1)-this.calculateX(0))-6;while(this.xLabelWidth>h&&this.xLabelRotation===0||this.xLabelWidth>h&&this.xLabelRotation<=90&&this.xLabelRotation>0){o=Math.cos(m(this.xLabelRotation));e=o*t;n=o*i;if(e+this.fontSize/2>this.yLabelWidth+8){this.xScalePaddingLeft=e+this.fontSize/2}this.xScalePaddingRight=this.fontSize/2;this.xLabelRotation++;this.xLabelWidth=o*s}if(this.xLabelRotation>0){this.endPoint-=Math.sin(m(this.xLabelRotation))*s+3}}else{this.xLabelWidth=0;this.xScalePaddingRight=this.padding;this.xScalePaddingLeft=this.padding}},calculateYRange:n,drawingArea:function(){return this.startPoint-this.endPoint},calculateY:function(t){var i=this.drawingArea()/(this.min-this.max);return this.endPoint-i*(t-this.min)},calculateX:function(t){var i=this.xLabelRotation>0,e=this.width-(this.xScalePaddingLeft+this.xScalePaddingRight),n=e/(this.valuesCount-(this.offsetGridLines?0:1)),s=n*t+this.xScalePaddingLeft;if(this.offsetGridLines){s+=n/2}return Math.round(s)},update:function(t){f.extend(this,t);this.fit()},draw:function(){var a=this.ctx,o=(this.endPoint-this.startPoint)/this.steps,h=Math.round(this.xScalePaddingLeft);if(this.display){a.fillStyle=this.textColor;a.font=this.font;d(this.yLabels,function(t,i){var e=this.endPoint-o*i,n=Math.round(e),s=this.showHorizontalLines;a.textAlign="right";a.textBaseline="middle";if(this.showLabels){a.fillText(t,h-10,e)}if(i===0&&!s){s=true}if(s){a.beginPath()}if(i>0){a.lineWidth=this.gridLineWidth;a.strokeStyle=this.gridLineColor}else{a.lineWidth=this.lineWidth;a.strokeStyle=this.lineColor}n+=f.aliasPixel(a.lineWidth);if(s){a.moveTo(h,n);a.lineTo(this.width,n);a.stroke();a.closePath()}a.lineWidth=this.lineWidth;a.strokeStyle=this.lineColor;a.beginPath();a.moveTo(h-5,n);a.lineTo(h,n);a.stroke();a.closePath()},this);d(this.xLabels,function(t,i){var e=this.calculateX(i)+w(this.lineWidth),n=this.calculateX(i-(this.offsetGridLines?.5:0))+w(this.lineWidth),s=this.xLabelRotation>0,o=this.showVerticalLines;if(i===0&&!o){o=true}if(o){a.beginPath()}if(i>0){a.lineWidth=this.gridLineWidth;a.strokeStyle=this.gridLineColor}else{a.lineWidth=this.lineWidth;a.strokeStyle=this.lineColor}if(o){a.moveTo(n,this.endPoint);a.lineTo(n,this.startPoint-3);a.stroke();a.closePath()}a.lineWidth=this.lineWidth;a.strokeStyle=this.lineColor;a.beginPath();a.moveTo(n,this.endPoint);a.lineTo(n,this.endPoint+5);a.stroke();a.closePath();a.save();a.translate(e,s?this.endPoint+12:this.endPoint+8);a.rotate(m(this.xLabelRotation)*-1);a.font=this.font;a.textAlign=s?"right":"center";a.textBaseline=s?"middle":"top";a.fillText(t,0,0);a.restore()},this)}}});a.RadialScale=a.Element.extend({initialize:function(){this.size=y([this.height,this.width]);this.drawingArea=this.display?this.size/2-(this.fontSize/2+this.backdropPaddingY):this.size/2},calculateCenterOffset:function(t){var i=this.drawingArea/(this.max-this.min);return(t-this.min)*i},update:function(){if(!this.lineArc){this.setScaleSize()}else{this.drawingArea=this.display?this.size/2-(this.fontSize/2+this.backdropPaddingY):this.size/2}this.buildYLabels()},buildYLabels:function(){this.yLabels=[];var t=g(this.stepValue);for(var i=0;i<=this.steps;i++){this.yLabels.push(P(this.templateString,{value:(this.min+i*this.stepValue).toFixed(t)}))}},getCircumference:function(){return Math.PI*2/this.valuesCount},setScaleSize:function(){var t=y([this.height/2-this.pointLabelFontSize-5,this.width/2]),i,e,n,s,o=this.width,a,h,r=0,l,u,c,f,d,p,g;this.ctx.font=k(this.pointLabelFontSize,this.pointLabelFontStyle,this.pointLabelFontFamily);for(e=0;e<this.valuesCount;e++){i=this.getPointPosition(e,t);n=this.ctx.measureText(P(this.templateString,{value:this.labels[e]})).width+5;if(e===0||e===this.valuesCount/2){s=n/2;if(i.x+s>o){o=i.x+s;a=e}if(i.x-s<r){r=i.x-s;l=e}}else if(e<this.valuesCount/2){if(i.x+n>o){o=i.x+n;a=e}}else if(e>this.valuesCount/2){if(i.x-n<r){r=i.x-n;l=e}}}c=r;f=Math.ceil(o-this.width);h=this.getIndexAngle(a);u=this.getIndexAngle(l);d=f/Math.sin(h+Math.PI/2);p=c/Math.sin(u+Math.PI/2);d=x(d)?d:0;p=x(p)?p:0;this.drawingArea=t-(p+d)/2;this.setCenterPoint(p,d)},setCenterPoint:function(t,i){var e=this.width-i-this.drawingArea,n=t+this.drawingArea;this.xCenter=(n+e)/2;this.yCenter=this.height/2},getIndexAngle:function(t){var i=Math.PI*2/this.valuesCount;return t*i-Math.PI/2},getPointPosition:function(t,i){var e=this.getIndexAngle(t);return{x:Math.cos(e)*i+this.xCenter,y:Math.sin(e)*i+this.yCenter}},draw:function(){if(this.display){var h=this.ctx;d(this.yLabels,function(t,i){if(i>0){var e=i*(this.drawingArea/this.steps),n=this.yCenter-e,s;if(this.lineWidth>0){h.strokeStyle=this.lineColor;h.lineWidth=this.lineWidth;if(this.lineArc){h.beginPath();h.arc(this.xCenter,this.yCenter,e,0,Math.PI*2);h.closePath();h.stroke()}else{h.beginPath();for(var o=0;o<this.valuesCount;o++){s=this.getPointPosition(o,this.calculateCenterOffset(this.min+i*this.stepValue));if(o===0){h.moveTo(s.x,s.y)}else{h.lineTo(s.x,s.y)}}h.closePath();h.stroke()}}if(this.showLabels){h.font=k(this.fontSize,this.fontStyle,this.fontFamily);if(this.showLabelBackdrop){var a=h.measureText(t).width;h.fillStyle=this.backdropColor;h.fillRect(this.xCenter-a/2-this.backdropPaddingX,n-this.fontSize/2-this.backdropPaddingY,a+this.backdropPaddingX*2,this.fontSize+this.backdropPaddingY*2)}h.textAlign="center";h.textBaseline="middle";h.fillStyle=this.fontColor;h.fillText(t,this.xCenter,n)}}},this);if(!this.lineArc){h.lineWidth=this.angleLineWidth;h.strokeStyle=this.angleLineColor;for(var t=this.valuesCount-1;t>=0;t--){if(this.angleLineWidth>0){var i=this.getPointPosition(t,this.calculateCenterOffset(this.max));h.beginPath();h.moveTo(this.xCenter,this.yCenter);h.lineTo(i.x,i.y);h.stroke();h.closePath()}var e=this.getPointPosition(t,this.calculateCenterOffset(this.max)+5);h.font=k(this.pointLabelFontSize,this.pointLabelFontStyle,this.pointLabelFontFamily);h.fillStyle=this.pointLabelFontColor;var n=this.labels.length,s=this.labels.length/2,o=s/2,a=t<o||t>n-o,r=t===o||t===n-o;if(t===0){h.textAlign="center"}else if(t===s){h.textAlign="center"}else if(t<s){h.textAlign="left"}else{h.textAlign="right"}if(r){h.textBaseline="middle"}else if(a){h.textBaseline="bottom"}else{h.textBaseline="top"}h.fillText(this.labels[t],e.x,e.y)}}}}});f.addEvent(window,"resize",function(){var t;return function(){clearTimeout(t);t=setTimeout(function(){d(a.instances,function(t){if(t.options.responsive){t.resize(t.render,true)}})},50)}}());if(c){define(function(){return a})}else if(typeof module==="object"&&module.exports){module.exports=a}t.Chart=a;a.noConflict=function(){t.Chart=i;return a}}).call(this);
// #END