// JS-Script (US): jquery.event.drop.js @ 2022-04-04 22:54:28 +0000
(function($){$.fn.drop=function(str,arg,opts){var type=typeof str=="string"?str:"",fn=$.isFunction(str)?str:$.isFunction(arg)?arg:null;if(type.indexOf("drop")!==0)type="drop"+type;opts=(str==fn?arg:opts)||{};return fn?this.on(type,opts,fn):this.trigger(type)};$.drop=function(opts){opts=opts||{};drop.multi=opts.multi===true?Infinity:opts.multi===false?1:!isNaN(opts.multi)?opts.multi:drop.multi;drop.delay=opts.delay||drop.delay;drop.tolerance=$.isFunction(opts.tolerance)?opts.tolerance:opts.tolerance===null?null:drop.tolerance;drop.mode=opts.mode||drop.mode||"intersect"};var $event=$.event,$special=$event.special,drop=$.event.special.drop={multi:1,delay:20,mode:"overlap",targets:[],datakey:"dropdata",noBubble:true,add:function(obj){var data=$.data(this,drop.datakey);data.related+=1},remove:function(){$.data(this,drop.datakey).related-=1},setup:function(){if($.data(this,drop.datakey))return;var data={related:0,active:[],anyactive:0,winner:0,location:{}};$.data(this,drop.datakey,data);drop.targets.push(this)},teardown:function(){var data=$.data(this,drop.datakey)||{};if(data.related)return;$.removeData(this,drop.datakey);var element=this;drop.targets=$.grep(drop.targets,function(target){return target!==element})},handler:function(event,dd){var results,$targets;if(!dd)return;switch(event.type){case"mousedown":case"touchstart":$targets=$(drop.targets);if(typeof dd.drop=="string")$targets=$targets.filter(dd.drop);$targets.each(function(){var data=$.data(this,drop.datakey);data.active=[];data.anyactive=0;data.winner=0});dd.droppable=$targets;$special.drag.hijack(event,"dropinit",dd);break;case"mousemove":case"touchmove":drop.event=event;if(!drop.timer)drop.tolerate(dd);break;case"mouseup":case"touchend":drop.timer=clearTimeout(drop.timer);if(dd.propagates){$special.drag.hijack(event,"drop",dd);$special.drag.hijack(event,"dropend",dd)}break}},locate:function(elem,index){var data=$.data(elem,drop.datakey),$elem=$(elem),posi=$elem.offset()||{},height=$elem.outerHeight(),width=$elem.outerWidth(),location={elem:elem,width:width,height:height,top:posi.top,left:posi.left,right:posi.left+width,bottom:posi.top+height};if(data){data.location=location;data.index=index;data.elem=elem}return location},contains:function(target,test){return(test[0]||test.left)>=target.left&&(test[0]||test.right)<=target.right&&(test[1]||test.top)>=target.top&&(test[1]||test.bottom)<=target.bottom},modes:{intersect:function(event,proxy,target){return this.contains(target,[event.pageX,event.pageY])?1e9:this.modes.overlap.apply(this,arguments)},overlap:function(event,proxy,target){return Math.max(0,Math.min(target.bottom,proxy.bottom)-Math.max(target.top,proxy.top))*Math.max(0,Math.min(target.right,proxy.right)-Math.max(target.left,proxy.left))},fit:function(event,proxy,target){return this.contains(target,proxy)?1:0},middle:function(event,proxy,target){return this.contains(target,[proxy.left+proxy.width*.5,proxy.top+proxy.height*.5])?1:0}},sort:function(a,b){return b.winner-a.winner||a.index-b.index},tolerate:function(dd){var i,drp,drg,data,arr,len,elem,x=0,ia,end=dd.interactions.length,xy=[drop.event.pageX,drop.event.pageY],tolerance=drop.tolerance||drop.modes[drop.mode];do{if(ia=dd.interactions[x]){if(!ia)return;ia.drop=[];arr=[];len=ia.droppable.length;if(tolerance)drg=drop.locate(ia.proxy);i=0;do{if(elem=ia.droppable[i]){data=$.data(elem,drop.datakey);drp=data.location;if(!drp)continue;data.winner=tolerance?tolerance.call(drop,drop.event,drg,drp):drop.contains(drp,xy)?1:0;arr.push(data)}}while(++i<len);arr.sort(drop.sort);i=0;do{if(data=arr[i]){if(data.winner&&ia.drop.length<drop.multi){if(!data.active[x]&&!data.anyactive){if($special.drag.hijack(drop.event,"dropstart",dd,x,data.elem)[0]!==false){data.active[x]=1;data.anyactive+=1}else data.winner=0}if(data.winner)ia.drop.push(data.elem)}else if(data.active[x]&&data.anyactive==1){$special.drag.hijack(drop.event,"dropend",dd,x,data.elem);data.active[x]=0;data.anyactive-=1}}}while(++i<len)}}while(++x<end);if(drop.last&&xy[0]==drop.last.pageX&&xy[1]==drop.last.pageY)delete drop.timer;else drop.timer=setTimeout(function(){drop.tolerate(dd)},drop.delay);drop.last=drop.event}};$special.dropinit=$special.dropstart=$special.dropend=drop})(jQuery);
// #END