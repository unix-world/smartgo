// JS-Script (US): jquery.stopwatch.js @ 2022-04-04 22:54:31 +0000
(function($){function incrementer(ct,increment){return function(){ct+=increment;return ct}}function pad2(number){return(number<10?"0":"")+number}function defaultFormatMilliseconds(millis){var x,seconds,minutes,hours;x=millis/1e3;seconds=Math.floor(x%60);x/=60;minutes=Math.floor(x%60);x/=60;hours=Math.floor(x%24);return[pad2(hours),pad2(minutes),pad2(seconds)].join(":")}function formatMilliseconds(millis,data){var formatter;formatter=defaultFormatMilliseconds;formatMilliseconds=function(millis,data){return formatter(millis,data)};return formatMilliseconds(millis,data)}var methods={init:function(options){var defaults={updateInterval:1e3,startTime:0,format:"{HH}:{MM}:{SS}",formatter:formatMilliseconds};return this.each(function(){var $this=$(this),data=$this.data("stopwatch");if(!data){var settings=$.extend({},defaults,options);data=settings;data.active=false;data.target=$this;data.elapsed=settings.startTime;data.incrementer=incrementer(data.startTime,data.updateInterval);data.tick_function=function(){var millis=data.incrementer();data.elapsed=millis;data.target.trigger("tick.stopwatch",[millis]);data.target.stopwatch("render")};$this.data("stopwatch",data)}})},start:function(){return this.each(function(){var $this=$(this),data=$this.data("stopwatch");data.active=true;data.timerID=setInterval(data.tick_function,data.updateInterval);$this.data("stopwatch",data)})},stop:function(){return this.each(function(){var $this=$(this),data=$this.data("stopwatch");clearInterval(data.timerID);data.active=false;$this.data("stopwatch",data)})},destroy:function(){return this.each(function(){var $this=$(this),data=$this.data("stopwatch");$this.stopwatch("stop").unbind(".stopwatch").removeData("stopwatch")})},render:function(){var $this=$(this),data=$this.data("stopwatch");$this.html(data.formatter(data.elapsed,data))},getTime:function(){var $this=$(this),data=$this.data("stopwatch");return data.elapsed},toggle:function(){return this.each(function(){var $this=$(this);var data=$this.data("stopwatch");if(data.active){$this.stopwatch("stop")}else{$this.stopwatch("start")}})},reset:function(){return this.each(function(){var $this=$(this);data=$this.data("stopwatch");data.incrementer=incrementer(data.startTime,data.updateInterval);data.elapsed=data.startTime;$this.data("stopwatch",data)})}};$.fn.stopwatch=function(method){if(methods[method]){return methods[method].apply(this,Array.prototype.slice.call(arguments,1))}else if(typeof method==="object"||!method){return methods.init.apply(this,arguments)}else{$.error("Method "+method+" does not exist on jQuery.stopwatch")}}})(jQuery);
// #END