// JS-Script (UM): jquery.table-pagination.js @ 2026-08-30 02:41:24 +0000
(function(z){"use strict";z.fn.createTablePagination=function(t){const n="createTablePagination";const a=1e3;const i={currentPage:1,rowPerPage:10,paginationColor:"#778888",fontColor:"#444444",transitionDuration:0,jumpPage:false};const e=z.extend({},i,t);const o=this;const l=String(o.attr("id").trim()||"");if(l==""){console.error(n,"Table ID is Empty");return}const p=/^[A-Za-z0-9_\-]+$/;if(!p.test(l)){console.warn(n,"Table ID is Invalid");return}const r=z("#"+l);if(z(".pagination-container-"+l).length>0){z("#pagination-"+l).remove();const I=z(".pagination-container-"+l).parent();if(I.children().length>z(".pagination-container-"+l).index()+1){I.children().eq(z(".pagination-container-"+l).index()+1).before(o.clone())}else{I.append(o.clone())}z(".pagination-container-"+l).remove();z("#"+l).find("tr").show()}let s=Math.ceil(e.rowPerPage||0);if(s<1){s=1}let g=String(e.paginationColor||"");let c=String(e.fontColor||"");let d=!!e.jumpPage;let b=Math.ceil(e.transitionDuration||0);let f=r.find("tbody > tr").length;if(f>a){console.warn(n,"Component was Disabled, too many rows, javascript may be too slow ...");return}let u=Math.ceil(f/s);if(s>f){s=f}let h=Math.ceil(e.currentPage||1);if(h<1){h=1}else if(h>u){h=u}let m=r.index();let x=r.width();let v="";if(d!==true){v="justify-content: space-evenly;"}let w=1;let j=[];const y=document.createElement("style");y.setAttribute("id","pagination-"+l);y.textContent=`.page-list-table-`+l+` {
			width: 480px;
			margin-top: 20px;
			display: flex;
			align-items: center;
			font-size: 16px;
			`+v+`
		}
		.table-pagination-pagination-num-`+l+`,
		.table-pagination-prev-btn-`+l+`,
		.table-pagination-next-btn-`+l+`{
			color: `+c+`;
			text-decoration: none;
			height: 20px;
			display: flex;
			align-items: center;
			padding: 6px 10px;
			cursor: pointer;
			user-select: none;
			border-radius: 2px;
		}
		.table-pagination-prev-btn-`+l+`::before,
		.table-pagination-next-btn-`+l+`::after{
			font-weight: bold;
			color: `+g+`;
			white-space: pre;
			font-size: 32px;
			position: relative;
			top: -4px;
		}
		.table-pagination-next-btn-`+l+`::after{
			content: ' ›';
		}
		.table-pagination-prev-btn-`+l+`::before{
			content: '‹ ';
		}
		.more-btn-first-`+l+`,
		.more-btn-last-`+l+`{
			color: `+c+`;
			padding: 5px 2px 5px 3px;
			position: relative;
			left: -1px
		}
		.table-pagination-pagination-num-`+l+`:hover,
		.table-pagination-prev-btn-`+l+`:hover,
		.table-pagination-next-btn-`+l+`:hover{
			background-color: `+g+`2b;
		}
		.table-pagination-pagination-num-`+l+`.active{
			color: #FFFFFF;
			background-color: `+g+`;
		}
		.table-pagination-jump-container-`+l+`{
			display: flex;
			align-items: center;
			height: 100%;
			color:`+c+`;
			padding-left: 10px;
			margin-left: auto;
		}
		.table-pagination-jump-input-`+l+`{
			width: 30px;
			height: 100%;
			margin-right: 5px;
			padding: 6px 5px;
			border: 1px solid `+c+`;
			border-radius: 2px;
			outline: none;
		}
		.table-pagination-jump-input-`+l+`:focus{
			border: 2px solid `+g+`;
		}
		.table-pagination-jump-input-`+l+`::-webkit-outer-spin-button,
		.table-pagination-jump-input-`+l+`::-webkit-inner-spin-button {
			-webkit-appearance: none;
			margin: 0;
		}
		.table-pagination-jump-input-`+l+` {
			-moz-appearance: textfield;
		}
		`;let M=r.parent();if(M.children().length>r.index()+1){M.children().eq(m+1).before('<div class="pagination-container-'+l+'"></div>')}else{M.append('<div class="pagination-container-'+l+'"></div>')}r.detach().appendTo(".pagination-container-"+l);M=r.parent();M.append(y);for(let a=0;a<u;a++){let t=a*s;let n=(a+1)*s;if(n>f){n=f}const T={rowStart:t,rowEnd:n};j[a]=T}r.find("tbody > tr").each(function(){if(z(this).index()>=j[0].rowStart&&z(this).index()<j[0].rowEnd){z(this).show()}else{z(this).hide()}});M.append('<div class="page-list-table-'+l+'"></div>');z(".page-list-table-"+l).append('<a title="Prev" class="table-pagination-prev-btn-'+l+'"></a>');for(let t=0;t<u;t++){z(".page-list-table-"+l).append('<a class="table-pagination-pagination-num-'+l+" table-pagination-pgnum-"+l+"-"+(t+1)+'"  data-page-id="'+(t+1)+'" >'+(t+1)+"</a>")}z(".page-list-table-"+l).append('<a title="Next" class="table-pagination-next-btn-'+l+'"></a>');z(".table-pagination-pagination-num-"+l).eq(0).after('<a class="more-btn-first-'+l+'">..</a>');z(".table-pagination-pagination-num-"+l).eq(-1).before('<a class="more-btn-last-'+l+'">..</a>');if(d===true){z(".page-list-table-"+l).append('<div class="table-pagination-jump-container-'+l+'"><input class="table-pagination-jump-input-'+l+'" type="number" max="'+u+'"> / '+u+"</div>")}let P;if(d===true){P=z(".table-pagination-jump-container-"+l).outerWidth()}else{P=0}const k=x-z(".table-pagination-prev-btn-"+l).outerWidth()-z(".table-pagination-next-btn-"+l).outerWidth()-P;let C=z(".table-pagination-pagination-num-"+l).eq(-1).outerWidth();if(C<1){C=1}let F=Math.floor(k/C);let S=1;let q=u;if(F<u){q=F;F=F-3}const D=function(){if(w===1){S=w;q=F}else if(w===u){q=w;S=w-F+1}else{if(Math.floor(F/2)*2+1>F){S=w-Math.floor(F/2)+1;q=w+Math.floor(F/2)}else{S=w-Math.floor(F/2);q=w+Math.floor(F/2)}}if(S<1){q=q-S+1;S=1;if(q>u){q=u}}if(q>u){S=S-(q-u);q=u;if(S<1){S=1}}z(".table-pagination-pagination-num-"+l).each(function(){if(z(this).attr("data-page-id")>=S&&z(this).attr("data-page-id")<=q){z(this).show()}else{z(this).hide()}});if(S===1){z(".more-btn-first-"+l).hide()}else{z(".table-pagination-pagination-num-"+l+'[data-page-id="1"]').show();z(".more-btn-first-"+l).show()}if(q===u){z(".more-btn-last-"+l).hide()}else{z(".table-pagination-pagination-num-"+l+'[data-page-id="'+u+'"]').show();z(".more-btn-last-"+l).show()}z(".table-pagination-jump-input-"+l).val(w)};D();const E=function(t,n){if(n==="number"){w=Math.floor(t.attr("data-page-id"))}else if(n==="first"){w=1}else if(n==="prev"){if(w>1){w=w-1}}else if(n==="next"){if(w<u){w=w+1}}else if(n==="last"){w=u}else if(n==="jump"){w=parseInt(t.val())}r.find("tbody > tr").each(function(){if(z(this).index()>=j[w-1].rowStart&&z(this).index()<j[w-1].rowEnd){if(b>=250&&b<=500){z(this).fadeIn(b)}else{z(this).show()}}else{z(this).hide()}});z(".page-list-table-"+l).find(".table-pagination-pagination-num-"+l).removeClass("active");z(".table-pagination-pagination-num-"+l+'[data-page-id="'+w+'"]').addClass("active")};z(".table-pagination-pagination-num-"+l+'[data-page-id="1"]').addClass("active");z(".table-pagination-pagination-num-"+l).on("click",function(){E(z(this),"number");D()});z(".table-pagination-prev-btn-"+l).on("click",function(){E(z(this),"prev");D()});z(".table-pagination-next-btn-"+l).on("click",function(){E(z(this),"next");D()});z(".table-pagination-jump-input-"+l).on({change:function(){if(z(this).val()>=1&&z(this).val()<=u){E(z(this),"jump");D()}}});if(h>1){z("a.table-pagination-pgnum-"+l+"-"+h).trigger("click")}}})(jQuery);
// #END
