
// jQuery Table Pagination
// r.20260814.2358
// (c) 2026-present unix-world.org
// License: BSD


(function($) {
'use strict';

	$.fn.createTablePagination = function(options) {

		const _N$ = 'createTablePagination';

		const maxAllowedRows = 1000; // {{{SYNC-MAX-ROWS-JQUERY-TABLE-PAGINATION}}}

		const defaults = {
			currentPage: 1,
			rowPerPage: 10,
			paginationColor: '#778888',
			fontColor: '#444444',
			transitionDuration: 0, // to use fadeIn, set this 250..500
			jumpPage: false,
		};

		const settings = $.extend({}, defaults, options);

		const _C$ = this; // self referencing

		const tblId = String(_C$.attr('id').trim() || '');
		if(tblId == '') {
			console.error(_N$, 'Table ID is Empty');
			return;
		}
		const regexId = /^[A-Za-z0-9_\-]+$/
		if(!regexId.test(tblId)) { // allow just `A-Z a-z 0-9 _ -` because other characters will conflict with the class style logic below, it appends `tblId` to the css classes !
			console.warn(_N$, 'Table ID is Invalid');
			return;
		}

		const $table = $('#' + tblId);
		if($('.pagination-container-' + tblId).length > 0) {
			$('#pagination-' + tblId).remove();

			const $paginationParentContainer = $('.pagination-container-' + tblId).parent();

			if($paginationParentContainer.children().length > $('.pagination-container-' + tblId).index() + 1) {
				$paginationParentContainer.children().eq($('.pagination-container-' + tblId).index() + 1).before(_C$.clone());
			} else {
				$paginationParentContainer.append(_C$.clone());
			}
			$('.pagination-container-' + tblId).remove();
			$('#' + tblId).find('tr').show();
		}

		let rowPerPage = Math.ceil(settings.rowPerPage || 0);
		if(rowPerPage < 1) {
			rowPerPage = 1;
		}
		let paginationColor = String(settings.paginationColor || '');
		let fontColor = String(settings.fontColor || '');
		let jumpPage = !! settings.jumpPage;
		let transitionDurationMilliSec = Math.ceil(settings.transitionDuration || 0);

		let totalRows = $table.find('tbody > tr').length;
		if(totalRows > maxAllowedRows) {
			console.warn(_N$, 'Component was Disabled, too many rows, javascript may be too slow ...');
			return;
		}

		let totalPages = Math.ceil(totalRows / rowPerPage);
		if(rowPerPage > totalRows) {
			rowPerPage = totalRows; // unixman: fix value instead of raise error
		}

		let crrPage = Math.ceil(settings.currentPage || 1);
		if(crrPage < 1) {
			crrPage = 1;
		} else if(crrPage > totalPages) {
			crrPage = totalPages;
		}

		let tblIndex = $table.index();
		let tblWidth = $table.width();

		let $alignPagination = '';
		if(jumpPage !== true) {
			$alignPagination = 'justify-content: space-evenly;';
		}

		let crrActivePage = 1;
		let $pageDisplay = [];

		//create style for pagination
		const style = document.createElement('style');
		style.setAttribute('id', 'pagination-' + tblId);
		//apply styling to pagination
		style.textContent = `.page-list-table-` + tblId + ` {
			width: 480px;
			margin-top: 20px;
			display: flex;
			align-items: center;
			font-size: 16px;
			` + $alignPagination + `
		}
		.table-pagination-pagination-num-` + tblId + `,
		.table-pagination-prev-btn-` + tblId + `,
		.table-pagination-next-btn-` + tblId + `{
			color: ` + fontColor + `;
			text-decoration: none;
			height: 20px;
			display: flex;
			align-items: center;
			padding: 6px 10px;
			cursor: pointer;
			user-select: none;
			border-radius: 2px;
		}
		.table-pagination-prev-btn-` + tblId + `::before,
		.table-pagination-next-btn-` + tblId + `::after{
			font-weight: bold;
			color: ` + paginationColor + `;
			white-space: pre;
			font-size: 32px;
			position: relative;
			top: -4px;
		}
		.table-pagination-next-btn-` + tblId + `::after{
			content: ' ›';
		}
		.table-pagination-prev-btn-` + tblId + `::before{
			content: '‹ ';
		}
		.more-btn-first-` + tblId + `,
		.more-btn-last-` + tblId + `{
			color: ` + fontColor + `;
			padding: 5px 2px 5px 3px;
			position: relative;
			left: -1px
		}
		.table-pagination-pagination-num-` + tblId + `:hover,
		.table-pagination-prev-btn-` + tblId + `:hover,
		.table-pagination-next-btn-` + tblId + `:hover{
			background-color: ` + paginationColor + `2b;
		}
		.table-pagination-pagination-num-` + tblId + `.active{
			color: #FFFFFF;
			background-color: ` + paginationColor + `;
		}
		.table-pagination-jump-container-` + tblId + `{
			display: flex;
			align-items: center;
			height: 100%;
			color:` + fontColor + `;
			padding-left: 10px;
			margin-left: auto;
		}
		.table-pagination-jump-input-` + tblId + `{
			width: 30px;
			height: 100%;
			margin-right: 5px;
			padding: 6px 5px;
			border: 1px solid ` + fontColor + `;
			border-radius: 2px;
			outline: none;
		}
		.table-pagination-jump-input-` + tblId + `:focus{
			border: 2px solid ` + paginationColor + `;
		}
		.table-pagination-jump-input-` + tblId + `::-webkit-outer-spin-button,
		.table-pagination-jump-input-` + tblId + `::-webkit-inner-spin-button {
			-webkit-appearance: none;
			margin: 0;
		}
		.table-pagination-jump-input-` + tblId + ` {
			-moz-appearance: textfield;
		}
		`;
	//	document.head.appendChild(style); // unixman
		let $parentContainer = $table.parent();
		if($parentContainer.children().length > $table.index() + 1) {
			$parentContainer.children().eq(tblIndex + 1).before('<div class="pagination-container-' + tblId + '"></div>');
		} else {
			$parentContainer.append('<div class="pagination-container-' + tblId + '"></div>');
		}
		$table.detach().appendTo('.pagination-container-' + tblId);
		$parentContainer = $table.parent();
		$parentContainer.append(style); // unixman

		//assign the Row Start and Row End for each page.
		for(let i = 0; i < totalPages; i++) {
			let $rowStart = (i * rowPerPage);
			let $rowEnd = ((i + 1) * rowPerPage);
			if($rowEnd > totalRows) {
				$rowEnd = totalRows;
			}
			const $pageDisplayObject = {
				rowStart: $rowStart,
				rowEnd: $rowEnd,
			};
			$pageDisplay[i] = $pageDisplayObject;
		}

		$table.find('tbody > tr').each(function() {
			if($(this).index() >= $pageDisplay[0].rowStart && $(this).index() < $pageDisplay[0].rowEnd) {
				$(this).show();
			} else {
				$(this).hide();
			}
		});

		//create pagination
		$parentContainer.append('<div class="page-list-table-' + tblId + '"></div>');
		$('.page-list-table-' + tblId).append('<a title="Prev" class="table-pagination-prev-btn-' + tblId + '"></a>');

		for(let i = 0; i < totalPages; i++) {
			$('.page-list-table-' + tblId).append('<a class="table-pagination-pagination-num-' + tblId + ' table-pagination-pgnum-' + tblId + '-' + (i + 1) + '"  data-page-id="' + (i + 1) + '" >' + (i + 1) + '</a>');
		}
		$('.page-list-table-' + tblId).append('<a title="Next" class="table-pagination-next-btn-' + tblId + '"></a>');

		$('.table-pagination-pagination-num-' + tblId).eq(0).after('<a class="more-btn-first-' + tblId + '">..</a>');
		$('.table-pagination-pagination-num-' + tblId).eq(-1).before('<a class="more-btn-last-' + tblId + '">..</a>');

		//Create Jump Page Input
		if(jumpPage === true) {
			$('.page-list-table-' + tblId).append('<div class="table-pagination-jump-container-' + tblId + '"><input class="table-pagination-jump-input-' + tblId + '" type="number" max="' + totalPages + '"> / ' + totalPages + '</div>');
		}

		//show the pagination number according to size
		let jumpPageSpace;
		if(jumpPage === true) {
			jumpPageSpace = $('.table-pagination-jump-container-' + tblId).outerWidth();
		} else {
			jumpPageSpace = 0;
		}

		const $availableSpace = tblWidth - $('.table-pagination-prev-btn-' + tblId).outerWidth() - $('.table-pagination-next-btn-' + tblId).outerWidth() - jumpPageSpace;

		let $numBlockSize = $('.table-pagination-pagination-num-' + tblId).eq(-1).outerWidth();
		if($numBlockSize < 1) {
			$numBlockSize = 1; // unixman, avoid divizion by zero
		}
		let $avaliableBlock = Math.floor($availableSpace / $numBlockSize);
		let $pageStart = 1;
		let $pageEnd = totalPages;
		if($avaliableBlock < totalPages) {
			$pageEnd = $avaliableBlock;
			$avaliableBlock = $avaliableBlock - 3;
		}

		const rearrangePagination = function() {
			if(crrActivePage === 1) {
				$pageStart = crrActivePage;
				$pageEnd = $avaliableBlock;
			} else if(crrActivePage === totalPages) {
				$pageEnd = crrActivePage;
				$pageStart = crrActivePage - $avaliableBlock + 1;
			} else {
				if((Math.floor($avaliableBlock / 2) * 2) + 1 > $avaliableBlock) {
					$pageStart = crrActivePage - Math.floor($avaliableBlock / 2) + 1;
					$pageEnd = crrActivePage + Math.floor($avaliableBlock / 2);
				} else {
					$pageStart = crrActivePage - Math.floor($avaliableBlock / 2);
					$pageEnd = crrActivePage + Math.floor($avaliableBlock / 2);
				}
			}

			if($pageStart < 1) {
				$pageEnd = $pageEnd - $pageStart + 1;
				$pageStart = 1;
				if($pageEnd > totalPages) {
					$pageEnd = totalPages;
				}

			}
			if($pageEnd > totalPages) {
				$pageStart = $pageStart - ($pageEnd - totalPages);
				$pageEnd = totalPages;
				if($pageStart < 1) {
					$pageStart = 1;

				}
			}

			$('.table-pagination-pagination-num-' + tblId).each(function() {
				if($(this).attr('data-page-id') >= $pageStart && $(this).attr('data-page-id') <= $pageEnd) {
					$(this).show();
				} else {
					$(this).hide();
				}
			});

			if($pageStart === 1) {
				// $(".table-pagination-first-btn").hide();
				$('.more-btn-first-' + tblId).hide();
			} else {
				// $(".table-pagination-first-btn").show();
				$('.table-pagination-pagination-num-' + tblId + '[data-page-id="1"]').show();
				$('.more-btn-first-' + tblId).show();
			}

			if($pageEnd === totalPages) {
				// $(".table-pagination-last-btn").hide();
				$('.more-btn-last-' + tblId).hide();
			} else {
				// $(".table-pagination-last-btn").show();
				$('.table-pagination-pagination-num-' + tblId + '[data-page-id="' + totalPages + '"]').show();
				$('.more-btn-last-' + tblId).show();
			}

			$('.table-pagination-jump-input-' + tblId).val(crrActivePage);

		};

		rearrangePagination();

		const displayPage = function(theButton, type) {
			if(type === 'number') {
				crrActivePage = Math.floor(theButton.attr("data-page-id"));
			} else if(type === 'first') {
				crrActivePage = 1;
			} else if(type === 'prev') {
				if(crrActivePage > 1) {
					crrActivePage = crrActivePage - 1;
				}
			} else if(type === 'next') {
				if(crrActivePage < totalPages) {
					crrActivePage = crrActivePage + 1;
				}
			} else if(type === 'last') {
				crrActivePage = totalPages;
			} else if(type === 'jump') {
				crrActivePage = parseInt(theButton.val());
			}

			$table.find('tbody > tr').each(function() {
				if($(this).index() >= $pageDisplay[crrActivePage - 1].rowStart && $(this).index() < $pageDisplay[crrActivePage - 1].rowEnd) {
					if((transitionDurationMilliSec >= 250) && (transitionDurationMilliSec <= 500)) {
						$(this).fadeIn(transitionDurationMilliSec);
					} else {
						$(this).show(); // unixman
					}
				} else {
					$(this).hide();
				}
			});

			$('.page-list-table-' + tblId).find('.table-pagination-pagination-num-' + tblId).removeClass("active");
			$('.table-pagination-pagination-num-' + tblId + '[data-page-id="' + crrActivePage + '"]').addClass("active");

		};

		//Defaultly set the 1st pagination active
		$('.table-pagination-pagination-num-' + tblId + '[data-page-id="1"]').addClass("active");

		//change page when click on number pagination
		$('.table-pagination-pagination-num-' + tblId).on("click", function() {
			displayPage($(this), 'number');
			rearrangePagination();
		});

		//change to prev page when prev button clicked
		$('.table-pagination-prev-btn-' + tblId).on("click", function() {
			displayPage($(this), 'prev');
			rearrangePagination()
		});

		//change to next page when next button clicked
		$('.table-pagination-next-btn-' + tblId).on("click", function() {
			displayPage($(this), 'next');
			rearrangePagination()
		});

		//show the page when user input in jump page
		$('.table-pagination-jump-input-' + tblId).on({
			"change": function() {
				if($(this).val() >= 1 && $(this).val() <= totalPages) {
					displayPage($(this), 'jump');
					rearrangePagination();
				}
			}
		});

		if(crrPage > 1) {
			$('a.table-pagination-pgnum-' + tblId + '-' + crrPage).trigger('click');
		}

	}

}(jQuery));

// #end
