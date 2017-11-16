(function(suggestions, $) {
	suggestions.codesFromindex = [];
	suggestions.matrix = [];
	suggestions.indexFromCodes = {};
	suggestions.current = [];
	suggestions.exclusions = [];
	suggestions.number;

	suggestions.query = function(side) {
		suggestions.promise = $.ajax('/'+side+'.json', {
			dataType: 'json',
			success: function (data) {
				suggestions.codesFromindex = data.index;
				suggestions.matrix = data.matrix;
				// reconstitute the full matrix from the lower half matrix
				for(var i=0; i<suggestions.matrix.length; i++) {
					for(var j=i; j<suggestions.matrix.length; j++) {
						suggestions.matrix[i][j] = suggestions.matrix[j][i];
					}
				}
				for(var i=0; i<suggestions.codesFromindex.length; i++) {
					suggestions.indexFromCodes[suggestions.codesFromindex[i]] = i;
				}
			},
			error: function( jqXHR, textStatus, errorThrown ) {
				console.log('['+moment().format('YYYY-MM-DD HH:mm:ss')+'] Error on '+this.url, textStatus, errorThrown);
			}
		});
		suggestions.promise.done(suggestions.compute);
	};
        
        suggestions.refresh = function () {
                suggestions.number = parseInt(NRDB.settings.getItem('show-suggestions'), 10);
        }

	suggestions.compute = function() {
		suggestions.refresh();
                
                // init current suggestions
                suggestions.codesFromindex.forEach(function (code, index) {
                        suggestions.current[index] = {
                                code: code,
                                proba: 0
                        };
                });
                // find used cards
                var indexes = NRDB.data.cards.find({indeck:{'$gt':0}}).map(function (card) {
                        return suggestions.indexFromCodes[card.code];
                });
                // add suggestions of all used cards
                indexes.forEach(function (i) {
                        if(suggestions.matrix[i]) {
                                suggestions.matrix[i].forEach(function (value, j) {
                                        suggestions.current[j].proba += (value || 0);
                                });
                        }
                });
                // remove suggestions of already used cards
                indexes.forEach(function (i) {
                        if(suggestions.current[i]) suggestions.current[i].proba = 0;
                });
                // remove suggestions of identity
                NRDB.data.cards.find({type_code:'identity'}).map(function (card) {
                        return suggestions.indexFromCodes[card.code];
                }).forEach(function (i) {
                        if(suggestions.current[i]) suggestions.current[i].proba = 0;
                });
                // remove suggestions of excluded cards
                suggestions.exclusions.forEach(function (i) {
                        suggestions.current[i].proba = 0;
                });
                // sort suggestions
                suggestions.current.sort(function (a, b) {
                        return (b.proba - a.proba);
                });
                
		suggestions.show();
	};

	suggestions.show = function() {
                suggestions.refresh();
                
                var table = $('#table-suggestions');
		var tbody = table.children('tbody');
		tbody.empty();
		if(!suggestions.number && table.is(':visible')) {
			table.hide();
			return;
		}
		if(suggestions.number && !table.is(':visible')) {
			table.show();
		}
		var nb = 0;
		for(var i=0; i<suggestions.current.length; i++) {
			if(suggestions.current[i].proba === 0) continue;
			var card = NRDB.data.cards.findById(suggestions.current[i].code);
			if(is_card_usable(card) && Filters.pack_code.indexOf(card.pack_code) > -1) {
				var div = suggestions.div(card);
				div.on('click', 'button.close', suggestions.exclude.bind(this, card.code));
				tbody.append(div);
				if(++nb >= suggestions.number) break;
			}
		}
	};

	suggestions.div = function(record) {
		var faction = record.faction_code;
		var influ = "";
		for (var i = 0; i < record.factioncost; i++)
			influ += "●";

		var radios = '';
		for (var i = 0; i <= record.maxqty; i++) {
			radios += '<label class="btn btn-xs btn-default'
					+ (i == record.indeck ? ' active' : '')
					+ '"><input type="radio" name="qty-' + record.code
					+ '" value="' + i + '">' + i + '</label>';
		}

		var imgsrc = record.faction_code.substr(0,7) === "neutral" ? "" : '<img src="'
					+ Url_FactionImage.replace('xxx', record.faction_code)
					+ '.png" alt="'+record.title+'">';
		var div = $('<tr class="card-container" data-index="'
					+ record.code
					+ '"><td><button type="button" class="close"><span aria-hidden="true">&times;</span><span class="sr-only">Remove</span></button></td>'
					+ '<td><div class="btn-group" data-toggle="buttons">'
					+ radios
					+ '</div></td><td><a class="card" href="'
					+ Routing.generate('cards_zoom', {card_code:record.code})
					+ '" data-target="#cardModal" data-remote="false" data-toggle="modal">'
					+ record.title + '</a></td><td class="influence influence-' + faction
					+ '">' + influ + '</td><td class="type" title="' + record.type.name
					+ '"><img src="/bundles/app/images/types/'
					+ record.type_code + '.png" alt="'+record.type.name+'">'
					+ '</td><td class="faction" title="' + record.faction.name + '">'
					+ imgsrc + '</td></tr>');

		return div;
	};

	suggestions.exclude = function(code) {
		suggestions.exclusions.push(suggestions.indexFromCodes[code]);
		suggestions.compute();
	};

	suggestions.pick = function(event) {
		InputByTitle = false;
		var input = this;
		$(input).closest('tr').animate({
			opacity: 0
		}, function() {
			handle_quantity_change.call(input, event);
		});
	};

	$(function() {

		$('#table-suggestions').on({
			change : suggestions.pick
		}, 'input[type=radio]');

	});

})(NRDB.suggestions = {}, jQuery);
