/* CSFv2 - Enhanced JavaScript */

/* Legacy glyphicon name -> Tabler icon name (backend still emits glyphicon names in a few JSON feeds) */
var TI_MAP = {"refresh":"refresh","plus":"plus","info-sign":"info-circle","ok":"check","hourglass":"hourglass","trash":"trash","warning-sign":"alert-triangle","floppy-disk":"device-floppy","search":"search","ok-circle":"circle-check","globe":"world","flash":"bolt","cog":"settings","ban-circle":"ban","remove":"x","upload":"upload","transfer":"arrows-exchange","lock":"lock","envelope":"mail","wrench":"tool","list-alt":"list-details","eye-open":"eye","th-list":"list","cloud":"cloud","chevron-down":"chevron-down","repeat":"repeat","play":"player-play","list":"list","link":"link","certificate":"certificate","time":"clock","remove-sign":"circle-x","random":"arrows-shuffle","pencil":"pencil","floppy-save":"device-floppy","fire":"flame","exclamation-sign":"alert-circle","download":"download","cloud-download":"cloud-download","unchecked":"square","question-sign":"help-circle","ok-sign":"circle-check","chevron-up":"chevron-up","stop":"player-stop","shield":"shield","pause":"player-pause","log-in":"login","hdd":"server","folder-open":"folder-open","flag":"flag","file":"file","edit":"edit","console":"terminal-2","check":"checkbox","alert":"alert-triangle","user":"user","tasks":"list-check","star":"star","signal":"antenna-bars-5","share-alt":"share","send":"send","resize-full":"arrows-maximize","remove-circle":"circle-x","open":"upload","off":"power","minus":"minus","map-marker":"map-pin","filter":"filter","dashboard":"layout-dashboard","comment":"message","bell":"bell","arrow-right":"arrow-right","arrow-left":"arrow-left","eye-close":"eye-off","ban":"ban","heart":"heart","calendar":"calendar","home":"home","asterisk":"asterisk","tag":"tag","cloud-upload":"cloud-upload","import":"file-import","export":"file-export","copy":"copy","th":"layout-grid","book":"book","briefcase":"briefcase","chevron-right":"chevron-right","chevron-left":"chevron-left","exclamation":"alert-circle","stats":"chart-bar","save":"device-floppy","new-window":"external-link","phone":"phone","earphone":"phone","bullhorn":"speakerphone","equalizer":"adjustments","road":"road","plane":"plane","question":"help-circle","log":"file-text","plus-sign":"circle-plus","minus-sign":"circle-minus","tags":"tags","folder-close":"folder","arrow-up":"arrow-up","arrow-down":"arrow-down","share":"share","knight":"chess-knight","tower":"building-broadcast-tower","flask":"flask","list-check":"list-check","sort":"arrows-sort","inbox":"inbox","lamp":"bulb","leaf":"leaf","tint":"droplet","picture":"photo","camera":"camera","print":"printer","zoom-in":"zoom-in","zoom-out":"zoom-out","fullscreen":"arrows-maximize","thumbs-up":"thumb-up","thumbs-down":"thumb-down","pushpin":"pin","bookmark":"bookmark","gift":"gift","magnet":"magnet","music":"music","scale":"scale","education":"school","credit-card":"credit-card","bitcoin":"currency-bitcoin","usd":"currency-dollar","sunglasses":"sunglasses","king":"crown","queen":"chess-queen","pawn":"chess","bishop":"chess-bishop","tree-conifer":"christmas-tree","tree-deciduous":"tree","cutlery":"tools-kitchen-2","glass":"glass","headphones":"headphones","paperclip":"paperclip","font":"typography","bold":"bold","italic":"italic","align-left":"align-left","align-right":"align-right","align-center":"align-center","align-justify":"align-justified","move":"arrows-move","retweet":"repeat","eject":"player-eject","forward":"player-skip-forward","backward":"player-skip-back","fast-forward":"player-track-next","step-forward":"player-skip-forward","play-circle":"player-play","volume-up":"volume","volume-down":"volume-2","volume-off":"volume-off","qrcode":"qrcode","barcode":"barcode","adjust":"contrast","erase":"eraser","scissors":"scissors","level-up":"arrow-up","resize-small":"arrows-minimize","resize-vertical":"arrows-vertical","resize-horizontal":"arrows-horizontal","menu-hamburger":"menu-2","menu-down":"caret-down","menu-up":"caret-up","menu-left":"caret-left","menu-right":"caret-right","triangle-right":"caret-right","triangle-left":"caret-left","triangle-top":"caret-up","triangle-bottom":"caret-down","log-out":"logout","moon":"moon","sun":"sun","option-horizontal":"dots","star-empty":"star","heart-empty":"heart","download-alt":"download","th-large":"layout-grid","screenshot":"screenshot","facetime-video":"video","sort-by-alphabet":"sort-a-z","sort-by-alphabet-alt":"sort-z-a","sort-by-attributes":"sort-ascending","sort-by-attributes-alt":"sort-descending","sort-by-order":"sort-ascending","sort-by-order-alt":"sort-descending","modal-window":"app-window","compressed":"file-zip","cd":"disc","circle-arrow-right":"circle-arrow-right","circle-arrow-down":"circle-arrow-down","circle-arrow-up":"circle-arrow-up","hand-right":"hand-move","hand-left":"hand-move","hand-up":"hand-move","hand-down":"hand-move","text-size":"text-size","text-height":"text-size","text-width":"text-size","header":"heading","superscript":"superscript","subscript":"subscript","indent-left":"indent-decrease","indent-right":"indent-increase","oil":"flame","grain":"grain","tent":"tent","blackboard":"chalkboard","bed":"bed","apple":"brand-apple","piggy-bank":"pig-money","ruble":"currency-rubel","gbp":"currency-pound","eur":"currency-euro","yen":"currency-yen","ice-lolly":"ice-cream","sound-dolby":"volume","duplicate":"copy","object-align-top":"layout-align-top"};

var CSFv2 = {
    /* Map a legacy glyphicon name (possibly with trailing classes) to a Tabler class list */
    ti: function(name) {
        name = String(name || '').replace(/^glyphicon-/, '');
        var parts = name.split(/\s+/);
        var base = parts.shift();
        return [TI_MAP[base] || base || 'circle-dot'].concat(parts).join(' ');
    },

    // Toast notification system
    _toastMax: 5,
    _dismissAllBtn: null,

    _getContainer: function() {
        var container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        return container;
    },

    _updateDismissAll: function() {
        var container = this._getContainer();
        var toasts = container.querySelectorAll('.toast');
        var btn = document.getElementById('toast-dismiss-all');
        if (toasts.length >= 2) {
            if (!btn) {
                btn = document.createElement('button');
                btn.id = 'toast-dismiss-all';
                btn.className = 'toast-dismiss-all';
                btn.textContent = '✕ Dismiss all';
                var self = this;
                btn.addEventListener('click', function() {
                    var all = container.querySelectorAll('.toast');
                    all.forEach(function(t) {
                        t.classList.add('fade-out');
                        setTimeout(function() { t.remove(); }, 300);
                    });
                    btn.remove();
                });
                container.insertBefore(btn, container.firstChild);
            }
        } else if (btn) {
            btn.remove();
        }
    },

    toast: function(message, type, duration) {
        type = type || 'info';
        var container = this._getContainer();
        var self = this;

        /* Drop oldest non-error toast if at cap */
        var existing = container.querySelectorAll('.toast');
        if (existing.length >= this._toastMax) {
            existing[0].classList.add('fade-out');
            setTimeout(function() { existing[0].remove(); }, 300);
        }

        var autoDismissMs = duration || (type === 'success' ? 4000 : type === 'info' ? 5000 : 8000);
        var toast = document.createElement('div');
        toast.className = 'toast toast-' + type;
        var icons = {
            success: 'ti-circle-check',
            danger: 'ti-circle-x',
            warning: 'ti-alert-triangle',
            info: 'ti-info-circle'
        };
        toast.innerHTML = '<i class="ti ' + (icons[type] || icons.info) + '"></i> ' +
            '<span style="flex:1">' + message + '</span>' +
            '<span class="toast-close ti ti-x"></span>';
        container.appendChild(toast);
        this._updateDismissAll();

        function dismiss() {
            toast.classList.add('fade-out');
            setTimeout(function() {
                toast.remove();
                self._updateDismissAll();
            }, 300);
        }
        toast.querySelector('.toast-close').addEventListener('click', function(e) {
            e.stopPropagation();
            dismiss();
        });
        setTimeout(dismiss, autoDismissMs);
    },

    // AJAX action helper
    ajaxAction: function(url, data, successMsg) {
        var self = this;
        $.ajax({
            url: url,
            method: 'POST',
            data: data || {},
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            beforeSend: function() {
                self.toast('Processing...', 'info', 2000);
            },
            success: function(resp) {
                if (resp.success) {
                    self.toast(successMsg || 'Action completed', 'success');
                } else {
                    self.toast(resp.stderr || resp.error || 'Action failed', 'danger', 6000);
                }
            },
            error: function() {
                self.toast('Request failed', 'danger', 6000);
            }
        });
    },

    // Dark mode
    initTheme: function() {
        var saved = localStorage.getItem('csfv2-theme');
        if (saved === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
        }
    },
    toggleTheme: function() {
        var current = document.documentElement.getAttribute('data-theme');
        if (current === 'dark') {
            document.documentElement.removeAttribute('data-theme');
            localStorage.setItem('csfv2-theme', 'light');
        } else {
            document.documentElement.setAttribute('data-theme', 'dark');
            localStorage.setItem('csfv2-theme', 'dark');
        }
    },

    // Config expand
    expand: function(obj) {
        var len = obj.value.length;
        if (len < 20) len = 20;
        if (len > 120) len = 120;
        obj.style.width = (len * 8) + 'px';
    },

    // Refresh system stats
    refreshStats: function() {
        $.getJSON('/api/system', function(data) {
            if (data.cpu_usage !== undefined) {
                $('#stat-cpu').text(data.cpu_usage + '%');
                CSFv2.updateProgress('#prog-cpu', data.cpu_usage);
                CSFv2.pushSpark('cpu', data.cpu_usage);
            }
            if (data.memory) {
                $('#stat-mem').text(data.memory.percent + '%');
                $('#stat-mem-detail').text(data.memory.used_mb + ' / ' + data.memory.total_mb + ' MB');
                CSFv2.updateProgress('#prog-mem', data.memory.percent);
                CSFv2.pushSpark('mem', data.memory.percent);
            }
            if (data.load) {
                $('#stat-load').text(data.load['1min']);
            }
            if (data.connections) {
                $('#stat-conn').text(data.connections.established);
                $('#prog-conn').css('width', Math.min(100, Math.round(data.connections.established / 5)) + '%');
                CSFv2.pushSpark('conn', data.connections.established);
            }
            if (data.blocked_ips !== undefined) {
                var delta = $('#stat-blocked-delta').detach();
                $('#stat-blocked').text(data.blocked_ips + ' ').append(delta);
                $('#prog-blocked').css('width', Math.min(100, Math.round(data.blocked_ips / 20)) + '%');
            }
        });
    },

    updateProgress: function(selector, percent) {
        var el = $(selector);
        el.css('width', percent + '%');
        el.removeClass('green yellow red');
        if (percent < 60) el.addClass('green');
        else if (percent < 85) el.addClass('yellow');
        else el.addClass('red');
    },

    // Auto-refresh timer
    startAutoRefresh: function(interval) {
        interval = interval || 10000;
        this.refreshStats();
        setInterval(function() { CSFv2.refreshStats(); }, interval);
    },

    // ---- Sparklines on stat cards (history kept in sessionStorage so it survives reloads) ----
    _sparkMax: 30,
    pushSpark: function(key, value) {
        var hist;
        try { hist = JSON.parse(sessionStorage.getItem('csfv2-spark') || '{}'); } catch (e) { hist = {}; }
        var arr = hist[key] || [];
        arr.push(+value || 0);
        if (arr.length > this._sparkMax) arr = arr.slice(-this._sparkMax);
        hist[key] = arr;
        try { sessionStorage.setItem('csfv2-spark', JSON.stringify(hist)); } catch (e) {}
        this.drawSpark(key, arr);
    },
    drawSpark: function(key, arr) {
        var svg = document.getElementById('spark-' + key);
        if (!svg || arr.length < 2) return;
        var max = Math.max.apply(null, arr.concat([1])), min = Math.min.apply(null, arr);
        if (max === min) { max = min + 1; }
        var pts = arr.map(function(v, i) {
            var x = (i / (arr.length - 1)) * 100;
            var y = 22 - ((v - min) / (max - min)) * 20;
            return x.toFixed(1) + ',' + y.toFixed(1);
        });
        svg.innerHTML = '<polygon points="0,24 ' + pts.join(' ') + ' 100,24"></polygon><polyline points="' + pts.join(' ') + '"></polyline>';
    },

    // ---- Sidebar: collapsible groups, pins, filter, badges ----
    _navState: function(k, def) { try { return JSON.parse(localStorage.getItem(k)) || def; } catch (e) { return def; } },
    initSidebar: function() {
        var self = this;
        var nav = document.getElementById('sidebar-nav');
        if (!nav) return;
        var collapsed = this._navState('csfv2-nav-collapsed', []);
        var pins = this._navState('csfv2-nav-pins', []);

        // Collapse state (a group holding the active page always starts open)
        $('.nav-section[data-group]').each(function() {
            var g = $(this).data('group');
            if (collapsed.indexOf(g) >= 0 && !$(this).find('.nav-item.active').length) $(this).addClass('collapsed');
        });
        $(nav).on('click keydown', '.nav-section[data-group] > .nav-section-label', function(e) {
            if (e.type === 'keydown' && e.key !== 'Enter' && e.key !== ' ') return;
            e.preventDefault();
            var sec = $(this).closest('.nav-section');
            sec.toggleClass('collapsed');
            var g = sec.data('group');
            var list = self._navState('csfv2-nav-collapsed', []).filter(function(x) { return x !== g; });
            if (sec.hasClass('collapsed')) list.push(g);
            localStorage.setItem('csfv2-nav-collapsed', JSON.stringify(list));
        });

        // Pins
        function renderPins() {
            var wrap = $('#nav-pinned-items').empty();
            $('.nav-section[data-group] .nav-item').removeClass('pinned');
            pins.forEach(function(href) {
                var src = $('.nav-section[data-group] .nav-item').filter(function() { return $(this).attr('href') === href; }).first();
                if (!src.length) return;
                src.addClass('pinned');
                var clone = src.clone().removeAttr('id').find('.nav-badge').remove().end();
                clone.find('.nav-pin').attr('title', 'Unpin');
                wrap.append(clone);
            });
            $('#nav-pinned').toggle(pins.length > 0);
        }
        $(nav).on('click', '.nav-pin', function(e) {
            e.preventDefault(); e.stopPropagation();
            var href = $(this).closest('.nav-item').attr('href');
            var i = pins.indexOf(href);
            if (i >= 0) pins.splice(i, 1); else pins.push(href);
            localStorage.setItem('csfv2-nav-pins', JSON.stringify(pins));
            renderPins();
        });
        renderPins();

        // Filter
        var input = document.getElementById('nav-filter');
        if (input) {
            input.addEventListener('input', function() {
                var q = input.value.trim().toLowerCase();
                $('.nav-section[data-group]').each(function() {
                    var sec = $(this), any = false;
                    sec.find('.nav-item').each(function() {
                        var hit = !q || ($(this).data('label') || $(this).text()).toLowerCase().indexOf(q) >= 0;
                        $(this).toggleClass('filtered-out', !hit);
                        if (hit) any = true;
                    });
                    sec.toggleClass('filtering', !!q).toggle(!q || any);
                });
                $('#nav-pinned').toggle(!q && pins.length > 0);
            });
            input.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') {
                    var first = $('.nav-section[data-group]:visible .nav-item:not(.filtered-out)').first();
                    if (first.length) location.href = first.attr('href');
                } else if (e.key === 'Escape') { input.value = ''; input.dispatchEvent(new Event('input')); input.blur(); }
            });
        }

        this.refreshTempBadge();
    },
    refreshTempBadge: function() {
        var self = this;
        if (!document.getElementById('nav-temp-badge')) return;
        $.getJSON('/api/temp', function(list) {
            var n = (list || []).filter(function(e) { return (e.type || '').toLowerCase().indexOf('deny') >= 0 || (e.type || '').toLowerCase().indexOf('block') >= 0; }).length;
            var b = $('#nav-temp-badge');
            if (n > 0) b.text(n).show(); else b.hide();
            self.syncGroupBadges();
        });
    },
    syncGroupBadges: function() {
        $('.nav-section[data-group]').each(function() {
            var has = $(this).find('.nav-badge:visible').length > 0;
            $(this).find('.nav-group-badge').toggleClass('on', has);
        });
    },

    // ---- Safe apply bar: restart with auto-rollback unless confirmed ----
    _safeTimer: null,
    initSafeApply: function() {
        var bar = document.getElementById('safe-bar');
        if (!bar) return;
        var self = this;
        function render(s) {
            var $bar = $(bar), icon = $bar.find('.safe-bar-icon'), act = $('#safe-bar-actions').empty();
            $bar.removeClass('safe-pending safe-armed safe-rolled');
            if (s.rolled_back) {
                $bar.addClass('safe-rolled').show();
                icon.attr('class', 'ti safe-bar-icon ti-arrow-back-up');
                $('#safe-bar-title').text(s.rolled_back.success ? 'Change rolled back' : 'Rollback failed');
                $('#safe-bar-sub').text(s.rolled_back.message || '');
                act.append($('<button class="btn btn-default btn-sm">Dismiss</button>').on('click', function() {
                    $.post('/api/safe-apply/dismiss', function() { refresh(); });
                }));
            } else if (s.armed) {
                $bar.addClass('safe-armed').show();
                icon.attr('class', 'ti safe-bar-icon ti-hourglass');
                $('#safe-bar-title').text('Confirm the firewall still lets you in');
                var sub = $('#safe-bar-sub');
                var remaining = s.remaining;
                sub.text('Rolls back to the previous config in ' + remaining + 's unless you confirm.');
                clearInterval(self._safeTimer);
                self._safeTimer = setInterval(function() {
                    remaining -= 1;
                    if (remaining <= 0) { clearInterval(self._safeTimer); refresh(); return; }
                    sub.text('Rolls back to the previous config in ' + remaining + 's unless you confirm.');
                }, 1000);
                act.append($('<button class="btn btn-primary btn-sm"><i class="ti ti-check"></i> Keep this config</button>').on('click', function() {
                    var b = $(this).prop('disabled', true);
                    $.post('/api/safe-apply/confirm', function() { clearInterval(self._safeTimer); self.toast('Configuration confirmed', 'success'); refresh(); })
                     .fail(function() { b.prop('disabled', false); });
                }));
            } else if (s.pending) {
                $bar.addClass('safe-pending').show();
                icon.attr('class', 'ti safe-bar-icon ti-player-play');
                $('#safe-bar-title').text('Unapplied firewall changes');
                $('#safe-bar-sub').text('Apply safely restarts csf+lfd and rolls back automatically in ' + s.seconds + 's unless you confirm you still have access.');
                act.append($('<button class="btn btn-primary btn-sm"><i class="ti ti-shield-check"></i> Apply safely</button>').on('click', function() {
                    var b = $(this).prop('disabled', true).text('Applying…');
                    $.ajax({url: '/api/safe-apply/start', method: 'POST', contentType: 'application/json', data: JSON.stringify({seconds: s.seconds})})
                        .done(function(r) { if (!r.success) self.toast(r.error || 'Apply failed', 'danger'); refresh(); })
                        .fail(function() { self.toast('Apply failed', 'danger'); b.prop('disabled', false); });
                }));
                act.append($('<a class="btn btn-default btn-sm" href="/backup-restore">Backups</a>'));
            } else {
                $bar.hide();
            }
        }
        function refresh() { $.getJSON('/api/safe-apply/status', render); }
        refresh();
        setInterval(refresh, 20000);
    },

    // ---- Tables: sort, filter, CSV export, bulk IP selection, empty rows, mobile labels ----
    _ipKey: function(s) {
        var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/.exec(s);
        return m ? ((+m[1]) * 16777216 + (+m[2]) * 65536 + (+m[3]) * 256 + (+m[4])) : null;
    },
    _cellKey: function(td) {
        var t = $.trim(td.textContent || '');
        var ip = this._ipKey(t);
        if (ip !== null) return ip;
        var n = parseFloat(t.replace(/[,%\s]/g, ''));
        return (!isNaN(n) && /^[\d.,%\s-]+(\s*[KMG]?B)?$/.test(t)) ? n : t.toLowerCase();
    },
    enhanceTables: function(root) {
        var self = this;
        $(root || document).find('table.table').each(function() {
            var table = this, $t = $(table);
            if ($t.closest('.modal, .no-enhance').length || $t.hasClass('no-enhance')) return;
            var thead = table.tHead, ths = thead ? $(thead).find('th') : $();
            self._labelCells($t);
            self._markEmptyRows($t);
            if ($t.data('enhanced') || ths.length < 2) return;
            $t.data('enhanced', true);
            /* Sorting */
            ths.each(function(i) {
                var th = $(this);
                if (th.find('input,button').length || !$.trim(th.text())) return;
                th.addClass('sortable').attr('title', 'Sort').on('click', function(e) {
                    if ($(e.target).is('a,button,input')) return;
                    var dir = th.hasClass('sort-asc') ? -1 : 1;
                    ths.removeClass('sort-asc sort-desc');
                    th.addClass(dir === 1 ? 'sort-asc' : 'sort-desc');
                    $(table).find('tbody').each(function() {
                        var rows = $(this).children('tr').not('.empty-row').get();
                        rows.sort(function(a, b) {
                            var ka = self._cellKey(a.cells[i] || {}), kb = self._cellKey(b.cells[i] || {});
                            if (typeof ka === 'number' && typeof kb === 'number') return (ka - kb) * dir;
                            return String(ka).localeCompare(String(kb)) * dir;
                        });
                        $(this).append(rows);
                    });
                });
            });
            /* Toolbar: filter + CSV (+ bulk) — only for tables likely to hold a list */
            if ($t.hasClass('no-toolbar') || $t.closest('.panel-body, .table-responsive, .panel').find('.tbl-toolbar').length) return;
            var bulk = $t.data('bulk');
            var tb = $('<div class="tbl-toolbar"></div>');
            var filter = $('<input type="search" class="form-control input-sm tbl-filter" placeholder="Filter rows…" aria-label="Filter rows">');
            var count = $('<span class="tbl-count"></span>');
            var csv = $('<button type="button" class="btn btn-default btn-xs" title="Export visible rows as CSV"><i class="ti ti-download"></i> CSV</button>');
            tb.append(filter, count, csv);
            function refreshCount() {
                var rows = $t.find('tbody tr').not('.empty-row'), vis = rows.filter(':visible').length;
                count.text(rows.length ? (vis === rows.length ? rows.length + ' rows' : vis + ' of ' + rows.length) : '');
            }
            filter.on('input', function() {
                var q = this.value.toLowerCase();
                $t.find('tbody tr').not('.empty-row').each(function() { $(this).toggle(!q || this.textContent.toLowerCase().indexOf(q) >= 0); });
                refreshCount();
            });
            csv.on('click', function() {
                var lines = [ths.map(function() { return '"' + $.trim($(this).text()).replace(/"/g, '""') + '"'; }).get().join(',')];
                $t.find('tbody tr:visible').not('.empty-row').each(function() {
                    lines.push($(this).children('td').map(function() { return '"' + $.trim($(this).text()).replace(/"/g, '""') + '"'; }).get().join(','));
                });
                var a = document.createElement('a');
                a.href = URL.createObjectURL(new Blob([lines.join('\n')], {type: 'text/csv'}));
                a.download = ($('.topbar-title').text().trim() || 'table').toLowerCase().replace(/\s+/g, '-') + '.csv';
                document.body.appendChild(a); a.click(); a.remove();
            });
            $t.before(tb);
            refreshCount();
            new MutationObserver(function() { self._markEmptyRows($t); self._labelCells($t); refreshCount(); if (bulk) self._syncBulk($t); })
                .observe(table, {childList: true, subtree: true});
            if (bulk) self._initBulk($t, tb, bulk);
        });
    },
    _markEmptyRows: function($t) {
        $t.find('tbody > tr').each(function() {
            var tds = this.cells;
            $(this).toggleClass('empty-row', tds.length === 1 && tds[0].colSpan > 1 && !$(tds[0]).find('table,form').length);
        });
    },
    _labelCells: function($t) {
        var labels = $t.find('thead th').map(function() { return $.trim($(this).text()); }).get();
        if (!labels.length) return;
        $t.find('tbody > tr').not('.empty-row').each(function() {
            $(this).children('td').each(function(i) { if (!this.hasAttribute('data-label') && labels[i]) this.setAttribute('data-label', labels[i]); });
        });
    },
    /* Bulk: data-bulk="<cell index with the IP>"; adds checkboxes and an action bar posting to /bulk/action */
    _initBulk: function($t, toolbar, ipCol) {
        var self = this;
        ipCol = parseInt(ipCol, 10) || 0;
        var bar = $('<div class="bulk-bar" style="display:none"><span class="bulk-count"></span>' +
            '<button class="btn btn-default btn-xs" data-act="allow"><i class="ti ti-circle-check"></i> Allow</button>' +
            '<button class="btn btn-default btn-xs" data-act="deny"><i class="ti ti-ban"></i> Block</button>' +
            '<button class="btn btn-default btn-xs" data-act="unblock"><i class="ti ti-lock-open"></i> Unblock</button>' +
            '<button class="btn btn-link btn-xs bulk-clear">Clear</button></div>');
        toolbar.after(bar);
        $t.find('thead tr').prepend('<th class="bulk-th"><input type="checkbox" class="bulk-all" aria-label="Select all"></th>');
        $t.data('bulkCol', ipCol);
        self._syncBulk($t);
        $t.on('change', '.bulk-all', function() { $t.find('.bulk-cb:visible').prop('checked', this.checked); update(); });
        $t.on('change', '.bulk-cb', update);
        function selected() { return $t.find('.bulk-cb:checked').map(function() { return $(this).data('ip'); }).get(); }
        function update() { var n = selected().length; bar.toggle(n > 0); bar.find('.bulk-count').text(n + ' selected'); }
        bar.on('click', '.bulk-clear', function() { $t.find('.bulk-cb, .bulk-all').prop('checked', false); update(); });
        bar.on('click', '[data-act]', function() {
            var act = $(this).data('act'), ips = selected();
            if (!ips.length || !confirm(act.charAt(0).toUpperCase() + act.slice(1) + ' ' + ips.length + ' IP' + (ips.length > 1 ? 's' : '') + '?')) return;
            var b = $(this).prop('disabled', true);
            $.post('/bulk/action', {action: act, ips: ips.join('\n')}, function(r) {
                if (r.success) { self.toast(act + ': ' + r.succeeded + ' ok, ' + r.failed + ' failed', r.failed ? 'warning' : 'success'); setTimeout(function() { location.reload(); }, 1200); }
                else self.toast(r.error || 'Bulk action failed', 'danger');
            }).fail(function() { self.toast('Bulk action failed', 'danger'); }).always(function() { b.prop('disabled', false); });
        });
    },
    _syncBulk: function($t) {
        var col = $t.data('bulkCol') || 0;
        $t.find('tbody > tr').not('.empty-row').each(function() {
            if ($(this).children('.bulk-td').length) return;
            var ipText = $.trim($(this.cells[col] || {}).text()), m = /(\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?|[0-9a-f:]{3,}(?:\/\d{1,3})?)/i.exec(ipText);
            $(this).prepend(m ? '<td class="bulk-td"><input type="checkbox" class="bulk-cb" data-ip="' + m[1] + '" aria-label="Select ' + m[1] + '"></td>' : '<td class="bulk-td"></td>');
        });
        $t.find('tbody > tr.empty-row').each(function() { if (this.cells[0] && this.cells[0].colSpan) this.cells[0].colSpan = $t.find('thead th').length; });
    },

    // ---- Loading state for buttons that run csf commands ----
    initLoadingStates: function() {
        $(document).on('submit', 'form', function() {
            var form = $(this), btn = form.find('button[type=submit], input[type=submit]').filter(':focus').first();
            if (!btn.length) btn = form.find('button[type=submit]').first();
            if (!btn.length || btn.hasClass('no-loading')) return;
            btn.addClass('is-loading');
            setTimeout(function() { btn.prop('disabled', true); }, 0);
            if (form.data('ajax')) setTimeout(function() { btn.removeClass('is-loading').prop('disabled', false); }, 2500);
            else setTimeout(function() { btn.removeClass('is-loading').prop('disabled', false); }, 15000);
        });
    },

    // ---- Notification centre (bell) ----
    initBell: function() {
        var bell = $('#bell-btn');
        if (!bell.length) return;
        var self = this, panel = $('#bell-panel'), list = $('#bell-list'), badge = $('#bell-badge');
        var seen = parseInt(localStorage.getItem('csfv2-bell-seen') || '0', 10);
        function esc(t) { return $('<div>').text(t == null ? '' : String(t)).html(); }
        function ago(ts) { var s = Math.max(0, Math.floor(Date.now() / 1000 - ts)); if (s < 60) return s + 's ago'; if (s < 3600) return Math.floor(s / 60) + 'm ago'; if (s < 86400) return Math.floor(s / 3600) + 'h ago'; return Math.floor(s / 86400) + 'd ago'; }
        function render(events) {
            var unread = events.filter(function(e) { return e.ts > seen; }).length;
            badge.text(unread > 9 ? '9+' : unread).toggle(unread > 0);
            if (!events.length) { list.html('<div class="bell-empty">No events yet. Blocks, service changes and updates will show here.</div>'); return; }
            var icons = {lfd_block: 'ban', lfd_down: 'alert-triangle', firewall_down: 'shield-off', update_available: 'cloud-download', cert_expiry: 'certificate', ui_login: 'login', ui_login_failed: 'lock-x', safe_apply: 'arrow-back-up', test: 'send'};
            list.html(events.map(function(e) {
                return '<div class="bell-item' + (e.ts > seen ? ' unread' : '') + ' lvl-' + esc(e.level) + '"><i class="ti ti-' + (icons[e.kind] || 'bell') + '"></i>' +
                    '<div><b>' + esc(e.title) + '</b><span>' + esc((e.body || '').split('\n')[0]).substring(0, 120) + '</span><small>' + ago(e.ts) + '</small></div></div>';
            }).join(''));
        }
        function load() { $.getJSON('/api/notifications/events', function(r) { render(r.events || []); }); }
        bell.on('click', function(e) {
            e.preventDefault(); e.stopPropagation();
            panel.toggle();
            if (panel.is(':visible')) { seen = Math.floor(Date.now() / 1000); localStorage.setItem('csfv2-bell-seen', seen); badge.hide(); }
        });
        $(document).on('click', function(e) { if (!$(e.target).closest('#bell-panel, #bell-btn').length) panel.hide(); });
        load();
        setInterval(load, 60000);
    },

    // ---- Command palette (Ctrl+K) ----
    _settingHelp: null,
    initPalette: function() {
        var self = this;
        var backdrop = document.getElementById('palette');
        if (!backdrop) return;
        var q = document.getElementById('palette-q');
        var results = $('#palette-results');
        var pages = $('.nav-section[data-group] .nav-item').map(function() {
            return { href: $(this).attr('href'), label: $(this).data('label') || $(this).text().trim(), icon: ($(this).find('.ti').attr('class') || '').replace(/text-\S+/g, '').trim() };
        }).get();
        var IPRE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^[0-9a-f:]{3,}(\/\d{1,3})?$/i;
        var sel = 0;

        function esc(t) { return $('<div>').text(t == null ? '' : String(t)).html(); }
        function open() {
            backdrop.style.display = 'block';
            q.value = ''; render(''); q.focus();
            if (!self._settingHelp) {
                $.getJSON('/api/setting-help', function(h) { self._settingHelp = h || {}; render(q.value); });
            }
        }
        function close() { backdrop.style.display = 'none'; }
        function item(icon, text, sub, hint, attrs) {
            return '<a class="palette-item" ' + attrs + '><i class="' + icon + '"></i><span class="pi-text">' + text +
                (sub ? '<span class="pi-sub">' + sub + '</span>' : '') + '</span>' + (hint ? '<span class="pi-hint">' + hint + '</span>' : '') + '</a>';
        }
        function render(v) {
            v = v.trim(); var lv = v.toLowerCase(); var html = '';
            if (v && IPRE.test(v)) {
                var e = encodeURIComponent(v);
                html += '<div class="palette-group">IP ' + esc(v) + '</div>' +
                    item('ti ti-search', 'Look up ' + esc(v), 'GeoIP, WHOIS, reputation', '', 'href="/ip-lookup?ip=' + e + '"') +
                    item('ti ti-file-search', 'Search firewall and logs for ' + esc(v), '', '', 'href="#" data-search="' + esc(v) + '"') +
                    item('ti ti-ban', 'Block ' + esc(v), '', '', 'href="/#ip=' + e + '&act=deny"') +
                    item('ti ti-circle-check', 'Allow ' + esc(v), '', '', 'href="/#ip=' + e + '&act=allow"') +
                    item('ti ti-lock-open', 'Unblock ' + esc(v), '', '', 'href="/#ip=' + e + '&act=unblock"');
            }
            var hits = pages.filter(function(p) { return !lv || p.label.toLowerCase().indexOf(lv) >= 0 || p.href.indexOf(lv) >= 0; });
            if (!lv) hits = hits.slice(0, 8);
            if (hits.length) {
                html += '<div class="palette-group">Pages</div>';
                hits.forEach(function(p) { html += item(p.icon || 'ti ti-file', esc(p.label), '', 'Go', 'href="' + p.href + '"'); });
            }
            if (lv.length >= 2 && self._settingHelp) {
                var keys = Object.keys(self._settingHelp).filter(function(k) {
                    var h = self._settingHelp[k]; var txt = (k + ' ' + (typeof h === 'string' ? h : (h.plain || ''))).toLowerCase();
                    return txt.indexOf(lv) >= 0;
                }).slice(0, 6);
                if (keys.length) {
                    html += '<div class="palette-group">Settings</div>';
                    keys.forEach(function(k) {
                        var h = self._settingHelp[k]; var plain = typeof h === 'string' ? h : (h.plain || '');
                        html += item('ti ti-settings', '<code>' + esc(k) + '</code>', esc(plain.substring(0, 70)), 'Config', 'href="/config?q=' + encodeURIComponent(k) + '"');
                    });
                }
            }
            if (!html) html = '<div class="palette-empty">No matches. Try a page name, a setting like TCP_IN, or an IP address.</div>';
            results.html(html);
            sel = 0; results.find('.palette-item').first().addClass('active');
        }
        function go(a) {
            if (!a.length) return;
            var s = a.data('search');
            if (s) { $('#palette-search-ip').val(s); $('#palette-search-form').submit(); return; }
            var href = a.attr('href');
            if (href.indexOf('/#') === 0 && location.pathname === '/') { location.hash = href.substring(2); close(); location.reload(); return; }
            location.href = href;
        }

        $('#palette-open').on('click', open);
        $(document).on('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); if (backdrop.style.display === 'none') open(); else close(); }
            else if (e.key === 'Escape' && backdrop.style.display !== 'none') close();
        });
        $(backdrop).on('click', function(e) { if (e.target === backdrop) close(); });
        q.addEventListener('input', function() { render(q.value); });
        q.addEventListener('keydown', function(e) {
            var items = results.find('.palette-item');
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                sel = (sel + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
                items.removeClass('active').eq(sel).addClass('active')[0].scrollIntoView({block: 'nearest'});
            } else if (e.key === 'Enter') { e.preventDefault(); go(items.eq(sel)); }
        });
        results.on('click', '.palette-item', function(e) { e.preventDefault(); go($(this)); });
    }
};

// Global shortcut
window.CSFexpand = CSFv2.expand;

$(document).ready(function() {

    // Init theme
    CSFv2.initTheme();
    CSFv2.initSidebar();
    CSFv2.initPalette();
    CSFv2.initSafeApply();
    CSFv2.initLoadingStates();
    CSFv2.initBell();
    CSFv2.enhanceTables(document);
    /* Tables rendered later by page scripts get the same treatment */
    var _tblTimer = null, _mc = document.querySelector('.main-content');
    if (_mc) new MutationObserver(function() { clearTimeout(_tblTimer); _tblTimer = setTimeout(function() { CSFv2.enhanceTables(_mc); }, 150); })
        .observe(_mc, {childList: true, subtree: true});
    /* Read-only users: block state-changing forms client-side (the server enforces it too) */
    if (document.body.getAttribute('data-role') === 'viewer') {
        $(document).on('submit', 'form', function(e) {
            var m = (this.method || 'get').toLowerCase(), a = this.action || '';
            if (m === 'post' && a.indexOf('/settings') < 0 && a.indexOf('/quick/search') < 0 && a.indexOf('/logs/') < 0 && a.indexOf('/logout') < 0) { e.preventDefault(); CSFv2.toast('Your account is read-only', 'warning'); }
        });
    }

    // Theme toggle
    function syncThemeIcon() {
        var dark = document.documentElement.getAttribute('data-theme') === 'dark';
        $('.theme-toggle .ti').toggleClass('ti-moon', !dark).toggleClass('ti-sun', dark);
    }
    syncThemeIcon();
    $(document).on('click', '.theme-toggle', function(e) {
        e.preventDefault();
        CSFv2.toggleTheme();
        syncThemeIcon();
    });

    // Confirm modal for dangerous actions
    $(document).on('click', '.confirmButton', function(e) {
        e.preventDefault();
        e.stopPropagation();
        var query = $(this).data('query') || 'Are you sure?';
        var action = $(this).data('action');
        var form = $(this).closest('form');

        $('#modal-text').text(query);

        if (action) {
            $('#modal-form').attr('action', action);
        } else if (form.length) {
            $('#modal-form').attr('action', form.attr('action'));
        }

        // Copy hidden inputs from the source form
        $('#modal-form').find('.cloned-input').remove();
        if (form.length) {
            form.find('input[type="hidden"]').each(function() {
                var clone = $(this).clone().addClass('cloned-input');
                $('#modal-form').append(clone);
            });
        }

        $('#confirmModal').modal('show');
    });

    $('#confirmModal').on('hidden.bs.modal', function() {
        $('#modal-form').find('.cloned-input').remove();
    });

    // AJAX quick actions (forms with data-ajax="true")
    $(document).on('submit', 'form[data-ajax="true"]', function(e) {
        e.preventDefault();
        var form = $(this);
        var url = form.attr('action');
        var data = form.serialize();
        var msg = form.data('success-msg') || 'Action completed';
        var refreshTarget = form.data('refresh');

        CSFv2.ajaxAction(url, data, msg);

        if (refreshTarget) {
            setTimeout(function() {
                if (refreshTarget === 'page') {
                    location.reload();
                } else {
                    $(refreshTarget).load(location.pathname + ' ' + refreshTarget + ' > *');
                }
            }, 1500);
        }

        // Clear input fields
        form.find('input[type="text"]').val('');
    });

    // Convert only server-flashed messages (direct children of .main-content) to toasts
    $('.main-content > .alert').each(function() {
        var el = $(this);
        var text = el.text().trim();
        var type = 'info';
        if (el.hasClass('alert-success')) type = 'success';
        else if (el.hasClass('alert-danger')) type = 'danger';
        else if (el.hasClass('alert-warning')) type = 'warning';
        CSFv2.toast(text, type, 5000);
        el.remove();
    });

    // Auto refresh stats if stat widgets exist
    if ($('.stat-card').length > 0) {
        CSFv2.startAutoRefresh(10000);
    }

    // Font size controls for output
    var myFont = 12;
    $(document).on('click', '#fontplus-btn', function() {
        if (myFont < 20) {
            myFont += 1;
            $('#output').css('font-size', myFont + 'px');
        }
    });
    $(document).on('click', '#fontminus-btn', function() {
        if (myFont > 8) {
            myFont -= 1;
            $('#output').css('font-size', myFont + 'px');
        }
    });

    // Keyboard shortcuts
    $(document).on('keydown', function(e) {
        // Ctrl+Shift+D: toggle dark mode
        if (e.ctrlKey && e.shiftKey && e.key === 'D') {
            e.preventDefault();
            CSFv2.toggleTheme();
            $('.theme-toggle .ti').toggleClass('ti-moon ti-sun');
        }
    });

});
