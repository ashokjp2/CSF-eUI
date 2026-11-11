/* CSFv2 - Enhanced JavaScript */

var CSFv2 = {
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
            success: 'glyphicon-ok-circle',
            danger: 'glyphicon-remove-circle',
            warning: 'glyphicon-warning-sign',
            info: 'glyphicon-info-sign'
        };
        toast.innerHTML = '<span class="glyphicon ' + (icons[type] || icons.info) + '"></span> ' +
            '<span style="flex:1">' + message + '</span>' +
            '<span class="toast-close glyphicon glyphicon-remove"></span>';
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
