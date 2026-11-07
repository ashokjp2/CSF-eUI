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
            }
            if (data.memory) {
                $('#stat-mem').text(data.memory.percent + '%');
                $('#stat-mem-detail').text(data.memory.used_mb + ' / ' + data.memory.total_mb + ' MB');
                CSFv2.updateProgress('#prog-mem', data.memory.percent);
            }
            if (data.load) {
                $('#stat-load').text(data.load['1min']);
            }
            if (data.connections) {
                $('#stat-conn').text(data.connections.established);
            }
            if (data.blocked_ips !== undefined) {
                $('#stat-blocked').text(data.blocked_ips);
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
    }
};

// Global shortcut
window.CSFexpand = CSFv2.expand;

$(document).ready(function() {

    // Init theme
    CSFv2.initTheme();

    // Theme toggle
    $(document).on('click', '.theme-toggle', function(e) {
        e.preventDefault();
        CSFv2.toggleTheme();
        var icon = $(this).find('.glyphicon');
        if (document.documentElement.getAttribute('data-theme') === 'dark') {
            icon.removeClass('glyphicon-moon').addClass('glyphicon-sun');
        } else {
            icon.removeClass('glyphicon-sun').addClass('glyphicon-moon');
        }
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
        }
    });

});
