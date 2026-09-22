'use strict';
'require view';
'require form';
'require uci';
'require rpc';
'require network';
'require fs';
'require ui';
'require poll';

var CTL = '/usr/libexec/iptv-scanner-ctl';

function ctl(cmd) {
	return fs.exec(CTL, [ cmd ]);
}

function getStatus() {
	return ctl('status').then(function (res) {
		var out = (res.stdout || '').trim();
		var m = out.match(/^running\s+(\d+)/);
		if (m)
			return { running: true, pid: parseInt(m[1], 10) };
		return { running: false, pid: null };
	}).catch(function () {
		return { running: false, pid: null };
	});
}

return view.extend({
	load: function () {
		return Promise.all([
			uci.load('iptv_scanner'),
			network.getDevices()
		]);
	},

	/* ---------- 操作按钮 ---------- */

	handleAction: function (cmd, successMsg) {
		var self = this;
		return ctl(cmd).then(function (res) {
			var out = (res.stdout || res.stderr || '').trim();
			if (res.code !== 0) {
				ui.addNotification(null,
					E('p', _(cmd) + _(' 失败：') + (out || _('未知错误'))),
					'error');
			} else {
				ui.addNotification(null,
					E('p', out || successMsg || _('操作完成')),
					'info');
			}
			return self.refreshStatus();
		}).catch(function (err) {
			ui.addNotification(null,
				E('p', _('执行失败：') + err.message), 'error');
		});
	},

	handleStart:   function () { return this.handleAction('start');   },
	handleStop:    function () { return this.handleAction('stop');    },
	handleRestart: function () { return this.handleAction('restart'); },

	/* ---------- 通用：弹窗并自动滚到底部 ---------- */

	showScrollableModal: function (title, content, preId) {
		var preStyle =
			'max-height:60vh; overflow:auto; white-space:pre-wrap; ' +
			'font-size:12px;';

		ui.showModal(title, [
			E('pre', { 'id': preId, 'style': preStyle }, content || _('(空)')),
			E('div', { 'class': 'right' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-neutral',
					'click': ui.hideModal
				}, _('关闭'))
			])
		]);

		var scrollToBottom = function () {
			var el = document.getElementById(preId);
			if (el) el.scrollTop = el.scrollHeight;
		};
		window.requestAnimationFrame(function () {
			scrollToBottom();
			window.setTimeout(scrollToBottom, 50);
			window.setTimeout(scrollToBottom, 200);
		});
	},

	handleViewM3U: function () {
		var path = uci.get('iptv_scanner', 'settings', 'm3u_file') || '/tmp/iptv.m3u';
		var self = this;
		return ctl('cat-m3u').then(function (res) {
			var content = (res.stdout || '');
			self.showScrollableModal(
				_('M3U 文件内容') + ' — ' + path,
				content,
				'iptv-m3u-content'
			);
		}).catch(function (err) {
			ui.addNotification(null, E('p', _('读取失败：') + err.message), 'error');
		});
	},

	handleViewLog: function () {
		var self = this;
		return ctl('cat-log').then(function (res) {
			var content = (res.stdout || '');
			self.showScrollableModal(
				_('扫描日志 (最近 200 行)'),
				content,
				'iptv-log-content'
			);
		}).catch(function (err) {
			ui.addNotification(null, E('p', _('读取失败：') + err.message), 'error');
		});
	},

	refreshStatus: function () {
		return getStatus().then(function (st) {
			var el = document.getElementById('iptv-scanner-status');
			if (!el) return;
			if (st.running) {
				el.textContent = '● ' + _('运行中') +
					(st.pid ? ' (PID: ' + st.pid + ')' : '');
				el.style.color = '#090';
			} else {
				el.textContent = '○ ' + _('已停止');
				el.style.color = '#999';
			}
		});
	},

	/* ---------- 渲染 ---------- */

	render: function (data) {
		var devices = data[1] || [];
		var self = this;
		var m, s, o;

		m = new form.Map('iptv_scanner',
			_('IPTV 扫描器'),
			_('扫描局域网中的 IPTV 组播流并生成 M3U 播放列表。修改配置后请点击"保存 & 应用"生效。'));

		/* ===== 状态与控制 ===== */
		s = m.section(form.NamedSection, 'settings', 'iptvscanner', _('运行状态与控制'));
		s.anonymous = true;
		s.addremove = false;

		o = s.option(form.DummyValue, '_status', _('当前状态'));
		o.cfgvalue = function () {
			return E('span', {
				'id': 'iptv-scanner-status',
				'style': 'font-weight:bold;'
			}, _('查询中...'));
		};

		o = s.option(form.DummyValue, '_controls', _('操作'));
		o.cfgvalue = function () {
			return E('div', {}, [
				E('button', {
					'class': 'btn cbi-button cbi-button-apply',
					'click': function (ev) { ev.preventDefault(); self.handleStart(); }
				}, ' ' + _('启动扫描') + ' '),
				' ',
				E('button', {
					'class': 'btn cbi-button cbi-button-reset',
					'click': function (ev) { ev.preventDefault(); self.handleStop(); }
				}, ' ' + _('停止扫描') + ' '),
				' ',
				E('button', {
					'class': 'btn cbi-button cbi-button-action',
					'click': function (ev) { ev.preventDefault(); self.handleRestart(); }
				}, ' ' + _('重启扫描') + ' '),
				' ',
				E('button', {
					'class': 'btn cbi-button',
					'click': function (ev) { ev.preventDefault(); self.handleViewM3U(); }
				}, ' ' + _('查看 M3U') + ' '),
				' ',
				E('button', {
					'class': 'btn cbi-button',
					'click': function (ev) { ev.preventDefault(); self.handleViewLog(); }
				}, ' ' + _('查看日志') + ' ')
			]);
		};

		/* ===== 扫描参数 ===== */
		o = s.option(form.Value, 'timeout', _('等待秒数'),
			_('每个组播地址的监听时间（1-60 秒）。数值越大扫描越慢但更可靠。'));
		o.datatype = 'range(1,60)';
		o.default = '2';
		o.rmempty = false;

		o = s.option(form.ListValue, 'interface', _('网卡接口'),
			_('接收 IPTV 组播的网络接口，例如 lan1 / eth0.1'));
		var hasIface = false;
		devices.forEach(function (dev) {
			var name = dev.getName();
			if (!name) return;
			o.value(name, name);
			hasIface = true;
		});
		if (!hasIface)
			o.value('lan1', 'lan1');
		o.default = 'lan1';
		o.rmempty = false;

		o = s.option(form.Value, 'm3u_file', _('M3U 输出路径'),
			_('生成 M3U 文件的完整路径'));
		o.default = '/tmp/iptv.m3u';
		o.datatype = 'filepath';
		o.rmempty = false;

		o = s.option(form.DynamicList, 'ranges', _('扫描网段'),
			_('每行一个组播网段前缀（如 239.81.0），程序会自动扫描 .1 - .254。'));
		o.datatype = 'string';
		o.rmempty = false;
		o.validate = function (section_id, value) {
			if (!value) return true;
			if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value))
				return _('格式应为 a.b.c，例如 239.81.0');
			var parts = value.split('.').map(Number);
			if (parts.some(function (n) { return n < 0 || n > 255; }))
				return _('每段必须在 0-255 之间');
			if (parts[0] < 224 || parts[0] > 239)
				return _('网段应在多播范围 224.0.0.0 - 239.255.255.255 内');
			return true;
		};

		var rendered = m.render();

		window.setTimeout(function () { self.refreshStatus(); }, 100);

		poll.add(L.bind(function () {
			return this.refreshStatus();
		}, this), 3);

		return rendered;
	}
});