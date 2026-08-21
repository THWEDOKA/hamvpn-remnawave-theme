(() => {
    const BASE = '/ham-infrastructure/api';
    const state = { inventory: null, ipPlan: null, nodePlan: null, sshCheck: null };
    const $ = (selector, root = document) => root.querySelector(selector);
    const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

    function token() {
        try {
            const stored = JSON.parse(localStorage.getItem('sessionStore') || '{}');
            return stored?.state?.token || stored?.token || '';
        } catch (_) {
            return '';
        }
    }

    async function api(path, options = {}) {
        const currentToken = token();
        if (!currentToken) throw new Error('Сессия панели не найдена. Вернитесь в Remnawave и войдите снова.');
        const response = await fetch(`${BASE}${path}`, {
            ...options,
            headers: {
                Authorization: `Bearer ${currentToken}`,
                'Content-Type': 'application/json',
                ...(options.headers || {})
            }
        });
        let payload = {};
        try { payload = await response.json(); } catch (_) {}
        if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
        return payload;
    }

    function toast(message, error = false) {
        const item = document.createElement('div');
        item.className = `toast${error ? ' error' : ''}`;
        item.textContent = message;
        $('#toasts').append(item);
        setTimeout(() => item.remove(), 5200);
    }

    function busy(button, active, label = 'Выполняется…') {
        if (!button) return;
        if (active) {
            button.dataset.label = button.textContent;
            button.textContent = label;
            button.disabled = true;
        } else {
            button.textContent = button.dataset.label || button.textContent;
            button.disabled = false;
        }
    }

    function escapeHtml(value) {
        return String(value ?? '').replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[char]);
    }

    function showView(name) {
        $$('.view').forEach((view) => view.classList.toggle('active', view.id === `view-${name}`));
        $$('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === name));
        const titles = { overview: 'Инфраструктура', 'node-add': 'Быстрое добавление', 'ip-change': 'Смена IP', history: 'Журнал операций' };
        $('#page-title').textContent = titles[name] || 'Инфраструктура';
        if (name === 'history') loadHistory();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function showStep(number) {
        $$('.form-step').forEach((item) => item.classList.toggle('active', Number(item.dataset.formStep) === number));
        $$('.stepper span').forEach((item) => item.classList.toggle('current', Number(item.dataset.step) === number));
    }

    function renderInventory() {
        const data = state.inventory;
        if (!data) return;
        const values = [
            [data.summary.nodes, 'всего в панели'],
            [data.summary.connectedNodes, `${data.summary.nodes - data.summary.connectedNodes} требуют внимания`],
            [data.summary.hosts, 'клиентских точек'],
            [`${data.summary.profiles} / ${data.summary.squads}`, 'конфигурации доступа']
        ];
        $$('#metrics article').forEach((card, index) => {
            $('strong', card).textContent = values[index][0];
            $('small', card).textContent = values[index][1];
        });
        $('#node-list').innerHTML = data.nodes.slice(0, 8).map((node) => `
            <div class="node-row">
                <i class="${node.isConnected && !node.isDisabled ? 'online' : ''}"></i>
                <div><b>${escapeHtml(node.name)}</b><br><small>${escapeHtml(node.countryCode || 'XX')} · ${escapeHtml(node.profileName || 'без профиля')}</small></div>
                <span class="mono">${escapeHtml(node.address)}:${escapeHtml(node.port)}</span>
                <small>${node.isDisabled ? 'отключена' : node.isConnected ? 'на связи' : 'нет связи'}</small>
            </div>`).join('') || '<div class="empty">Ноды не найдены</div>';

        const profileSelect = $('#profile-select');
        const currentProfile = profileSelect.value;
        profileSelect.innerHTML = '<option value="">Выберите профиль</option>' + data.profiles.map((profile) => `<option value="${escapeHtml(profile.uuid)}">${escapeHtml(profile.name)}</option>`).join('');
        profileSelect.value = currentProfile;
        const nodeSelect = $('#ip-node-select');
        const currentNode = nodeSelect.value;
        nodeSelect.innerHTML = '<option value="">Выберите ноду</option>' + data.nodes.map((node) => `<option value="${escapeHtml(node.uuid)}">${escapeHtml(node.name)} · ${escapeHtml(node.address)}</option>`).join('');
        nodeSelect.value = currentNode;
        renderSquads();
        renderInbounds();
    }

    async function loadInventory() {
        const button = $('#refresh');
        busy(button, true, '…');
        try {
            state.inventory = await api('/inventory');
            renderInventory();
        } catch (error) {
            toast(error.message, true);
            $('#node-list').innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
        } finally {
            busy(button, false);
        }
    }

    function renderInbounds() {
        const profile = state.inventory?.profiles.find((item) => item.uuid === $('#profile-select').value);
        const inbounds = profile?.inbounds || [];
        $('#inbound-choices').innerHTML = inbounds.length ? inbounds.map((item) => `
            <label class="choice"><input type="checkbox" name="inboundUuid" value="${escapeHtml(item.uuid)}"><b>${escapeHtml(item.tag)} · ${escapeHtml(item.type)}</b></label>`).join('') : '<span class="muted">В профиле нет inbound</span>';
        $('#host-inbound-select').innerHTML = '<option value="">Выберите inbound</option>' + inbounds.map((item) => `<option value="${escapeHtml(item.uuid)}">${escapeHtml(item.tag)} · ${escapeHtml(item.type)}</option>`).join('');
    }

    function renderSquads() {
        const squads = state.inventory?.squads || [];
        $('#squad-choices').innerHTML = squads.length ? squads.map((item) => {
            const selected = /(^|\s)BASE($|\s)/i.test(item.name || '') ? ' checked' : '';
            return `<label class="choice"><input type="checkbox" name="squadUuid" value="${escapeHtml(item.uuid)}"${selected}><b>${escapeHtml(item.name)}</b></label>`;
        }).join('') : '<span class="muted">Сквады не найдены</span>';
    }

    function sshPayload() {
        const form = $('#node-form').elements;
        return {
            host: form.sshHost.value.trim(),
            port: Number(form.sshPort.value),
            username: form.sshUser.value.trim(),
            password: form.sshPassword.value,
            privateKey: form.sshPrivateKey.value
        };
    }

    async function checkSsh() {
        const button = $('#ssh-check');
        busy(button, true, 'Проверяем SSH…');
        try {
            const result = await api('/node-add/ssh-preflight', { method: 'POST', body: JSON.stringify({ ssh: sshPayload() }) });
            if (result.existingNode) throw new Error('На сервере уже установлен Remnawave Node. Автоматическая перезапись запрещена.');
            state.sshCheck = result;
            const box = $('#ssh-result');
            box.classList.remove('hidden');
            box.innerHTML = `<b>Сервер готов</b><br>${escapeHtml(result.distribution)} · ${escapeHtml(result.architecture)} · ${escapeHtml(result.docker)}<br><span class="mono">${escapeHtml(result.fingerprint)}</span>`;
            const form = $('#node-form').elements;
            if (!form.nodeAddress.value) form.nodeAddress.value = form.sshHost.value.trim();
            showStep(2);
            toast('SSH и системные требования проверены');
        } catch (error) {
            state.sshCheck = null;
            toast(error.message, true);
        } finally {
            busy(button, false);
        }
    }

    function validateStepTwo() {
        const form = $('#node-form');
        const fields = ['nodeName', 'nodeAddress', 'nodePort', 'countryCode', 'profileUuid'];
        for (const field of fields) if (!form.elements[field].reportValidity()) return false;
        const selected = $$('input[name="inboundUuid"]:checked');
        if (!selected.length) { toast('Выберите хотя бы один inbound', true); return false; }
        if (!form.elements.hostInboundUuid.value) form.elements.hostInboundUuid.value = selected[0].value;
        return true;
    }

    function nodePlanBody() {
        const form = $('#node-form').elements;
        return {
            node: {
                name: form.nodeName.value.trim(), address: form.nodeAddress.value.trim(),
                port: Number(form.nodePort.value), countryCode: form.countryCode.value.trim().toUpperCase(),
                profileUuid: form.profileUuid.value,
                inboundUuids: $$('input[name="inboundUuid"]:checked').map((item) => item.value)
            },
            host: {
                enabled: form.hostEnabled.checked, remark: form.hostRemark.value.trim(),
                address: form.hostAddress.value.trim(), port: Number(form.hostPort.value),
                sni: form.hostSni.value.trim(), fingerprint: form.hostFingerprint.value.trim(),
                inboundUuid: form.hostInboundUuid.value,
                squadUuids: $$('input[name="squadUuid"]:checked').map((item) => item.value)
            }
        };
    }

    async function createNodePlan() {
        if (!state.sshCheck) { showStep(1); toast('Сначала повторно проверьте SSH', true); return; }
        const form = $('#node-form');
        if (form.elements.hostEnabled.checked && !form.elements.hostInboundUuid.value) { toast('Выберите inbound хоста', true); return; }
        const button = $('#node-plan');
        busy(button, true, 'Строим план…');
        try {
            state.nodePlan = await api('/node-add/plan', { method: 'POST', body: JSON.stringify(nodePlanBody()) });
            const plan = state.nodePlan;
            $('#node-plan-result').innerHTML = `
                <div class="plan-line"><span>Нода</span><b>${escapeHtml(plan.node.name)} · ${escapeHtml(plan.node.address)}:${escapeHtml(plan.node.port)}</b></div>
                <div class="plan-line"><span>Профиль</span><b>${escapeHtml(plan.node.profileName)} · inbound: ${plan.node.inboundUuids.length}</b></div>
                <div class="plan-line"><span>Хост</span><b>${plan.host.enabled ? `${escapeHtml(plan.host.remark)} · ${escapeHtml(plan.host.address)}:${escapeHtml(plan.host.port)}` : 'не создаётся'}</b></div>
                <div class="plan-line"><span>Доступ</span><b>${plan.host.squadUuids.length} сквад(а), исключено ${plan.host.excludedSquadUuids.length}</b></div>
                <div class="notice amber"><b>Будет выполнено</b><span>Установка Docker/Node, отдельное правило файрвола только для Node Port, создание ноды и хоста, затем проверка связи.</span></div>`;
            form.elements.nodeConfirmation.value = '';
            showStep(4);
        } catch (error) { toast(error.message, true); }
        finally { busy(button, false); }
    }

    async function applyNode() {
        if (!state.nodePlan || !state.sshCheck) return;
        const button = $('#node-apply');
        busy(button, true, 'Установка и проверка…');
        try {
            const result = await api('/node-add/apply', {
                method: 'POST',
                body: JSON.stringify({
                    operationId: state.nodePlan.operationId,
                    confirmation: $('#node-form').elements.nodeConfirmation.value,
                    expectedFingerprint: state.sshCheck.fingerprint,
                    ssh: sshPayload()
                })
            });
            toast(`Нода добавлена и проверена · ${result.nodeUuid}`);
            $('#node-form').reset();
            state.nodePlan = null; state.sshCheck = null;
            await loadInventory();
            showView('overview'); showStep(1);
        } catch (error) { toast(error.message, true); }
        finally { busy(button, false); }
    }

    async function createIpPlan(event) {
        event.preventDefault();
        const form = event.currentTarget;
        const button = $('button[type="submit"]', form);
        busy(button, true, 'Ищем зависимости…');
        try {
            state.ipPlan = await api('/ip-change/plan', {
                method: 'POST', body: JSON.stringify({ nodeUuid: form.elements.nodeUuid.value, newAddress: form.elements.newAddress.value.trim() })
            });
            const plan = state.ipPlan;
            $('#ip-plan-status').textContent = 'план готов';
            const hosts = plan.hosts.map((item) => `<div class="dependency-child"><b>Хост · ${escapeHtml(item.remark)}</b><small>${item.willChange ? `${escapeHtml(item.oldAddress)} → ${escapeHtml(item.newAddress)}` : 'связан, адрес не меняется'}</small></div>`).join('');
            const profiles = plan.profiles.map((item) => `<div class="dependency-child"><b>Профиль · ${escapeHtml(item.name)}</b><small>${item.matches} точных вхождений IP</small></div>`).join('');
            const warnings = plan.warnings.map((item) => `<div class="notice amber"><b>Проверить вручную</b><span>${escapeHtml(item)}</span></div>`).join('');
            $('#ip-plan-result').className = 'dependency-tree';
            $('#ip-plan-result').innerHTML = `
                <div class="dependency-root"><b>${escapeHtml(plan.node.name)}</b><small>${escapeHtml(plan.node.oldAddress)} → ${escapeHtml(plan.node.newAddress)} · порт ${escapeHtml(plan.node.port)}</small></div>
                ${hosts || '<div class="dependency-child"><b>Связанных хостов нет</b><small>Изменится только адрес ноды</small></div>'}
                ${profiles}${warnings}
                <div class="plan-line"><span>Итого</span><b>1 нода · ${plan.impact.hosts} хостов · ${plan.impact.profileValues} значений профилей</b></div>`;
            $('#ip-confirm-wrap').classList.remove('hidden');
            $('#ip-confirmation').value = '';
        } catch (error) { toast(error.message, true); }
        finally { busy(button, false); }
    }

    async function applyIp() {
        if (!state.ipPlan) return;
        const button = $('#ip-apply');
        busy(button, true, 'Применяем и проверяем…');
        try {
            const result = await api('/ip-change/apply', {
                method: 'POST', body: JSON.stringify({ operationId: state.ipPlan.operationId, confirmation: $('#ip-confirmation').value })
            });
            toast(result.warning || `IP изменён и подтверждён: ${result.newAddress}`);
            state.ipPlan = null;
            $('#ip-confirm-wrap').classList.add('hidden');
            $('#ip-plan-status').textContent = 'выполнено';
            await loadInventory();
        } catch (error) { toast(error.message, true); }
        finally { busy(button, false); }
    }

    async function loadHistory() {
        try {
            const data = await api('/operations');
            $('#history-list').innerHTML = data.operations.length ? data.operations.map((item) => `
                <div class="history-row">
                    <span>${item.type === 'node-add' ? 'Добавление' : 'Смена IP'}</span>
                    <b>${escapeHtml(item.resource)}</b>
                    <small>${new Date(item.createdAt).toLocaleString('ru-RU')}</small>
                    <span class="state ${escapeHtml(item.state)}">${escapeHtml(item.state)}</span>
                </div>`).join('') : '<div class="empty">Операций пока нет</div>';
        } catch (error) { $('#history-list').innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`; }
    }

    $$('.nav-item').forEach((button) => button.addEventListener('click', () => showView(button.dataset.view)));
    $$('[data-go]').forEach((button) => button.addEventListener('click', () => showView(button.dataset.go)));
    $$('[data-prev]').forEach((button) => button.addEventListener('click', () => showStep(Number(button.dataset.prev))));
    $$('[data-next]').forEach((button) => button.addEventListener('click', () => {
        if (Number(button.dataset.next) === 3 && !validateStepTwo()) return;
        showStep(Number(button.dataset.next));
    }));
    $('#refresh').addEventListener('click', loadInventory);
    $('#history-refresh').addEventListener('click', loadHistory);
    $('#profile-select').addEventListener('change', renderInbounds);
    $('#ssh-check').addEventListener('click', checkSsh);
    $('#node-plan').addEventListener('click', createNodePlan);
    $('#node-apply').addEventListener('click', applyNode);
    $('#ip-form').addEventListener('submit', createIpPlan);
    $('#ip-apply').addEventListener('click', applyIp);
    $('#node-form').elements.sshHost.addEventListener('input', () => { state.sshCheck = null; });
    loadInventory();
})();

