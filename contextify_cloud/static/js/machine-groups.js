/* Group controls use the existing session and CSRF boundary. No secret persistence. */
(() => {
  'use strict';
  const el = id => document.getElementById(id);
  if (!el('machine-groups')) return;
  let state, selected, secret, tokenId, tokenOffset = 0, tokenRequest = 0, tokenLoading = false, tokenHasMore = false;
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || '';
  const error = e => { el('group-error').textContent = e.message; };
  const announce = text => { el('group-result').textContent = text; el('group-error').textContent = ''; };
  function node(tag, text, cls) {
    const n = document.createElement(tag); if (text) n.textContent = text;
    if (cls) n.className = cls; return n;
  }
  function timestamp(value, fallback) {
    const time = node('time', fallback);
    if (!value) return time;
    const date = new Date(value); time.title = value; time.dateTime = value;
    if (!Number.isNaN(date.getTime())) time.textContent = date.toLocaleString('en-US', {
      month:'short', day:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit',
      second:'2-digit', hour12:false, timeZone:'UTC'
    }) + ' UTC';
    return time;
  }
  function selectStyle() {
    el('group-list').querySelectorAll('button').forEach(button => {
      const active = button.dataset.groupId === selected?.id;
      button.setAttribute('aria-expanded', String(active));
      if (active) button.setAttribute('aria-current', 'true'); else button.removeAttribute('aria-current');
      button.classList.toggle('fw-bold', active);
      button.parentElement.classList.toggle('border-primary', active);
      button.parentElement.classList.toggle('bg-primary-subtle', active);
    });
  }
  async function action(name, payload = {}, extra = {}) {
    const r = await fetch('/cloud/sync/groups/action', {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf()},
      body: JSON.stringify({action: name, group_id: selected?.id, payload, ...extra})
    });
    const body = await r.json();
    if (!r.ok) {
      const fields = body.detail?.fields;
      throw new Error(fields?.length ? fields.map(f => `${f.field}: ${f.message}`).join('; ') :
        typeof body.detail === 'string' ? body.detail : body.detail?.message || 'Refresh group details and retry');
    }
    return body;
  }
  function clearSecret() {
    secret = null; tokenId = null; el('group-token-secret').textContent = '';
    el('group-token-delivery').hidden = true;
  }
  async function refresh(focusId) {
    const r = await fetch('/cloud/sync/groups');
    if (!r.ok) throw new Error('Could not load machine groups');
    state = await r.json();
    const list = el('group-list'); list.replaceChildren();
    const projectPicker = el('group-project'), oldProject = projectPicker.value;
    projectPicker.replaceChildren();
    const allProjects = node('option', 'All authorized projects'); allProjects.value = '';
    projectPicker.append(allProjects);
    (state.available_projects || []).forEach(p => {
      const option = node('option', p.name + ' · ' + p.id); option.value = p.id;
      projectPicker.append(option);
    });
    projectPicker.value = oldProject;
    el('group-empty').hidden = state.groups.length > 0;
    el('group-management-disabled').hidden = state.can_create;
    el('group-create').querySelectorAll('input,select,button').forEach(x => { x.disabled = !state.can_create; });
    el('group-visibility').querySelector('[value="team"]').disabled = !state.can_create_team;
    const noticeKey = 'machine-groups-dismissed:' + state.user_id;
    let dismissed = false; try { dismissed = localStorage.getItem(noticeKey) === '1'; } catch (_) { /* optional */ }
    el('group-upgrade-notice').hidden = state.capabilities.machine_groups !== 'allowed_with_upgrade_notice' || dismissed;
    el('group-upgrade-link').href = state.capabilities.upgrade_url || '#';
    el('group-upgrade-dismiss').onclick = () => {
      try { localStorage.setItem(noticeKey, '1'); } catch (_) { /* optional */ }
      el('group-upgrade-notice').hidden = true; el('groups-heading').focus();
    };
    state.groups.forEach(g => {
      const li = node('li', null, 'list-group-item'); li.id = 'group-row-' + g.id;
      const button = node('button', g.name, 'btn btn-link');
      button.dataset.groupId = g.id; button.setAttribute('aria-controls', 'group-detail');
      button.onclick = () => { clearSecret(); selected = g; tokenOffset = 0;
        el('group-token-inactive').checked = false; renderDetail(); el('group-detail-heading').focus(); };
      li.append(button, node('small', ` ${g.id.slice(0,8)} · ${g.visibility} · ${g.active_count} active · ${g.retired_count} retired`));
      list.append(li);
    });
    if (selected) { selected = state.groups.find(g => g.id === selected.id); if (selected) renderDetail(); }
    selectStyle();
    if (focusId) el(focusId)?.focus();
  }
  function renderDetail() {
    const g = selected; selectStyle(); el('group-detail').hidden = false;
    el('group-detail-heading').textContent = g.name;
    el('group-detail-description').textContent = `${g.id} · ${g.visibility} · Synced history only` +
      (g.project_selector ? ` · ${g.project_selector.kind}: ${g.project_selector.value}` : ' · All authorized projects');
    el('group-new-name').value = g.name;
    el('group-rename').querySelectorAll('input,button').forEach(x => { x.disabled = !g.can_manage; });
    el('group-device-add').querySelectorAll('select,button').forEach(x => { x.disabled = !g.can_manage; });
    const picker = el('group-add-device'); picker.replaceChildren();
    state.available_devices.filter(d => !d.retired &&
      (g.visibility === 'team' || d.owner_user_id === g.owner_user_id)).forEach(d => {
      const o = node('option', `${d.name} · ${d.short_id}`); o.value = d.device_record_id; picker.append(o);
    });
    el('group-active-devices').replaceChildren(); el('group-retired-devices').replaceChildren();
    const logical = new Map();
    g.devices.forEach(d => { if (!logical.has(d.canonical_record_id)) logical.set(d.canonical_record_id, []); logical.get(d.canonical_record_id).push(d); });
    logical.forEach(members => {
      const d = members.find(x => x.device_record_id === x.canonical_record_id) || members[0];
      const li = node('li', null, 'list-group-item'); li.id = 'group-device-row-' + d.device_record_id;
      li.append(node('strong', d.name), node('small', ` · ${d.short_id}`, 'text-secondary'));
      const id = node('div', d.device_id); id.dataset.role = 'group-device-id'; li.append(id);
      const status = node('div', `${d.physically_active ? d.state : "retired device"} · ${d.owner_name || 'Account user'} · Last seen: `);
      status.append(timestamp(d.last_seen_at, 'unknown'), ' · Last push: ', timestamp(d.last_push_at, 'never'));
      status.dataset.role = 'group-device-state'; li.append(status);
      if (members.length > 1) li.append(node('div', 'Includes: ' + members.map(x => `${x.device_id} (${x.physically_active ? x.state : "retired device"})`).join(', ')));
      const remove = node('button', `Remove ${d.name}`, 'btn btn-sm btn-outline-danger');
      remove.dataset.action = 'group-device-remove';
      remove.disabled = !g.can_manage && !(state.can_create && d.owner_user_id === state.user_id);
      remove.onclick = async () => { try {
        await action('remove', {device_record_id:d.device_record_id, expected_revision:g.revision});
        await refresh('group-detail-heading'); announce('Device removed. Ordinary search history is unchanged.');
      } catch (e) { error(e); } };
      li.append(remove);
      el(members.some(x => x.state === 'active' && x.physically_active) ? 'group-active-devices' : 'group-retired-devices').append(li);
    });
    el('group-devices-empty').textContent = g.devices.length ? 'No active devices in this group' : 'No devices in this group yet';
    el('group-devices-empty').hidden = el('group-active-devices').childElementCount > 0;
    el('group-retired-devices-empty').hidden = el('group-retired-devices').childElementCount > 0;
    el('group-tokens').hidden = !g.can_manage || g.visibility !== 'team';
    el('group-setup-copy-teammate').hidden = g.visibility !== 'team';
    if (g.can_manage && g.visibility === 'team') loadTokens().catch(error);
  }
  async function loadTokens() {
    const groupId = selected.id, request = ++tokenRequest;
    tokenLoading = true;
    el('group-token-previous').disabled = true; el('group-token-next').disabled = true;
    try {
    const result = await action('tokens', {include_inactive:el('group-token-inactive').checked, limit:50, offset:tokenOffset});
    if (selected?.id !== groupId || request !== tokenRequest) return;
    const list = el('group-token-list'); list.replaceChildren();
    result.tokens.forEach(t => {
      const li = node('li', `${t.id} · ${t.state.replace('_', ', ')} · ${t.uses}/${t.max_uses} uses · Expires `, 'list-group-item');
      li.append(timestamp(t.expires_at, 'unknown'));
      li.id = 'group-token-row-' + t.id;
      if (t.state === 'issued_unsaved') li.append(node('p', 'Secret delivery has not been confirmed'));
      const revoke = node('button', 'Revoke token ' + t.id.slice(0,8), 'btn btn-sm btn-outline-danger');
      revoke.dataset.action = 'group-token-revoke'; revoke.disabled = !!t.revoked_at;
      revoke.onclick = async () => { try { await action('revoke', {}, {token_id:t.id});
        if (tokenId === t.id) clearSecret(); tokenOffset = 0; await loadTokens(); el('group-detail-heading').focus(); announce('Token revoked');
      } catch(e) { error(e); } };
      li.append(revoke); list.append(li);
    });
    el('group-tokens-empty').hidden = result.tokens.length > 0;
    el('group-tokens-empty').textContent = el('group-token-inactive').checked ?
      'No join tokens issued' : 'No join tokens issued in this view. Show revoked and expired tokens to view earlier issues.';
    tokenHasMore = result.has_more;
    el('group-token-page').textContent = `Page ${Math.floor(tokenOffset / 50) + 1}`;
    } finally {
      if (request === tokenRequest) {
        tokenLoading = false;
        el('group-token-previous').disabled = tokenOffset === 0;
        el('group-token-next').disabled = !tokenHasMore;
      }
    }
  }
  async function tokenPage(offset) {
    if (tokenLoading) return;
    const prior = tokenOffset; tokenOffset = offset;
    try { await loadTokens(); } catch(e) {
      tokenOffset = prior; el('group-token-previous').disabled = prior === 0; error(e);
    }
  }
  el('group-token-inactive').onchange = () => { tokenOffset = 0; loadTokens().catch(error); };
  el('group-token-previous').onclick = () => { tokenPage(Math.max(0, tokenOffset - 50)); };
  el('group-token-next').onclick = () => { tokenPage(tokenOffset + 50); };
  el('group-create').onsubmit = async e => { e.preventDefault(); try {
    const project = el('group-project').value.trim();
    tokenOffset = 0; el('group-token-inactive').checked = false;
    selected = await action('create', {name:el('group-name').value, visibility:el('group-visibility').value,
      project_selector: project ? {kind:'project_id', value:project} : null});
    await refresh('group-detail-heading'); announce('Group created');
  } catch(e) { error(e); } };
  el('group-rename').onsubmit = async e => { e.preventDefault(); try {
    await action('edit', {name:el('group-new-name').value, expected_revision:selected.revision});
    await refresh('group-new-name'); announce('Group renamed');
  } catch(e) { error(e); } };
  el('group-device-add').onsubmit = async e => { e.preventDefault(); try {
    await action('add', {device_record_id:el('group-add-device').value, expected_revision:selected.revision});
    await refresh('group-add-device'); announce('Device added, including its already-synced history');
  } catch(e) { error(e); } };
  el('group-show-retired').onclick = () => {
    const button = el('group-show-retired'), list = el('group-retired-devices');
    list.hidden = !list.hidden; el('group-retired-section').hidden = list.hidden; button.setAttribute('aria-expanded', String(!list.hidden));
    button.textContent = list.hidden ? 'Show retired memberships' : 'Hide retired memberships';
  };
  el('group-token-create').onsubmit = async e => { e.preventDefault(); clearSecret(); try {
    const t = await action('issue', {create_request_id:crypto.randomUUID(), expires_in:Number(el('group-token-expiry').value), max_uses:Number(el('group-token-max-uses').value)});
    tokenOffset = 0; secret = t.secret; tokenId = t.id; el('group-token-secret').textContent = secret;
    el('group-token-delivery').hidden = false; await loadTokens(); el('group-token-copy').focus();
    announce('Token issued. Secret delivery has not been confirmed.');
  } catch(e) { error(e); } };
  async function delivered() {
    await action('acknowledge', {}, {token_id:tokenId}); clearSecret();
    await loadTokens(); el('group-token-create').querySelector('button').focus(); announce('Token delivery acknowledged');
  }
  el('group-token-copy').onclick = async () => { try { await navigator.clipboard.writeText(secret); await delivered(); } catch(e) { error(e); } };
  el('group-token-download').onclick = async () => { try {
    const url = URL.createObjectURL(new Blob([secret + '\n'], {type:'text/plain'}));
    const a = node('a'); a.href = url; a.download = 'group-join.token'; a.click(); URL.revokeObjectURL(url); await delivered();
  } catch(e) { error(e); } };
  el('group-token-close').onclick = () => { clearSecret(); el('group-token-create').querySelector('button').focus(); };
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && secret) { clearSecret(); el('group-token-create').querySelector('button').focus(); } });
  ['owner','teammate'].forEach(kind => { el('group-setup-copy-' + kind).onclick = async () => { try {
    const command = `contextify cloud setup --url ${location.origin} --join-group ${selected.id} --key-file /run/secrets/contextify-api-key` +
      (kind === 'teammate' ? ' --join-token-file /run/secrets/group-join' : '') + ' --no-input --json';
    await navigator.clipboard.writeText(command); announce('Setup command copied; supply your own secret file');
  } catch(e) { error(e); } }; });
  refresh().catch(error);
})();
