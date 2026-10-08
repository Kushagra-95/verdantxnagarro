'use strict';
const $ = s => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ALL_SECTIONS = ['kpis', 'rollups', 'chart', 'spotlight', 'sensitivity', 'queue', 'approvals', 'audit', 'replay'];
const ALL_KPIS = ['avoided', 'reduction', 'weekly', 'approvals'];
const ALL_ZONES = ['DE', 'US-CAL-CISO', 'IN-WE', 'GB'];
let directory, identity;
async function api(path, method='GET', body) {
  const r=await fetch(path,{method,headers:{'Content-Type':'application/json'},...(body ? {body:JSON.stringify(body)} : {})});
  if(r.status===401){location.assign('/login');throw new Error('Sign in required');}
  const data=await r.json();
  if(!r.ok)throw new Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail));
  return data;
}
function message(text,error=false){$('#admin-message').textContent=text;$('#admin-message').className=error?'form-error':'notice';}
function projectSelection(form){const tid=form.elements.tenant_id.value;form.elements.project_id.innerHTML=directory.projects.filter(p=>p.tenant_id===tid).map(p=>`<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');form.elements.project_id.disabled=form.elements.role.value==='client_admin';}
function policySelection(){const f=$('#policy-form'),p=directory.projects.find(p=>p.id===f.elements.project_id.value);if(p)for(const key of ['threshold_pct','threshold_g','safety_min','monthly_budget_g']){f.elements[key].value=p[key]??'';if(directory.guardrails[key]!==undefined)f.elements[key].min=directory.guardrails[key];}}
function providerSelection(){const e=directory.environments.find(e=>e.id===$('#provider-form').elements.environment_id.value);if(e){$('#provider-form').elements.provider.value=e.provider;$('#credential-hint').textContent=`Credential: ${e.credential_variable} · ${e.credential_configured?'configured':'not configured'}`;}}
function consentSelection(){const t=directory.tenants.find(t=>t.id===$('#consent-form').elements.tenant_id.value);$('#consent-form').elements.share_aggregate.checked=!!t?.share_aggregate;}
function projectViewHtml(p) {
  const v = p.view || {visible_sections: ALL_SECTIONS, visible_kpis: ALL_KPIS, allowed_zones: [], show_decision_log: true, show_flexibility: true, allow_export: true};
  return `<div class="project-entry" style="margin: 10px 0 16px 14px; padding: 12px; background: var(--panel2); border-radius: 8px; border: 1px solid var(--line);">
    <p><strong>${esc(p.name)}</strong> · <small>Project ID: ${esc(p.id)}</small></p>
    ${directory.environments.filter(e=>e.project_id===p.id).map(e=>`<p><a class="text-link" href="/?environment_id=${encodeURIComponent(e.id)}">Open ${esc(e.name)} →</a><small>${esc(e.id)} · ${esc(e.provider)}</small></p>`).join('')}
    <details class="project-view-panel" style="margin-top: 10px;">
      <summary style="cursor: pointer; font-size: 11px; color: var(--green);">⚙ Client view</summary>
      <form class="project-view-form account-form" data-project-id="${esc(p.id)}" style="padding: 10px 0 0; gap: 10px;">
        <label><strong>Visible sections</strong>
          <span style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px;">
            ${ALL_SECTIONS.map(s => `<label style="display: flex; align-items: center; gap: 4px; font-size: 11px;"><input type="checkbox" name="visible_sections" value="${esc(s)}" ${v.visible_sections.includes(s) ? 'checked' : ''}> ${esc(s)}</label>`).join('')}
          </span>
        </label>
        <label><strong>Visible KPIs</strong>
          <span style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px;">
            ${ALL_KPIS.map(k => `<label style="display: flex; align-items: center; gap: 4px; font-size: 11px;"><input type="checkbox" name="visible_kpis" value="${esc(k)}" ${v.visible_kpis.includes(k) ? 'checked' : ''}> ${esc(k)}</label>`).join('')}
          </span>
        </label>
        <label><strong>Allowed zones</strong> <small class="muted">(empty = all)</small>
          <span style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px;">
            ${ALL_ZONES.map(z => `<label style="display: flex; align-items: center; gap: 4px; font-size: 11px;"><input type="checkbox" name="allowed_zones" value="${esc(z)}" ${v.allowed_zones.includes(z) ? 'checked' : ''}> ${esc(z)}</label>`).join('')}
          </span>
        </label>
        <label><strong>Feature toggles</strong>
          <span style="display: flex; flex-direction: column; gap: 6px; margin-top: 4px;">
            <label style="display: flex; align-items: center; gap: 6px; font-size: 11px;"><input type="checkbox" name="show_decision_log" ${v.show_decision_log ? 'checked' : ''}> Show decision log</label>
            <label style="display: flex; align-items: center; gap: 6px; font-size: 11px;"><input type="checkbox" name="show_flexibility" ${v.show_flexibility ? 'checked' : ''}> Show flexibility sensitivity</label>
            <label style="display: flex; align-items: center; gap: 6px; font-size: 11px;"><input type="checkbox" name="allow_export" ${v.allow_export ? 'checked' : ''}> Allow SCI report export</label>
          </span>
        </label>
        <div style="display: flex; align-items: center; gap: 10px; margin-top: 6px;">
          <button type="submit" class="secondary" style="padding: 6px 14px;">Save view</button>
          <span class="view-status-msg" aria-live="polite" style="font-size: 11px;"></span>
        </div>
      </form>
    </details>
  </div>`;
}
async function load(){
  identity=await api('/api/auth/me');directory=await api('/api/admin/directory');
  $('#identity').textContent=`${identity.user.display_name} · ${identity.user.username}`;
  $('#tenant-form').hidden=!identity.user.platform_admin;
  $('#admin-forms').hidden=!identity.user.platform_admin&&!directory.tenants.length;
  $('#members-section').hidden=!identity.user.platform_admin&&!directory.tenants.length;
  $('#org-section').hidden=!identity.user.platform_admin;
  $('#directory-list').innerHTML=directory.tenants.map(t=>`<div class="directory-item"><h3>${esc(t.name)}</h3><small>Client ID: ${esc(t.id)} · Aggregate sharing: ${t.share_aggregate?'authorized':'off'}</small>${directory.projects.filter(p=>p.tenant_id===t.id).map(projectViewHtml).join('')}</div>`).join('')||'<p>No administered clients. Ask your administrator for workspace access.</p>';
  for(const [cls,items] of [['tenant',directory.tenants],['project',directory.projects],['environment',directory.environments]])document.querySelectorAll(`.${cls}-options`).forEach(select=>{const prev=select.value;select.innerHTML=items.map(i=>`<option value="${esc(i.id)}">${esc(i.tenant_name?i.tenant_name+' / '+i.project_name+' / ':cls==='project'?(directory.tenants.find(t=>t.id===i.tenant_id)?.name||'')+' / ':'')}${esc(i.name)}</option>`).join('');if(items.some(i=>i.id===prev))select.value=prev;});
  for(const id of ['user','membership'])projectSelection($(`#${id}-form`));
  policySelection();providerSelection();consentSelection();
  $('#member-list').innerHTML=directory.memberships.map(m=>`<div class="directory-item"><strong>${esc(m.display_name)}</strong> (${esc(m.username)}) · ${esc(m.role)}<p>${esc(m.tenant_id)} / ${esc(m.project_id||'All client projects')}</p><small>User ID: ${esc(m.user_id)}</small> <button class="secondary" data-revoke="${m.id}">Revoke role</button></div>`).join('')||'<p>No scoped memberships yet.</p>';
}
function form(id,handler){$(id).addEventListener('submit',async event=>{event.preventDefault();const f=event.target,b=f.querySelector('button');b.disabled=true;try{await handler(Object.fromEntries(new FormData(f)),f);message('Saved.');await load();}catch(e){message(e.message,true);}finally{b.disabled=false;}});}
form('#tenant-form',d=>api('/api/admin/tenants','POST',d));
form('#project-form',d=>api('/api/admin/projects','POST',d));
form('#environment-form',d=>api('/api/admin/environments','POST',d));
for(const [id,path] of [['user','users'],['membership','memberships']]){
  form(`#${id}-form`,async(d,f)=>{if(d.role==='client_admin')d.project_id=null;await api(`/api/admin/${path}`,'POST',d);if(f.elements.password)f.elements.password.value='';});
  for(const field of ['tenant_id','role'])$(`#${id}-form`).elements[field].addEventListener('change',()=>projectSelection($(`#${id}-form`)));
}
form('#policy-form',({project_id,...d})=>api(`/api/admin/projects/${encodeURIComponent(project_id)}/policy`,'PUT',Object.fromEntries(Object.entries(d).map(([k,v])=>[k,v===''?null:Number(v)]))));
$('#policy-form').elements.project_id.addEventListener('change',policySelection);
form('#provider-form',d=>{const e=directory.environments.find(e=>e.id===d.environment_id);return api(`/api/admin/environments/${encodeURIComponent(e.id)}/provider`,'PUT',{name:e.name,project_id:e.project_id,provider:d.provider});});
$('#provider-form').elements.environment_id.addEventListener('change',providerSelection);
form('#consent-form',(d,f)=>api(`/api/admin/tenants/${encodeURIComponent(d.tenant_id)}/reporting`,'PUT',{share_aggregate:f.elements.share_aggregate.checked}));
$('#consent-form').elements.tenant_id.addEventListener('change',consentSelection);
form('#password-form',async d=>{await api('/api/auth/password','POST',d);location.assign('/login');});
$('#directory-list').addEventListener('submit',async event=>{
  const f=event.target.closest('.project-view-form');
  if(!f)return;
  event.preventDefault();
  const pid=f.dataset.projectId;
  const btn=f.querySelector('button');
  const msg=f.querySelector('.view-status-msg');
  btn.disabled=true;
  msg.textContent='';
  msg.className='view-status-msg';
  try{
    const visible_sections=[...f.querySelectorAll('input[name="visible_sections"]:checked')].map(i=>i.value);
    const visible_kpis=[...f.querySelectorAll('input[name="visible_kpis"]:checked')].map(i=>i.value);
    const allowed_zones=[...f.querySelectorAll('input[name="allowed_zones"]:checked')].map(i=>i.value);
    const show_decision_log=f.elements.show_decision_log.checked;
    const show_flexibility=f.elements.show_flexibility.checked;
    const allow_export=f.elements.allow_export.checked;
    await api(`/api/admin/projects/${encodeURIComponent(pid)}/view`,'PUT',{
      visible_sections,visible_kpis,allowed_zones,
      show_decision_log,show_flexibility,allow_export
    });
    msg.textContent='Saved.';
    msg.style.color='var(--green)';
    message('Client view saved.');
  }catch(err){
    msg.textContent=err.message;
    msg.style.color='var(--red)';
    message(err.message,true);
  }finally{
    btn.disabled=false;
  }
});
$('#member-list').addEventListener('click',async event=>{const b=event.target.closest('[data-revoke]');if(!b)return;try{await api(`/api/admin/memberships/${b.dataset.revoke}`,'DELETE');message('Role revoked.');await load();}catch(e){message(e.message,true);}});
$('#org-refresh').addEventListener('click',async()=>{try{const r=await api('/api/organization/report');$('#org-report').innerHTML=`<p>${esc(r.source)} · ${Number(r.avoided_g).toLocaleString()} g modeled avoided · ${r.reduction_pct.toFixed(1)}% reduction</p><p>${esc(r.scope)}</p>`+r.environments.map(e=>`<p>${esc(e.client)} / ${esc(e.project)} / ${esc(e.environment)}: ${Number(e.avoided_g).toLocaleString()} g · ${esc(e.source)}</p>`).join('');}catch(e){message(e.message,true);}});
load().catch(e=>message(e.message,true));
