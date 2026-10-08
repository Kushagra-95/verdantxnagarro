"""Essential access-boundary checks, using one isolated in-memory application."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.access import Directory
from app.api.main import create_app
from app.config import Settings

PASSWORD = "local-security-test-only"


@pytest.fixture(scope="module")
def scenario():
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("VERDANT_ADMIN_PASSWORD", PASSWORD)
        app = create_app(Settings(database_path=":memory:", electricity_token="legacy-private-token"))
        with TestClient(app) as admin:
            assert admin.post("/api/auth/login", json={"username": "admin", "password": PASSWORD}).status_code == 200
            def create(path, data):
                r = admin.post('/api/admin/' + path, json=data)
                assert r.status_code == 201, r.text
                return r.json()
            a = create('tenants', {'name': 'Client A'})['id']
            b = create('tenants', {'name': 'Client B'})['id']
            pa = create('projects', {'tenant_id': a, 'name': 'Analytics'})['id']
            pb = create('projects', {'tenant_id': b, 'name': 'Analytics'})['id']
            pc = create('projects', {'tenant_id': a, 'name': 'Restricted project'})['id']
            ea = create('environments', {'project_id': pa, 'name': 'Dev'})['id']
            eb = create('environments', {'project_id': pb, 'name': 'Dev'})['id']
            ec = create('environments', {'project_id': pc, 'name': 'Dev'})['id']
            prod = create('environments', {'project_id': pa, 'name': 'Production'})['id']
            accounts = {}
            for role in ('viewer', 'project_operator', 'approver', 'client_admin'):
                record = create('users', {'username': role, 'display_name': role, 'password': PASSWORD,
                                         'tenant_id': a, 'project_id': None if role == 'client_admin' else pa, 'role': role})
                c = TestClient(app)
                assert c.post('/api/auth/login', json={'username': role, 'password': PASSWORD}).status_code == 200
                accounts[role] = (c, record['id'])
            yield {'app': app, 'admin': admin, 'accounts': accounts, 'a': a, 'b': b, 'pa': pa, 'pb': pb, 'ea': ea, 'eb': eb, 'ec': ec, 'prod': prod}
            for c, _ in accounts.values():
                c.close()


def test_signin_csrf_and_password_revocation(scenario):
    app = scenario['app']
    c = TestClient(app, follow_redirects=False)
    assert c.get('/').status_code == 303
    for path in ('/api/state', '/api/jobs', '/api/logs', '/api/report/export', '/api/admin/directory', '/api/organization/report'):
        assert c.get(path).status_code == 401
    assert c.post('/api/auth/login', json={'username': 'admin', 'password': 'wrong'}).status_code == 401
    r = c.post('/api/auth/login', json={'username': 'admin', 'password': PASSWORD})
    assert r.status_code == 200
    assert 'HttpOnly' in r.headers['set-cookie'] and 'SameSite=strict' in r.headers['set-cookie']
    assert c.post('/api/demo/reset', headers={'Origin': 'https://unrelated.example'}).status_code == 403
    assert c.post('/api/auth/logout').status_code == 200
    assert c.get('/api/auth/me').status_code == 401
    c.close()
    # Password change invalidates all outstanding sessions for that identity.
    admin = scenario['admin']
    admin.post('/api/admin/users', json={'username': 'password_user', 'display_name': 'Password user', 'password': PASSWORD,
                                       'tenant_id': scenario['a'], 'project_id': scenario['pa'], 'role': 'viewer'}).raise_for_status()
    first, second = TestClient(app), TestClient(app)
    for c in (first, second):
        c.post('/api/auth/login', json={'username': 'password_user', 'password': PASSWORD}).raise_for_status()
    assert first.post('/api/auth/password', json={'current_password': PASSWORD, 'new_password': PASSWORD + '-changed'}).status_code == 200
    assert second.get('/api/auth/me').status_code == 401
    first.close(); second.close()


def test_all_workspace_routes_deny_cross_client_and_project(scenario):
    viewer = scenario['accounts']['viewer'][0]
    for env in (scenario['eb'], scenario['ec']):
        for path in ('/api/state','/api/jobs','/api/jobs/demo-01/curve','/api/approvals','/api/logs?all_runs=true',
                     '/api/logs/1/evidence','/api/report','/api/report/export?format=csv',
                     '/api/report/export?scope=replay','/api/analysis/flexibility'):
            assert viewer.get(path, headers={'X-Environment-ID': env}).status_code == 404, path
        for path, body in (('/api/agent/cycle', {}),('/api/demo/reset', {}),('/api/demo/scale', {'n': 1}),
                           ('/api/demo/replay', {}),('/api/clock/advance', {'minutes': 1}),
                           ('/api/approvals/demo-01', {'action':'reject','comment':'x'})):
            assert viewer.post(path, json=body, headers={'X-Environment-ID':env}).status_code == 404, path
    assert viewer.get('/api/state', headers={'X-Environment-ID': scenario['ea']}).status_code == 200
    assert viewer.get('/api/state').status_code == 400  # no ambiguous implicit workspace
    assert viewer.post('/api/demo/reset', headers={'X-Environment-ID': scenario['ea']}).status_code == 403
    assert viewer.get('/api/organization/report').status_code == 403


def test_environment_state_evidence_exports_and_dependencies_are_isolated(scenario):
    c = scenario['admin']; a, b, prod = scenario['ea'], scenario['eb'], scenario['prod']
    assert c.get('/api/jobs', headers={'X-Environment-ID': b}).json() == []
    c.post('/api/demo/reset', headers={'X-Environment-ID': a}).raise_for_status()
    r = c.post('/api/agent/cycle', headers={'X-Environment-ID': a})
    assert r.json()['processed'] == 25
    assert c.post('/api/agent/cycle', headers={'X-Environment-ID': a}).json()['processed'] == 0
    state = c.get('/api/state', headers={'X-Environment-ID': a}).json()
    assert all(j['environment_id'] == a and j['project_id'] == scenario['pa'] for j in state['jobs'])
    for target in (b, prod):
        assert c.get('/api/jobs', headers={'X-Environment-ID': target}).json() == []
        assert c.get('/api/logs/1/evidence', headers={'X-Environment-ID': target}).status_code == 404
        assert c.get('/api/report/export', headers={'X-Environment-ID': target}).json()['rows'] == []
    evidence = c.get('/api/logs/1/evidence', headers={'X-Environment-ID': a}).json()
    assert evidence['scope']['environment_id'] == a and evidence['curve_snapshot']
    assert a in c.get('/api/report/export?format=csv', headers={'X-Environment-ID': a}).text
    body = {'name': 'Cross-environment dependency', 'owner': 'test', 'est_duration_min': 30, 'power_kw': 1,
            'earliest_start': '2026-10-09T06:00:00Z', 'sla_deadline': '2026-10-10T00:00:00Z', 'depends_on': [state['jobs'][0]['id']]}
    assert c.post('/api/jobs', json=body, headers={'X-Environment-ID': b}).status_code == 409
    # Stable scope cannot be injected into a job payload.
    body['environment_id'] = a
    assert c.post('/api/jobs', json=body, headers={'X-Environment-ID': b}).status_code == 422
    c.post('/api/demo/reset', headers={'X-Environment-ID': a}).raise_for_status()
    assert c.get('/api/logs/1/evidence', headers={'X-Environment-ID': a}).json() == evidence


def test_roles_and_authenticated_approval_identity(scenario):
    operator = scenario['accounts']['project_operator'][0]
    approver, uid = scenario['accounts']['approver']
    headers = {'X-Environment-ID': scenario['ea']}
    operator.post('/api/demo/reset', headers=headers).raise_for_status()
    operator.post('/api/agent/cycle', headers=headers).raise_for_status()
    job = operator.get('/api/approvals', headers=headers).json()[0]
    assert operator.post('/api/approvals/' + job['id'], headers=headers, json={'action':'approve','comment':'checked'}).status_code == 403
    assert approver.post('/api/agent/cycle', headers=headers).status_code == 403
    assert approver.post('/api/approvals/' + job['id'], headers=headers, json={'action':'approve','comment':'checked','approver_name':'Forged name'}).status_code == 200
    log = approver.get('/api/logs?actor=human', headers=headers).json()[0]
    assert log['user_id'] == uid and log['approver_name'] == 'approver'


def test_policy_credentials_and_client_admin_limits(scenario, monkeypatch):
    admin = scenario['admin']; ca = scenario['accounts']['client_admin'][0]
    assert ca.post('/api/admin/projects', json={'tenant_id': scenario['b'], 'name': 'escape'}).status_code == 403
    assert ca.post('/api/admin/tenants', json={'name': 'escape'}).status_code == 403
    assert ca.put(f"/api/admin/projects/{scenario['pa']}/policy", json={'threshold_pct':0,'threshold_g':0,'safety_min':0}).status_code == 422
    assert ca.put(f"/api/admin/projects/{scenario['pa']}/policy", json={'threshold_pct':6,'threshold_g':7,'safety_min':20}).status_code == 200
    d = scenario['app'].state.directory
    with d.lock:
        envs = {e['id']:e for e in d.environments({'platform_admin':True})}
        assert d.service(envs[scenario['ea']]).settings.electricity_token == ''
        monkeypatch.setenv(Directory.credential_name(scenario['ea']), 'only-client-a-secret')
        d.invalidate(scenario['pa'])
        assert d.service(envs[scenario['ea']]).settings.electricity_token == 'only-client-a-secret'
        assert d.service(envs[scenario['prod']]).settings.electricity_token == ''
        assert d.service(envs[scenario['eb']]).settings.electricity_token == ''
    for path in ('/api/admin/directory','/api/auth/me','/api/state?environment_id='+scenario['ea']):
        assert 'only-client-a-secret' not in admin.get(path).text
    with pytest.raises(sqlite3.IntegrityError), d.transaction():
        d.db.execute('DELETE FROM admin_events')


def test_client_consent_and_immediate_membership_revocation(scenario):
    admin = scenario['admin']; ca = scenario['accounts']['client_admin'][0]
    path = f"/api/admin/tenants/{scenario['a']}/reporting"
    assert admin.get('/api/organization/report').json()['environments'] == []
    assert admin.put(path, json={'share_aggregate': True}).status_code == 403
    assert ca.put(path, json={'share_aggregate': True}).status_code == 200
    report = admin.get('/api/organization/report').json()
    assert report['environments'] and all(r['tenant_id'] == scenario['a'] for r in report['environments'])
    assert all('rows' not in r and 'job_id' not in r for r in report['environments'])
    ca.put(path, json={'share_aggregate':False}).raise_for_status()
    assert admin.get('/api/organization/report').json()['environments'] == []
    viewer, uid = scenario['accounts']['viewer']
    grant = next(g for g in admin.get('/api/admin/directory').json()['memberships'] if g['user_id'] == uid)
    assert admin.delete('/api/admin/memberships/' + str(grant['id'])).status_code == 200
    assert viewer.get('/api/state', headers={'X-Environment-ID':scenario['ea']}).status_code == 404


def test_viewer_cannot_edit_view_config(scenario):
    admin = scenario['admin']
    ca = scenario['accounts']['client_admin'][0]
    operator = scenario['accounts']['project_operator'][0]
    viewer = scenario['accounts']['viewer'][0]
    pa, pb = scenario['pa'], scenario['pb']

    body = {
        'visible_sections': ['kpis', 'queue'],
        'visible_kpis': ['avoided'],
        'allowed_zones': ['DE'],
        'show_decision_log': False,
        'show_flexibility': False,
        'allow_export': False,
    }

    # Viewer and project_operator cannot edit view config
    assert viewer.put(f'/api/admin/projects/{pa}/view', json=body).status_code == 403
    assert operator.put(f'/api/admin/projects/{pa}/view', json=body).status_code == 403

    # Client admin of client A cannot edit project in client B
    assert ca.put(f'/api/admin/projects/{pb}/view', json=body).status_code == 403

    # Client admin of client A can edit own project
    r = ca.put(f'/api/admin/projects/{pa}/view', json=body)
    assert r.status_code == 200
    saved = r.json()
    assert saved['visible_sections'] == ['kpis', 'queue']
    assert saved['visible_kpis'] == ['avoided']
    assert saved['allowed_zones'] == ['DE']
    assert saved['show_decision_log'] is False
    assert saved['show_flexibility'] is False
    assert saved['allow_export'] is False

    # GET /admin/directory includes the view config
    directory_data = admin.get('/api/admin/directory').json()
    proj = next(p for p in directory_data['projects'] if p['id'] == pa)
    assert proj['view']['visible_sections'] == ['kpis', 'queue']


def test_hidden_sections_deny_or_strip_data_via_api(scenario):
    ca = scenario['accounts']['client_admin'][0]
    operator = scenario['accounts']['project_operator'][0]
    pa, ea = scenario['pa'], scenario['ea']
    headers = {'X-Environment-ID': ea}

    # Populate jobs and a cycle
    operator.post('/api/demo/reset', headers=headers).raise_for_status()
    operator.post('/api/agent/cycle', headers=headers).raise_for_status()

    # Hide audit, sensitivity, and disable export
    ca.put(f'/api/admin/projects/{pa}/view', json={
        'visible_sections': ['kpis', 'queue'],
        'visible_kpis': ['avoided', 'reduction'],
        'allowed_zones': [],
        'show_decision_log': False,
        'show_flexibility': False,
        'allow_export': False,
    }).raise_for_status()

    # /api/state returns the resolved view config
    st = operator.get('/api/state', headers=headers).json()
    assert st['view']['visible_sections'] == ['kpis', 'queue']
    assert st['view']['show_decision_log'] is False

    # Hidden sensitivity -> /api/analysis/flexibility returns 403
    assert operator.get('/api/analysis/flexibility', headers=headers).status_code == 403

    # Disallowed export -> /api/report/export returns 403
    assert operator.get('/api/report/export?format=csv', headers=headers).status_code == 403
    assert operator.get('/api/report/export?format=json', headers=headers).status_code == 403

    # Hidden audit -> /api/logs is stripped (empty list) and evidence returns 403
    assert operator.get('/api/logs', headers=headers).json() == []
    assert operator.get('/api/logs/1/evidence', headers=headers).status_code == 403


def test_allowed_zones_filter_works(scenario):
    ca = scenario['accounts']['client_admin'][0]
    operator = scenario['accounts']['project_operator'][0]
    pa, ea = scenario['pa'], scenario['ea']
    headers = {'X-Environment-ID': ea}

    operator.post('/api/demo/reset', headers=headers).raise_for_status()
    operator.post('/api/agent/cycle', headers=headers).raise_for_status()

    # Confirm initial demo has multiple zones
    ca.put(f'/api/admin/projects/{pa}/view', json={
        'visible_sections': ['kpis', 'queue', 'chart', 'rollups', 'audit', 'sensitivity'],
        'visible_kpis': ['avoided', 'reduction', 'weekly', 'approvals'],
        'allowed_zones': [],
        'show_decision_log': True,
        'show_flexibility': True,
        'allow_export': True,
    }).raise_for_status()
    all_jobs = operator.get('/api/jobs', headers=headers).json()
    assert len({j['zone'] for j in all_jobs}) > 1

    # Now restrict to DE only
    ca.put(f'/api/admin/projects/{pa}/view', json={
        'visible_sections': ['kpis', 'queue', 'chart', 'rollups', 'audit', 'sensitivity'],
        'visible_kpis': ['avoided', 'reduction', 'weekly', 'approvals'],
        'allowed_zones': ['DE'],
        'show_decision_log': True,
        'show_flexibility': True,
        'allow_export': True,
    }).raise_for_status()

    state = operator.get('/api/state', headers=headers).json()
    assert all(j['zone'] == 'DE' for j in state['jobs'])
    assert 'DE' in state['zones'] and len(state['zones']) == 1

    jobs = operator.get('/api/jobs', headers=headers).json()
    assert len(jobs) > 0
    assert all(j['zone'] == 'DE' for j in jobs)

    # Report and export are also filtered to allowed zone
    report = operator.get('/api/report', headers=headers).json()
    assert all(r['zone'] == 'DE' for r in report['rows'])
    csv_text = operator.get('/api/report/export?format=csv', headers=headers).text
    assert 'DE' in csv_text
    assert 'US-CAL-CISO' not in csv_text

    # Accessing curve of job outside allowed zone returns 403
    non_de_job = next(j for j in all_jobs if j['zone'] != 'DE')
    assert operator.get(f"/api/jobs/{non_de_job['id']}/curve", headers=headers).status_code == 403

    # Reset allowed_zones to empty (all zones allowed)
    ca.put(f'/api/admin/projects/{pa}/view', json={
        'visible_sections': ['kpis', 'queue', 'chart', 'rollups', 'audit', 'sensitivity'],
        'visible_kpis': ['avoided', 'reduction', 'weekly', 'approvals'],
        'allowed_zones': [],
        'show_decision_log': True,
        'show_flexibility': True,
        'allow_export': True,
    }).raise_for_status()
    restored_jobs = operator.get('/api/jobs', headers=headers).json()
    assert len({j['zone'] for j in restored_jobs}) > 1
