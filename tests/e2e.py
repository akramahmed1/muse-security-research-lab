import subprocess,time,requests,os,sys
BASE='http://127.0.0.1:8765'; cwd=os.path.join(os.path.dirname(__file__),'..','backend')
proc=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port','8765'],cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
 for _ in range(30):
  try:
   if requests.get(BASE+'/api/health').ok: break
  except: time.sleep(.2)
 s=requests.Session(); assert s.get(BASE+'/api/projects').status_code==401
 assert s.post(BASE+'/api/auth/login',json={'email':'admin@localhost','password':'ChangeMe!123'}).ok
 assert s.get(BASE+'/api/auth/me').ok
 for path in ['/api/dashboard','/api/projects','/api/experiments','/api/test-cases','/api/runs','/api/findings','/api/reports','/api/audit','/api/meta']: assert s.get(BASE+path).ok,path
 pj=s.post(BASE+'/api/projects',json={'name':'E2E Project','description':'test','scope':'synthetic','authorization':'authorized'});assert pj.ok;pj=pj.json()
 ex=s.post(BASE+'/api/experiments',json={'project_id':pj['id'],'name':'E2E Experiment','area':'Data egress','objective':'test','scope':'synthetic','expected_behavior':'no egress'});assert ex.ok;ex=ex.json();assert ex['invariants']
 tc=s.post(BASE+'/api/test-cases',json={'project_id':pj['id'],'name':'E2E Case','objective':'test','preconditions':['synthetic'],'inputs':['canary'],'expected':'preserve','reproduction':['repeat']});assert tc.ok
 assert s.get(BASE+'/api/canaries').ok
 r=s.post(BASE+'/api/runs',json={'experiment_id':ex['id'],'scenario':'baseline'});assert r.ok,r.text
 r=s.post(BASE+'/api/runs',json={'experiment_id':ex['id'],'scenario':'egress_violation_sim'});assert r.ok,r.text;run=r.json();assert run['score']>0
 d=s.get(BASE+'/api/runs/'+run['id']).json();assert d['events'] and d['run']['transcript'] and d['findings']
 f=d['findings'][0];assert s.post(BASE+'/api/reports/'+f['id']).ok;assert s.get(BASE+'/api/reports/'+f['id']+'/download').ok
 assert s.post(BASE+'/api/runs/'+run['id']+'/replay').ok;assert s.patch(BASE+'/api/findings/'+f['id'],json={'status':'validated'}).ok
 print('E2E PASS')
finally:
 proc.terminate();proc.wait(timeout=5)
