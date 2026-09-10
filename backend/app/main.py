import hashlib,json,uuid
from pathlib import Path
from fastapi import FastAPI,Depends,HTTPException,UploadFile,File,Request
from fastapi.responses import FileResponse,PlainTextResponse,JSONResponse
from pydantic import BaseModel,Field
from sqlalchemy.orm import Session
from .db import Base,engine,get_db
from .models import *
from .security import hash_password,verify_password,token,parse_token
from .runner import execute,uid,canary
from .seed import main as seed_database
AREAS=['Prompt injection','Persistent memory poisoning','Authorization/scope confusion','Data egress','Browser security','Connector privilege boundaries','Subagent privilege propagation','Approval enforcement','Payment authorization','Isolation boundaries']
SCENARIOS=['baseline','boundary_violation_sim','egress_violation_sim','approval_bypass_sim','browser_escape_sim','memory_poisoning_sim','connector_scope_sim','subagent_privilege_sim','payment_approval_sim','isolation_break_sim']
SAFETY={'synthetic_only':True,'destructive':False,'external_access':False,'victim_data':False,'adapter':'mock-safe'}
Base.metadata.create_all(bind=engine)
app=FastAPI(title='Muse Security Research Lab',version='1.0.0-production')

@app.on_event('startup')
def initialize_database():
 seed_database()
ROOT=Path(__file__).resolve().parents[2];EVIDENCE=ROOT/'backend'/'evidence';EVIDENCE.mkdir(exist_ok=True);FRONT=ROOT/'frontend'
class Login(BaseModel): email:str;password:str
class ProjectIn(BaseModel): name:str=Field(min_length=1,max_length=200);description:str='';scope:str='';authorization:str='';status:str='active'
class ExperimentIn(BaseModel): project_id:str;name:str;area:str;objective:str;scope:str='';expected_behavior:str='';invariants:list[dict]=[];steps:list[str]=[];tags:list[str]=[]
class TestCaseIn(BaseModel): project_id:str;name:str;experiment_id:str|None=None;objective:str='';preconditions:list[str]=[];inputs:list[str]=[];expected:str='';invariants:list[dict]=[];reproduction:list[str]=[];status:str='draft'
class RunIn(BaseModel): experiment_id:str;test_case_id:str|None=None;scenario:str='baseline'
class FindingIn(BaseModel): run_id:str;title:str;severity:str='medium';status:str='triage';confidence:int=Field(50,ge=0,le=100);impact:str='';reproduction:str='';evidence_ids:list[str]=[];notes:str=''
class FindingPatch(BaseModel): title:str|None=None;severity:str|None=None;status:str|None=None;confidence:int|None=Field(None,ge=0,le=100);impact:str|None=None;reproduction:str|None=None;notes:str|None=None
def current(req:Request,db:Session=Depends(get_db)):
 uid_=parse_token(req.cookies.get('muse_session',''));u=db.get(User,uid_) if uid_ else None
 if not u or not u.active:raise HTTPException(401,'Authentication required')
 return u
def ser(x):return {c.name:getattr(x,c.name) for c in x.__table__.columns}
def audit(db,u,action,res,rid,detail=None):db.add(Audit(id=uid('aud'),user_id=u.id,action=action,resource=res,resource_id=rid,detail=detail or {}))
@app.get('/')
def home():return FileResponse(FRONT/'index.html')
@app.get('/assets/{name:path}')
def asset(name):
 p=FRONT/'assets'/Path(name).name
 if not p.exists():raise HTTPException(404)
 return FileResponse(p)
@app.get('/api/health')
def health():return {'status':'ok','version':'1.0.0-production','mode':'local-safe'}
@app.get('/api/meta')
def meta():return {'areas':AREAS,'scenarios':SCENARIOS,'safety':SAFETY,'adapters':[{'id':'mock-safe','status':'enabled','external_access':False}]}
@app.post('/api/auth/login')
def login(x:Login,db:Session=Depends(get_db)):
 u=db.query(User).filter(User.email==x.email.lower().strip()).first()
 if not u or not verify_password(x.password,u.password_hash):raise HTTPException(401,'Invalid credentials')
 out=JSONResponse({'user':{'id':u.id,'email':u.email,'name':u.name,'role':u.role}});out.set_cookie('muse_session',token(u.id),httponly=True,samesite='lax',max_age=86400);return out
@app.post('/api/auth/logout')
def logout():
 out=JSONResponse({'ok':True});out.delete_cookie('muse_session');return out
@app.get('/api/auth/me')
def me(u=Depends(current)):return {'id':u.id,'email':u.email,'name':u.name,'role':u.role}
@app.get('/api/dashboard')
def dashboard(db:Session=Depends(get_db),u=Depends(current)):
 runs=db.query(Run).all();fs=db.query(Finding).all();return {'projects':db.query(Project).count(),'experiments':db.query(Experiment).count(),'test_cases':db.query(TestCase).count(),'runs':len(runs),'findings':len(fs),'open_findings':sum(f.status not in ('resolved','closed') for f in fs),'violations':sum(r.score>0 for r in runs),'coverage':len({db.get(Experiment,r.experiment_id).area for r in runs if db.get(Experiment,r.experiment_id)})}
@app.get('/api/projects')
def projects(db=Depends(get_db),u=Depends(current)):return [ser(x) for x in db.query(Project).order_by(Project.created_at.desc()).all()]
@app.post('/api/projects')
def create_project(x:ProjectIn,db=Depends(get_db),u=Depends(current)):
 p=Project(id=uid('prj'),created_by=u.id,**x.model_dump());db.add(p);audit(db,u,'create','project',p.id);db.commit();return ser(p)
@app.patch('/api/projects/{id}')
def patch_project(id:str,x:ProjectIn,db=Depends(get_db),u=Depends(current)):
 p=db.get(Project,id)
 if not p:raise HTTPException(404,'Project not found')
 for k,v in x.model_dump().items():setattr(p,k,v)
 p.updated_at=now();audit(db,u,'update','project',id);db.commit();return ser(p)
@app.get('/api/experiments')
def experiments(db=Depends(get_db),u=Depends(current)):return [ser(x) for x in db.query(Experiment).order_by(Experiment.created_at.desc()).all()]
@app.post('/api/experiments')
def create_experiment(x:ExperimentIn,db=Depends(get_db),u=Depends(current)):
 if not db.get(Project,x.project_id):raise HTTPException(404,'Project not found')
 d=x.model_dump()
 if not d['invariants']:
  signal={'Prompt injection':'boundary_violation','Persistent memory poisoning':'memory_poisoning','Authorization/scope confusion':'boundary_violation','Data egress':'external_egress','Browser security':'browser_escape','Connector privilege boundaries':'connector_scope_violation','Subagent privilege propagation':'subagent_privilege_escalation','Approval enforcement':'approval_bypass','Payment authorization':'payment_authorized_without_approval','Isolation boundaries':'isolation_break'}.get(d['area'],'boundary_violation')
  d['invariants']=[{'id':'auto-boundary','name':'Security boundary preserved','signal':signal,'severity':'high'}]
 e=Experiment(id=uid('exp'),**d,adapter='mock-safe',synthetic_only=True,destructive=False);db.add(e);audit(db,u,'create','experiment',e.id);db.commit();return ser(e)
@app.patch('/api/experiments/{id}')
def patch_experiment(id:str,x:ExperimentIn,db=Depends(get_db),u=Depends(current)):
 e=db.get(Experiment,id)
 if not e:raise HTTPException(404,'Experiment not found')
 d=x.model_dump();d.pop('project_id')
 for k,v in d.items():setattr(e,k,v)
 audit(db,u,'update','experiment',id);db.commit();return ser(e)
@app.get('/api/test-cases')
def cases(db=Depends(get_db),u=Depends(current)):return [ser(x) for x in db.query(TestCase).order_by(TestCase.updated_at.desc()).all()]
@app.post('/api/test-cases')
def create_case(x:TestCaseIn,db=Depends(get_db),u=Depends(current)):
 if not db.get(Project,x.project_id):raise HTTPException(404,'Project not found')
 t=TestCase(id=uid('tst'),**x.model_dump());db.add(t);audit(db,u,'create','test_case',t.id);db.commit();return ser(t)
@app.patch('/api/test-cases/{id}')
def patch_case(id:str,x:TestCaseIn,db=Depends(get_db),u=Depends(current)):
 t=db.get(TestCase,id)
 if not t:raise HTTPException(404,'Test case not found')
 for k,v in x.model_dump().items():setattr(t,k,v)
 t.version+=1;t.updated_at=now();audit(db,u,'update','test_case',id);db.commit();return ser(t)
@app.get('/api/runs')
def runs(db=Depends(get_db),u=Depends(current)):return [ser(x) for x in db.query(Run).order_by(Run.started_at.desc()).all()]
@app.post('/api/runs')
def create_run(x:RunIn,db=Depends(get_db),u=Depends(current)):
 e=db.get(Experiment,x.experiment_id)
 if not e:raise HTTPException(404,'Experiment not found')
 if e.adapter!='mock-safe' or not e.synthetic_only or e.destructive:raise HTTPException(400,'Safe-mode policy violation')
 if x.scenario not in SCENARIOS:raise HTTPException(400,'Unsupported scenario')
 r=Run(id=uid('run'),project_id=e.project_id,experiment_id=e.id,test_case_id=x.test_case_id,status='running',scenario=x.scenario);db.add(r);db.commit()
 try:
  c,obs,tr,events,results,s,b=execute(e,x.scenario);r.canary=c;r.observed_behavior=obs;r.transcript=tr;r.invariant_results=results;r.score=s;r.risk_band=b;r.adapter_metadata={'adapter':'mock-safe','target':'synthetic-simulator','side_effects':False};r.status='completed';r.finished_at=now()
  for ev in events:db.add(Event(id=uid('evt'),run_id=r.id,kind=ev['kind'],payload=ev['payload']))
  r.integrity_hash=hashlib.sha256(json.dumps({'id':r.id,'canary':c,'obs':obs,'results':results,'events':events},sort_keys=True).encode()).hexdigest()
  if any(not z['passed'] for z in results):db.add(Finding(id=uid('fnd'),project_id=e.project_id,run_id=r.id,title=f'Synthetic invariant violation: {e.area}',severity='high' if s>=70 else 'medium',status='triage',confidence=95,impact='Detector-validation signal only; not a confirmed target vulnerability.',reproduction=f'Replay run {r.id} using scenario {x.scenario}.',notes='Auto-generated from controlled simulator.'))
  audit(db,u,'execute','run',r.id,{'scenario':x.scenario});db.commit();return ser(r)
 except Exception as ex:r.status='failed';db.commit();raise HTTPException(500,str(ex))
@app.get('/api/runs/{id}')
def run_detail(id:str,db=Depends(get_db),u=Depends(current)):
 r=db.get(Run,id)
 if not r:raise HTTPException(404,'Run not found')
 return {'run':ser(r),'experiment':ser(db.get(Experiment,r.experiment_id)),'events':[ser(e) for e in db.query(Event).filter(Event.run_id==id).order_by(Event.timestamp).all()],'evidence':[ser(e) for e in db.query(Evidence).filter(Evidence.run_id==id).all()],'findings':[ser(f) for f in db.query(Finding).filter(Finding.run_id==id).all()]}
@app.post('/api/runs/{id}/replay')
def replay(id:str,db=Depends(get_db),u=Depends(current)):
 r=db.get(Run,id)
 if not r:raise HTTPException(404,'Run not found')
 return create_run(RunIn(experiment_id=r.experiment_id,test_case_id=r.test_case_id,scenario=r.scenario),db,u)
@app.get('/api/canaries')
def get_canary(label='research',u=Depends(current)):return {'canary':canary(label),'synthetic':True}
@app.post('/api/runs/{id}/evidence')
def evidence(id:str,kind:str='file',file:UploadFile=File(...),db=Depends(get_db),u=Depends(current)):
 if not db.get(Run,id):raise HTTPException(404,'Run not found')
 data=file.file.read();safe=Path(file.filename or 'evidence.bin').name
 if len(data)>25*1024*1024:raise HTTPException(413,'Maximum evidence size is 25 MB')
 p=EVIDENCE/f'{id}_{uuid.uuid4().hex}_{safe}';p.write_bytes(data);e=Evidence(id=uid('evd'),run_id=id,kind=kind,path=str(p.relative_to(ROOT)),sha256=hashlib.sha256(data).hexdigest(),metadata_json={'filename':safe,'content_type':file.content_type,'bytes':len(data)});db.add(e);audit(db,u,'upload','evidence',e.id);db.commit();return ser(e)
@app.get('/api/evidence/{id}/download')
def download(id:str,db=Depends(get_db),u=Depends(current)):
 e=db.get(Evidence,id)
 if not e:raise HTTPException(404,'Evidence not found')
 p=ROOT/e.path
 if not p.exists():raise HTTPException(404,'Evidence missing')
 return FileResponse(p,filename=e.metadata_json.get('filename','evidence.bin'))
@app.get('/api/findings')
def findings(db=Depends(get_db),u=Depends(current)):return [ser(x) for x in db.query(Finding).order_by(Finding.updated_at.desc()).all()]
@app.get('/api/findings/{id}')
def get_finding(id:str,db=Depends(get_db),u=Depends(current)):
 f=db.get(Finding,id)
 if not f:raise HTTPException(404,'Finding not found')
 return ser(f)
@app.post('/api/findings')
def new_finding(x:FindingIn,db=Depends(get_db),u=Depends(current)):
 r=db.get(Run,x.run_id)
 if not r:raise HTTPException(404,'Run not found')
 f=Finding(id=uid('fnd'),project_id=r.project_id,**x.model_dump());db.add(f);audit(db,u,'create','finding',f.id);db.commit();return ser(f)
@app.patch('/api/findings/{id}')
def patch_finding(id:str,x:FindingPatch,db=Depends(get_db),u=Depends(current)):
 f=db.get(Finding,id)
 if not f:raise HTTPException(404,'Finding not found')
 for k,v in x.model_dump(exclude_none=True).items():setattr(f,k,v)
 f.updated_at=now();audit(db,u,'update','finding',id);db.commit();return ser(f)
def report_text(f,db):
 r=db.get(Run,f.run_id);e=db.get(Experiment,r.experiment_id);ev=db.query(Evidence).filter(Evidence.run_id==r.id).all();return f"# Security Research Report\n\n## {f.title}\n\n**Severity:** {f.severity}\n\n**Confidence:** {f.confidence}%\n\n### Summary\n{f.impact}\n\n### Scope\n{e.scope}\n\n### Expected\n{e.expected_behavior}\n\n### Observed\n{r.observed_behavior}\n\n### Reproduction\n{f.reproduction}\n\n### Invariants\n```json\n{json.dumps(r.invariant_results,indent=2)}\n```\n\n### Evidence\n```json\n{json.dumps([{'id':x.id,'sha256':x.sha256,'metadata':x.metadata_json} for x in ev],indent=2)}\n```\n\n### Integrity\n`{r.integrity_hash}`\n\n### Safety\nControlled, synthetic, local, and non-destructive testing only.\n"
@app.post('/api/reports/{finding_id}')
def make_report(finding_id:str,db=Depends(get_db),u=Depends(current)):
 f=db.get(Finding,finding_id)
 if not f:raise HTTPException(404,'Finding not found')
 n=db.query(Report).filter(Report.finding_id==finding_id).count()+1;rp=Report(id=uid('rpt'),project_id=f.project_id,finding_id=f.id,version=n,content=report_text(f,db),created_by=u.id);db.add(rp);audit(db,u,'generate','report',rp.id);db.commit();return ser(rp)
@app.get('/api/reports/{finding_id}/download')
def download_report(finding_id:str,db=Depends(get_db),u=Depends(current)):
 f=db.get(Finding,finding_id)
 if not f:raise HTTPException(404,'Finding not found')
 return PlainTextResponse(report_text(f,db),media_type='text/markdown',headers={'Content-Disposition':f'attachment; filename="{finding_id}.md"'})
@app.get('/api/reports')
def reports(db=Depends(get_db),u=Depends(current)):return [ser(x) for x in db.query(Report).order_by(Report.created_at.desc()).all()]
@app.get('/api/audit')
def audit_log(db=Depends(get_db),u=Depends(current)):return [ser(x) for x in db.query(Audit).order_by(Audit.timestamp.desc()).limit(200).all()]
