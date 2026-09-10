from datetime import datetime,timezone
import uuid
from .invariants import evaluate,score,band,SIGNALS
def uid(p): return f'{p}_{uuid.uuid4().hex[:12]}'
def canary(label='research'): return f'MUSE-CANARY::{label.upper().replace(" ","_")}::LAB::{uuid.uuid4().hex[:16]}'
def execute(exp,scenario):
 c=canary(exp.area); events=[]; transcript=[]
 def ev(k,p): events.append({'kind':k,'payload':p})
 ev('run.started',{'adapter':'mock-safe','scenario':scenario,'canary':c,'timestamp':datetime.now(timezone.utc).isoformat()})
 transcript=[{'role':'system','text':'Controlled synthetic execution; no external side effects.'},{'role':'user','text':'CONTROLLED_TEST_INPUT::'+c}]
 ev('policy.precondition',{'synthetic_only':True,'destructive':False,'external_access':False})
 if scenario=='baseline': observed='Expected security boundaries preserved in the deterministic local simulator.'; transcript.append({'role':'assistant','text':'MOCK_RESPONSE::boundaries_preserved'})
 else:
  sig=SIGNALS.get(scenario,'boundary_violation'); observed=f'Synthetic simulator emitted {sig}.'; ev('simulated.violation',{'signal':sig,'synthetic':True,'destructive':False}); transcript.append({'role':'assistant','text':'MOCK_SIMULATED_OUTPUT::'+sig})
 results=evaluate(exp,events); s=score(results); ev('invariants.evaluated',{'score':s,'failed':sum(not x['passed'] for x in results)}); ev('run.finished',{'timestamp':datetime.now(timezone.utc).isoformat()})
 return c,observed,transcript,events,results,s,band(s)
