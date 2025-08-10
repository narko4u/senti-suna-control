
import hmac, hashlib, time, os, json, uuid
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

SHARED_SECRET = os.getenv("SHARED_SECRET", "")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
ALLOWED_MACHINES = set([m.strip() for m in os.getenv("ALLOWED_MACHINES","").split(",") if m.strip()])
if not SHARED_SECRET:
    raise RuntimeError("SHARED_SECRET missing")

def sign_payload(b: bytes) -> str:
    return hmac.new(SHARED_SECRET.encode(), b, hashlib.sha256).hexdigest()

def verify(sig: str, b: bytes):
    if not hmac.compare_digest(sign_payload(b), sig):
        raise HTTPException(status_code=401, detail="Bad signature")

def require_admin(k: Optional[str]):
    if ADMIN_API_KEY and k != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Bad admin key")

JOBS: Dict[str, Dict[str,Any]] = {}
PENDING: List[str] = []
RESULTS: Dict[str, Dict[str,Any]] = {}

app = FastAPI()

class EnqueueReq(BaseModel):
    machine_id: str
    command: str
    params: Dict[str, Any] = {}

class PollReq(BaseModel):
    machine_id: str
    capabilities: List[str] = []

class AckReq(BaseModel):
    job_id: str
    status: str
    stdout: str = ""
    stderr: str = ""
    took_ms: int = 0

@app.get("/health")
def health():
    return {"ok": True, "pending": len(PENDING)}

@app.post("/enqueue")
def enqueue(req: EnqueueReq, x_admin_key: Optional[str]=Header(None)):
    require_admin(x_admin_key)
    if ALLOWED_MACHINES and req.machine_id not in ALLOWED_MACHINES:
        raise HTTPException(status_code=403, detail="Machine not allowed")
    jid = str(uuid.uuid4())
    job = {"id": jid, "machine_id": req.machine_id, "command": req.command, "params": req.params, "ts": int(time.time())}
    JOBS[jid] = job
    PENDING.append(jid)
    jb = json.dumps(job, separators=(',',':')).encode()
    return {"ok": True, "job_id": jid, "sig": sign_payload(jb)}

@app.post("/poll")
def poll(req: PollReq, x_signature: str = Header(...)):
    b = json.dumps(req.model_dump(), separators=(',',':')).encode()
    verify(x_signature, b)
    if ALLOWED_MACHINES and req.machine_id not in ALLOWED_MACHINES:
        return {"job": None}
    for i, jid in enumerate(PENDING):
        job = JOBS[jid]
        if job["machine_id"] == req.machine_id:
            PENDING.pop(i)
            jb = json.dumps(job, separators=(',',':')).encode()
            return {"job": job, "sig": sign_payload(jb)}
    return {"job": None}

@app.post("/ack")
def ack(req: AckReq, x_signature: str = Header(...)):
    b = json.dumps(req.model_dump(), separators=(',',':')).encode()
    verify(x_signature, b)
    RESULTS[req.job_id] = req.model_dump()
    return {"ok": True}

@app.get("/result/{job_id}")
def result(job_id: str, x_admin_key: Optional[str]=Header(None)):
    require_admin(x_admin_key)
    return RESULTS.get(job_id, {"found": False})
