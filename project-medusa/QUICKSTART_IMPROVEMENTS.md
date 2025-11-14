# MEDUSA - Quick Start Implementation Guide
## Critical Improvements to Start Today

**Date:** November 14, 2025
**Priority:** P0 - Critical Path Items
**Timeline:** 4-6 weeks for core improvements

---

## 🎯 FOCUS AREAS

Based on the comprehensive audit, these are the **3 critical improvements** that will transform MEDUSA from educational to production-ready:

1. **Real Exploitation Capability** (Currently simulation-only)
2. **Production Web Dashboard** (Currently basic scaffolding)
3. **Core Tool Expansion** (Currently only 6 tools)

---

## 1️⃣ REAL EXPLOITATION ENGINE

### Current Problem
- `exploitation_agent.py:34` - "This agent ONLY simulates exploits"
- Cannot execute real attacks in authorized environments
- Limits practical pentesting value

### Implementation Plan

#### Step 1: Metasploit Integration (Week 1-2)
**File:** `medusa-cli/src/medusa/tools/metasploit.py`

```python
"""
Metasploit Framework Integration
Connects to MSF RPC API for exploit execution
"""

class MetasploitTool(BaseTool):
    def __init__(self):
        self.client = MsfRpcClient('password', server='127.0.0.1', port=55553)

    async def search_exploits(self, cve_id: str) -> List[Dict]:
        """Search for exploits by CVE"""
        modules = self.client.modules.search(cve_id)
        return self._parse_modules(modules)

    async def execute_exploit(
        self,
        module: str,
        target: str,
        payload: str = "generic/shell_reverse_tcp",
        options: Dict = None
    ) -> Dict[str, Any]:
        """Execute exploit module"""
        exploit = self.client.modules.use('exploit', module)
        exploit['RHOSTS'] = target
        exploit['PAYLOAD'] = payload

        # Apply custom options
        if options:
            for key, value in options.items():
                exploit[key] = value

        # Execute and return results
        result = exploit.execute()
        return self._parse_execution_result(result)

    async def list_sessions(self) -> List[Dict]:
        """List active Meterpreter sessions"""
        sessions = self.client.sessions.list
        return [self._format_session(s) for s in sessions.values()]
```

**Dependencies:**
```bash
pip install pymetasploit3
```

**Installation:**
```bash
# Start MSF RPC server
msfrpcd -P password -S -a 127.0.0.1
```

#### Step 2: Safe Exploitation Framework (Week 2-3)
**File:** `medusa-cli/src/medusa/exploits/safe_mode.py`

```python
"""
Safe Exploitation Framework
Provides rollback, validation, and safety controls
"""

class SafeExploitationManager:
    def __init__(self, world_model_client):
        self.world_model = world_model_client
        self.rollback_handlers = {}
        self.active_exploits = {}

    async def validate_target(self, target: str, scope: List[str]) -> bool:
        """Verify target is in authorized scope"""
        target_ip = self._resolve_ip(target)

        for scope_cidr in scope:
            if self._ip_in_cidr(target_ip, scope_cidr):
                return True

        self.logger.error(f"Target {target} is OUT OF SCOPE!")
        return False

    async def execute_with_rollback(
        self,
        exploit_func: Callable,
        rollback_func: Callable,
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """Execute exploit with automatic rollback on failure"""
        exploit_id = str(uuid.uuid4())

        # Record pre-state
        pre_state = await self._capture_state(kwargs.get('target'))

        try:
            # Execute exploit
            result = await exploit_func(*args, **kwargs)

            # Store rollback handler
            self.rollback_handlers[exploit_id] = {
                'rollback_func': rollback_func,
                'pre_state': pre_state,
                'timestamp': datetime.now()
            }

            return {
                'success': True,
                'exploit_id': exploit_id,
                'result': result
            }

        except Exception as e:
            # Auto-rollback on failure
            self.logger.error(f"Exploit failed: {e}")
            await rollback_func(pre_state)

            return {
                'success': False,
                'error': str(e),
                'rolled_back': True
            }

    async def rollback_exploit(self, exploit_id: str):
        """Manually rollback an exploit"""
        if exploit_id not in self.rollback_handlers:
            raise ValueError(f"Unknown exploit ID: {exploit_id}")

        handler = self.rollback_handlers[exploit_id]
        await handler['rollback_func'](handler['pre_state'])

        del self.rollback_handlers[exploit_id]
```

#### Step 3: Update Exploitation Agent (Week 3-4)
**File:** `medusa-cli/src/medusa/agents/exploitation_agent.py`

**Changes needed:**
1. Remove line 34 comment about simulation-only
2. Add real exploit execution path:

```python
async def _execute_exploit(self, task: AgentTask) -> AgentResult:
    """Execute exploit (REAL or SIMULATED based on config)"""
    exploit_spec = task.parameters.get("exploit", {})
    target = task.parameters.get("target")
    mode = self.config.get("exploitation_mode", "simulation")  # NEW

    # Check approval
    if self.require_approval:
        approval_status = await self._check_approval(task.task_id, exploit_spec)
        if approval_status != ApprovalStatus.APPROVED:
            return AgentResult(...)

    # REAL EXPLOITATION PATH (NEW)
    if mode == "real":
        # Validate target is in scope
        if not await self.safe_manager.validate_target(target, self.authorized_scope):
            return AgentResult(
                status=AgentStatus.FAILED,
                error="Target is out of authorized scope"
            )

        # Execute real exploit with rollback
        if exploit_spec["type"] == "metasploit":
            result = await self._execute_metasploit_exploit(exploit_spec, target)
        elif exploit_spec["type"] == "custom":
            result = await self._execute_custom_exploit(exploit_spec, target)
        else:
            return AgentResult(
                status=AgentStatus.FAILED,
                error=f"Unknown exploit type: {exploit_spec['type']}"
            )

        return result

    # SIMULATION PATH (EXISTING)
    else:
        # ... existing simulation code ...
```

### Testing Checklist
- [ ] Metasploit RPC connection works
- [ ] Exploit search returns valid modules
- [ ] Exploit execution in lab environment succeeds
- [ ] Rollback mechanism works correctly
- [ ] Out-of-scope targets are blocked
- [ ] Approval gates function properly

### Documentation Needed
- [ ] Safe exploitation guide
- [ ] Scope configuration format
- [ ] Rollback procedure documentation
- [ ] Legal authorization templates

---

## 2️⃣ PRODUCTION WEB DASHBOARD

### Current Problem
- `medusa-webapp/` has only basic Next.js scaffolding
- No real-time operation monitoring
- No graph visualization
- No approval interface

### Implementation Plan

#### Step 1: Backend API with WebSocket (Week 1-2)
**New Directory:** `medusa-api/`

```
medusa-api/
├── src/
│   ├── main.py                      # FastAPI app
│   ├── api/
│   │   ├── operations.py            # Operation endpoints
│   │   ├── graph.py                 # Graph data endpoints
│   │   ├── approvals.py             # Approval endpoints
│   │   └── websocket.py             # Real-time updates
│   ├── auth.py                      # JWT authentication
│   └── models.py                    # Pydantic models
├── requirements.txt
└── Dockerfile
```

**File:** `medusa-api/src/main.py`

```python
"""
MEDUSA API Server
FastAPI backend with WebSocket support
"""

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from .api import operations, graph, approvals, websocket
from .auth import router as auth_router

app = FastAPI(title="MEDUSA API", version="1.0.0")

# CORS for webapp
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(operations.router, prefix="/api/operations", tags=["operations"])
app.include_router(graph.router, prefix="/api/graph", tags=["graph"])
app.include_router(approvals.router, prefix="/api/approvals", tags=["approvals"])

# WebSocket for real-time updates
@app.websocket("/ws/{operation_id}")
async def websocket_endpoint(websocket: WebSocket, operation_id: str):
    await websocket.accept()
    await websocket_manager.connect(operation_id, websocket)

    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except:
        await websocket_manager.disconnect(operation_id, websocket)
```

**File:** `medusa-api/src/api/operations.py`

```python
"""
Operations API endpoints
"""

from fastapi import APIRouter, HTTPException
from typing import List
from ..models import OperationCreate, OperationStatus, Finding

router = APIRouter()

@router.post("/start", response_model=OperationStatus)
async def start_operation(operation: OperationCreate):
    """Start a new pentest operation"""
    # Create operation in database
    op_id = str(uuid.uuid4())

    # Launch medusa-cli in background
    process = await asyncio.create_subprocess_exec(
        "medusa", "agent", "run", operation.target,
        "--type", operation.operation_type,
        "--operation-id", op_id,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    # Store process handle
    operations[op_id] = {
        'process': process,
        'status': 'running',
        'started_at': datetime.now()
    }

    # Start streaming logs via WebSocket
    asyncio.create_task(stream_operation_logs(op_id, process))

    return OperationStatus(
        operation_id=op_id,
        status='running',
        started_at=datetime.now()
    )

@router.get("/{operation_id}/status")
async def get_operation_status(operation_id: str):
    """Get current status of operation"""
    if operation_id not in operations:
        raise HTTPException(status_code=404, detail="Operation not found")

    return operations[operation_id]

@router.get("/{operation_id}/findings")
async def get_findings(operation_id: str) -> List[Finding]:
    """Get findings from operation"""
    # Query Neo4j graph for findings
    findings = await world_model_client.get_findings(operation_id)
    return findings
```

**Dependencies:** `medusa-api/requirements.txt`
```
fastapi>=0.104.0
uvicorn[standard]>=0.24.0
websockets>=12.0
pydantic>=2.5.0
python-jose[cryptography]>=3.3.0
passlib[bcrypt]>=1.7.4
python-multipart>=0.0.6
neo4j>=5.14.1
```

**Run:**
```bash
cd medusa-api
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8000
```

#### Step 2: Frontend Dashboard (Week 2-4)
**File:** `medusa-webapp/app/operations/page.tsx`

```typescript
'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useWebSocket } from '@/lib/use-websocket';

interface Operation {
  operation_id: string;
  target: string;
  status: 'running' | 'completed' | 'failed';
  started_at: string;
  findings_count: number;
}

export default function OperationsPage() {
  const [operations, setOperations] = useState<Operation[]>([]);
  const [selectedOp, setSelectedOp] = useState<string | null>(null);

  // WebSocket for real-time updates
  const { lastMessage, sendMessage } = useWebSocket(
    selectedOp ? `ws://localhost:8000/ws/${selectedOp}` : null
  );

  // Load operations
  useEffect(() => {
    fetch('http://localhost:8000/api/operations')
      .then(res => res.json())
      .then(data => setOperations(data));
  }, []);

  // Handle WebSocket messages
  useEffect(() => {
    if (lastMessage) {
      const update = JSON.parse(lastMessage.data);

      if (update.type === 'finding') {
        // New finding discovered
        toast.success(`New ${update.severity} finding discovered!`);
        // Update operations list
      } else if (update.type === 'status') {
        // Status update
        setOperations(prev =>
          prev.map(op =>
            op.operation_id === update.operation_id
              ? { ...op, status: update.status }
              : op
          )
        );
      }
    }
  }, [lastMessage]);

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">Operations</h1>
        <Button onClick={() => router.push('/operations/new')}>
          Start New Operation
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {operations.map(op => (
          <Card key={op.operation_id} className="cursor-pointer hover:shadow-lg">
            <CardHeader>
              <CardTitle>{op.target}</CardTitle>
              <StatusBadge status={op.status} />
            </CardHeader>
            <CardContent>
              <p className="text-sm text-gray-500">
                Started: {new Date(op.started_at).toLocaleString()}
              </p>
              <p className="text-sm font-semibold mt-2">
                {op.findings_count} findings
              </p>
              <Button
                className="mt-4 w-full"
                onClick={() => router.push(`/operations/${op.operation_id}`)}
              >
                View Details
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
```

**File:** `medusa-webapp/app/graph/page.tsx`

```typescript
'use client';

import { useEffect, useRef } from 'react';
import Cytoscape from 'cytoscape';

export default function GraphVisualizationPage() {
  const cyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!cyRef.current) return;

    // Fetch graph data from API
    fetch('http://localhost:8000/api/graph/visualize')
      .then(res => res.json())
      .then(data => {
        // Initialize Cytoscape
        const cy = Cytoscape({
          container: cyRef.current,
          elements: data.elements,
          style: [
            {
              selector: 'node[type="host"]',
              style: {
                'background-color': '#3498db',
                'label': 'data(ip)'
              }
            },
            {
              selector: 'node[type="service"]',
              style: {
                'background-color': '#2ecc71',
                'label': 'data(name)'
              }
            },
            {
              selector: 'edge',
              style: {
                'width': 2,
                'line-color': '#95a5a6',
                'target-arrow-color': '#95a5a6',
                'target-arrow-shape': 'triangle'
              }
            }
          ],
          layout: {
            name: 'cose',
            animate: true
          }
        });

        // Click handler
        cy.on('tap', 'node', (evt) => {
          const node = evt.target;
          // Show node details panel
          showNodeDetails(node.data());
        });
      });
  }, []);

  return (
    <div className="h-screen w-full">
      <div ref={cyRef} className="h-full w-full" />
    </div>
  );
}
```

**Install Dependencies:**
```bash
cd medusa-webapp
npm install cytoscape
npm install @/components/ui/card @/components/ui/button # shadcn/ui
```

### Testing Checklist
- [ ] API endpoints return correct data
- [ ] WebSocket connection establishes
- [ ] Real-time updates appear in dashboard
- [ ] Graph visualization renders correctly
- [ ] Operation start/stop works
- [ ] Findings display properly

---

## 3️⃣ CORE TOOL EXPANSION

### Current Problem
Only 6 tools integrated:
- Nmap
- SQLMap
- Amass
- Kerbrute
- Web Scanner
- HTTPx

### Priority Tool Additions (Week 1-4)

#### Week 1: Network Tools
1. **Bloodhound** - AD attack path analysis
   - `tools/network/bloodhound.py`
2. **CrackMapExec** - Network service exploitation
   - `tools/network/crackmapexec.py`
3. **Responder** - LLMNR/NBT-NS poisoning
   - `tools/network/responder.py`

#### Week 2: Web Tools
4. **Nuclei** - Template-based scanner
   - `tools/web/nuclei.py`
5. **Nikto** - Web server scanner
   - `tools/web/nikto.py`
6. **Dirb** - Directory brute-force
   - `tools/web/dirb.py`

#### Week 3: Credential Tools
7. **Hydra** - Network brute-force
   - `tools/credentials/hydra.py`
8. **Hashcat** - Password cracking
   - `tools/credentials/hashcat.py`
9. **Mimikatz** - Windows credential extraction
   - `tools/credentials/mimikatz.py`

#### Week 4: Cloud Tools
10. **ScoutSuite** - Multi-cloud security audit
    - `tools/cloud/scoutsuite.py`

### Implementation Template

**File:** `medusa-cli/src/medusa/tools/network/bloodhound.py`

```python
"""
Bloodhound Integration
Active Directory attack path analysis
"""

from ..base import BaseTool

class BloodhoundTool(BaseTool):
    def __init__(self, timeout: int = 600):
        super().__init__(timeout=timeout, tool_name="bloodhound-python")

    @property
    def tool_binary_name(self) -> str:
        return "bloodhound-python"

    async def collect_data(
        self,
        domain: str,
        username: str,
        password: str,
        domain_controller: str,
        output_dir: str = "/tmp/bloodhound"
    ) -> Dict[str, Any]:
        """
        Collect Active Directory data

        Args:
            domain: Target domain (e.g., corp.local)
            username: Domain username
            password: Password
            domain_controller: DC IP/hostname
            output_dir: Output directory for JSON files
        """
        if not self.is_available():
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"{self.tool_binary_name} is not installed"
            )

        # Build command
        cmd = [
            "bloodhound-python",
            "-d", domain,
            "-u", username,
            "-p", password,
            "-dc", domain_controller,
            "-c", "All",  # Collect all data
            "--zip",  # Create zip file
            "-ns", domain_controller
        ]

        start_time = time.time()
        try:
            stdout, stderr, returncode = await self._run_command(cmd)
            duration = time.time() - start_time

            # Parse output
            findings = self._parse_bloodhound_output(stdout, output_dir)

            return self._create_result_dict(
                success=True,
                findings=findings,
                raw_output=stdout + stderr,
                duration=duration,
                metadata={
                    'domain': domain,
                    'data_collected': True,
                    'output_dir': output_dir
                }
            )

        except Exception as e:
            duration = time.time() - start_time
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=duration,
                error=str(e)
            )

    def _parse_bloodhound_output(self, output: str, output_dir: str) -> List[Dict]:
        """Parse Bloodhound collection results"""
        findings = []

        # Check for collected data files
        import os
        if os.path.exists(output_dir):
            json_files = [f for f in os.listdir(output_dir) if f.endswith('.json')]

            for json_file in json_files:
                findings.append({
                    'type': 'bloodhound_data',
                    'file': json_file,
                    'description': f'Bloodhound data collected: {json_file}'
                })

        return findings
```

**Installation:**
```bash
pip install bloodhound
```

### Testing Checklist
- [ ] All 10 tools install correctly
- [ ] Tool detection (is_available()) works
- [ ] Output parsing extracts findings
- [ ] Integration with agents works
- [ ] Neo4j graph updates with findings

---

## 📦 QUICK START SUMMARY

### Day 1-2: Setup
```bash
# 1. Create new branches
git checkout feat/multi-agent-aws-bedrock
git checkout -b feature/real-exploitation

# 2. Install dependencies
cd medusa-api
pip install -r requirements.txt

cd ../medusa-webapp
npm install

cd ../medusa-cli
pip install pymetasploit3 bloodhound

# 3. Start services
# Terminal 1: MSF RPC
msfrpcd -P password -S

# Terminal 2: API
cd medusa-api
uvicorn src.main:app --reload

# Terminal 3: Webapp
cd medusa-webapp
npm run dev

# Terminal 4: Neo4j (if not running)
docker run -p 7687:7687 -p 7474:7474 neo4j:latest
```

### Week 1: Metasploit Integration
- [ ] Create `tools/metasploit.py`
- [ ] Create `exploits/safe_mode.py`
- [ ] Add tests
- [ ] Test in lab environment

### Week 2: Backend API
- [ ] Create FastAPI application
- [ ] Implement WebSocket
- [ ] Create operations endpoints
- [ ] Add authentication

### Week 3: Frontend Dashboard
- [ ] Create operations page
- [ ] Add graph visualization
- [ ] Implement real-time updates
- [ ] Add approvals interface

### Week 4: Tool Expansion
- [ ] Add 10 critical tools
- [ ] Test all integrations
- [ ] Update documentation

---

## 🎯 SUCCESS CRITERIA

After 4 weeks, you should have:
- ✅ Real exploitation capability (Metasploit integration)
- ✅ Working web dashboard with real-time updates
- ✅ 16 total security tools (up from 6)
- ✅ Graph visualization of attack surface
- ✅ Approval queue interface
- ✅ Safe exploitation framework with rollback

**This transforms MEDUSA from educational to production-ready!**

---

## 📚 RESOURCES

### Documentation to Read
- Metasploit RPC API: https://metasploit.help.rapid7.com/docs/rpc-api
- FastAPI WebSockets: https://fastapi.tiangolo.com/advanced/websockets/
- Cytoscape.js: https://js.cytoscape.org/
- Neo4j Python Driver: https://neo4j.com/docs/api/python-driver/

### Testing Environments
- Lab environment: `cd lab-environment && docker-compose up`
- Metasploit: `msfconsole`
- Neo4j Browser: http://localhost:7474

### Support
- GitHub Issues: https://github.com/yourusername/project-medusa/issues
- Documentation: `/docs`

---

**Next Steps:** Start with Metasploit integration (Week 1) → Build API (Week 2) → Dashboard (Week 3) → Tools (Week 4)
