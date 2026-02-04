"""
MIS Python SDK - Session management for AI agents

Usage:
    import mis
    
    with mis.session(intent="RESEARCH") as session:
        # Your agent code here
        agent.run()
        
    print(f"Stats: {session.stats()}")
"""

import grpc
import os
from contextlib import contextmanager
from typing import Optional, Dict, Any
from dataclasses import dataclass

# Import generated proto stubs
# In production: generate with: python -m grpc_tools.protoc
from . import orchestrator_pb2
from . import orchestrator_pb2_grpc


@dataclass
class SessionStats:
    """Session statistics"""
    session_id: int
    violation_count: int
    defcon_level: int
    state: str  # "ACTIVE", "SUSPENDED", "TERMINATED"


class Session:
    """Active MIS session"""
    
    def __init__(
        self,
        session_id: int,
        capabilities: int,
        stub: orchestrator_pb2_grpc.OrchestrationServiceStub,
    ):
        self.session_id = session_id
        self.capabilities = capabilities
        self._stub = stub
        self._terminated = False
    
    def stats(self) -> SessionStats:
        """Get session statistics"""
        response = self._stub.GetSession(
            orchestrator_pb2.GetSessionRequest(
                session_id=self.session_id
            )
        )
        
        state_map = {
            0: "ACTIVE",
            1: "SUSPENDED",
            2: "TERMINATED",
        }
        
        return SessionStats(
            session_id=response.session_id,
            violation_count=response.violation_count,
            defcon_level=response.defcon_level,
            state=state_map.get(response.state, "UNKNOWN"),
        )
    
    def suspend(self):
        """Suspend session (pause agent)"""
        self._stub.SuspendSession(
            orchestrator_pb2.SuspendSessionRequest(
                session_id=self.session_id
            )
        )
    
    def resume(self):
        """Resume suspended session"""
        self._stub.ResumeSession(
            orchestrator_pb2.ResumeSessionRequest(
                session_id=self.session_id
            )
        )
    
    def refresh(self, ttl_secs: int = 3600):
        """Refresh token (extend TTL)"""
        self._stub.RefreshToken(
            orchestrator_pb2.RefreshTokenRequest(
                session_id=self.session_id,
                ttl_secs=ttl_secs,
            )
        )
    
    def terminate(self):
        """Explicitly terminate session"""
        if not self._terminated:
            self._stub.TerminateSession(
                orchestrator_pb2.TerminateSessionRequest(
                    session_id=self.session_id
                )
            )
            self._terminated = True


@contextmanager
def session(
    intent: str,
    *,
    ttl_secs: int = 3600,
    grpc_host: str = "localhost",
    grpc_port: int = 50051,
):
    """
    Create MIS session with intent-based capabilities
    
    Args:
        intent: Intent name ("RESEARCH", "DEPLOY", "TEST", "ANALYZE")
        ttl_secs: Token time-to-live in seconds (default 1 hour)
        grpc_host: Orchestrator gRPC host
        grpc_port: Orchestrator gRPC port
    
    Example:
        with mis.session(intent="RESEARCH") as s:
            # Automatically has:
            # - CAP_READ on /data/papers/*
            # - CAP_NETWORK on arxiv.org
            # - CAP_EXEC for analysis tools
            
            papers = fetch_from_arxiv("AI safety")
            analyze(papers)
    """
    
    # Connect to orchestrator
    channel = grpc.insecure_channel(f"{grpc_host}:{grpc_port}")
    stub = orchestrator_pb2_grpc.OrchestrationServiceStub(channel)
    
    # Get current process info
    pid = os.getpid()
    
    # Get cgroup ID (for container tracking)
    cgroup_id = _get_cgroup_id()
    
    try:
        # Create session
        response = stub.CreateSession(
            orchestrator_pb2.CreateSessionRequest(
                intent_name=intent,
                agent_pid=pid,
                cgroup_id=cgroup_id,
                ttl_secs=ttl_secs,
            )
        )
        
        session_obj = Session(
            session_id=response.session_id,
            capabilities=response.capabilities,
            stub=stub,
        )
        
        yield session_obj
        
    finally:
        # Cleanup: terminate session
        try:
            session_obj.terminate()
        except:
            pass  # Already terminated or connection lost
        
        channel.close()


def get_global_stats(
    grpc_host: str = "localhost",
    grpc_port: int = 50051,
) -> Dict[str, int]:
    """
    Get global MIS statistics
    
    Returns:
        Dictionary with:
        - token_validated: Total tokens validated
        - allowed: Operations allowed
        - denied: Operations denied
        - ...
    """
    channel = grpc.insecure_channel(f"{grpc_host}:{grpc_port}")
    stub = orchestrator_pb2_grpc.OrchestrationServiceStub(channel)
    
    try:
        response = stub.GetStats(
            orchestrator_pb2.GetStatsRequest()
        )
        
        return {
            "token_validated": response.token_validated,
            "token_expired": response.token_expired,
            "allowed": response.allowed,
            "denied": response.denied,
            "total_decisions": response.total_decisions,
        }
    finally:
        channel.close()


def list_sessions(
    grpc_host: str = "localhost",
    grpc_port: int = 50051,
) -> list:
    """List all active sessions"""
    channel = grpc.insecure_channel(f"{grpc_host}:{grpc_port}")
    stub = orchestrator_pb2_grpc.OrchestrationServiceStub(channel)
    
    try:
        response = stub.ListSessions(
            orchestrator_pb2.ListSessionsRequest()
        )
        
        return [
            {
                "session_id": s.session_id,
                "agent_pid": s.agent_pid,
                "intent": s.intent_name,
                "state": ["ACTIVE", "SUSPENDED", "TERMINATED"][s.state],
            }
            for s in response.sessions
        ]
    finally:
        channel.close()


def _get_cgroup_id() -> int:
    """Get current cgroup ID from /proc/self/cgroup"""
    try:
        with open("/proc/self/cgroup", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3:
                    # Extract cgroup path and hash it
                    path = parts[2]
                    # Simple hash for demo (production: use proper cgroup inode)
                    return hash(path) & 0xFFFFFFFFFFFFFFFF
    except:
        pass
    
    # Fallback: use PID
    return os.getpid()


# Convenience: pre-defined profiles
class Profile:
    """Pre-defined intent profiles"""
    RESEARCHER = "RESEARCH"
    DEPLOYER = "DEPLOY"
    TESTER = "TEST"
    ANALYZER = "ANALYZE"


__all__ = [
    "session",
    "Session",
    "SessionStats",
    "Profile",
    "get_global_stats",
    "list_sessions",
]
