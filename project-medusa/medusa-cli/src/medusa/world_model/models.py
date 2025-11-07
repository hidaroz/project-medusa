"""
MEDUSA World Model - Data Models
Pydantic models representing Neo4j nodes
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class Domain(BaseModel):
    """Root domain node"""

    name: str = Field(..., description="Domain name (e.g., medcare.local)")
    discovered_at: Optional[datetime] = Field(default_factory=datetime.now)
    scan_status: Optional[str] = Field(default="pending")


class Subdomain(BaseModel):
    """Subdomain node"""

    name: str = Field(..., description="Fully qualified subdomain name")
    discovered_at: Optional[datetime] = Field(default_factory=datetime.now)


class Host(BaseModel):
    """Host/IP address node"""

    ip: str = Field(..., description="IP address")
    hostname: Optional[str] = Field(None, description="DNS hostname")
    os_name: Optional[str] = Field(None, description="Operating system name")
    os_accuracy: Optional[int] = Field(
        None, ge=0, le=100, description="OS detection confidence (0-100)"
    )
    discovered_at: Optional[datetime] = Field(default_factory=datetime.now)
    last_seen: Optional[datetime] = Field(default_factory=datetime.now)


class Port(BaseModel):
    """Network port node"""

    number: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field(..., description="Protocol (tcp/udp)")
    state: Optional[str] = Field("unknown", description="Port state")
    service: Optional[str] = Field(None, description="Service name")
    product: Optional[str] = Field(None, description="Product name")
    version: Optional[str] = Field(None, description="Service version")
    service_string: Optional[str] = Field(None, description="Full service banner")
    host_id: str = Field(..., description="Reference to host IP")
    discovered_at: Optional[datetime] = Field(default_factory=datetime.now)


class WebServer(BaseModel):
    """Web application node"""

    url: str = Field(..., description="Full URL including protocol and port")
    status_code: Optional[int] = Field(None, description="HTTP response code")
    title: Optional[str] = Field(None, description="Page title")
    web_server: Optional[str] = Field(None, description="Web server software")
    technologies: Optional[List[str]] = Field(
        default_factory=list, description="Detected technologies"
    )
    ssl: Optional[bool] = Field(False, description="Whether HTTPS is used")
    discovered_at: Optional[datetime] = Field(default_factory=datetime.now)
    last_checked: Optional[datetime] = Field(default_factory=datetime.now)


class User(BaseModel):
    """User account node"""

    username: str = Field(..., description="Login username")
    name: Optional[str] = Field(None, description="Full name")
    domain: str = Field(..., description="Domain or realm")
    asrep_roastable: Optional[bool] = Field(
        False, description="Whether account is AS-REP roastable"
    )
    discovered_at: Optional[datetime] = Field(default_factory=datetime.now)


class Credential(BaseModel):
    """Credential node"""

    id: str = Field(..., description="Unique credential identifier")
    value: str = Field(..., description="The actual credential value")
    type: str = Field(..., description="Credential type")
    username: Optional[str] = Field(None, description="Associated username")
    domain: Optional[str] = Field(None, description="Associated domain")
    discovered_at: Optional[datetime] = Field(default_factory=datetime.now)
    source: Optional[str] = Field(
        None, description="How credential was obtained"
    )


class Vulnerability(BaseModel):
    """Vulnerability node"""

    id: str = Field(..., description="Unique vulnerability identifier")
    type: str = Field(..., description="Vulnerability type")
    parameter: Optional[str] = Field(None, description="Vulnerable parameter name")
    location: Optional[str] = Field(
        None, description="URL or file path where vulnerability exists"
    )
    dbms: Optional[str] = Field(None, description="Database management system")
    databases: Optional[List[str]] = Field(
        default_factory=list, description="Accessible database names"
    )
    tables: Optional[List[str]] = Field(
        default_factory=list, description="Accessible table names"
    )
    severity: Optional[str] = Field("medium", description="Severity level")
    discovered_at: Optional[datetime] = Field(default_factory=datetime.now)
    exploited: Optional[bool] = Field(False, description="Whether exploited")
