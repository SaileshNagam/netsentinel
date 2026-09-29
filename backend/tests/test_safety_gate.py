import pytest
import os
from app.response.safety_gate import SafetyGate, SafetyGateViolation

def test_safety_gate_blocks_loopback_ips():
    gate = SafetyGate()
    
    # These should raise SafetyGateViolation
    with pytest.raises(SafetyGateViolation, match="Refusing to block reserved"):
        gate.validate_ip_target("127.0.0.1")
        
    with pytest.raises(SafetyGateViolation, match="Refusing to block reserved"):
        gate.validate_ip_target("0.0.0.0")

def test_safety_gate_blocks_invalid_ips_and_shell_injection():
    gate = SafetyGate()
    
    with pytest.raises(SafetyGateViolation, match="unsafe shell characters"):
        gate.validate_ip_target("192.168.1.5; rm -rf /")
        
    with pytest.raises(SafetyGateViolation, match="Invalid IP address format"):
        gate.validate_ip_target("999.999.999.999")

def test_safety_gate_blocks_critical_pids():
    gate = SafetyGate()
    
    # PID 1 is init/systemd (protected threshold < 10)
    with pytest.raises(SafetyGateViolation, match="system/kernel process range"):
        gate.validate_pid_target(1)
        
    # Own process
    own_pid = os.getpid()
    with pytest.raises(SafetyGateViolation, match="own process"):
        gate.validate_pid_target(own_pid)

def test_safety_gate_prevents_unapproved_disruptive_action():
    gate = SafetyGate()
    
    with pytest.raises(SafetyGateViolation, match="Only 'APPROVED' actions can execute"):
        gate.validate_action_request(
            action_type="BLOCK_IP",
            target="192.168.1.100",
            action_status="PENDING_APPROVAL",
            operator="SOC_OPERATOR"
        )
        
def test_safety_gate_prevents_ai_self_approval():
    gate = SafetyGate()
    
    with pytest.raises(SafetyGateViolation, match="Autonomous approval by 'SYSTEM' is not permitted"):
        gate.validate_action_request(
            action_type="BLOCK_IP",
            target="192.168.1.100",
            action_status="APPROVED",
            operator="SYSTEM"
        )

def test_safety_gate_allows_valid_approved_action():
    gate = SafetyGate()
    
    # Should not raise an exception
    gate.validate_action_request(
        action_type="BLOCK_IP",
        target="192.168.1.100",
        action_status="APPROVED",
        operator="SOC_OPERATOR"
    )
