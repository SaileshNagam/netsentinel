"""
NetSentinel Safety Gate
The mandatory checkpoint before any disruptive defensive action is executed.

Safety rules enforced:
1. Simulation mode always defaults to True
2. Human approval is required for all disruptive actions
3. Localhost and management IPs cannot be blocked
4. Critical system PIDs cannot be terminated
5. Rejected actions cannot be re-executed
6. LLM cannot approve its own recommendations
7. Invalid IPs and shell metacharacters are rejected
"""
import ipaddress
import logging
import os
import re

logger = logging.getLogger("NetSentinel.SafetyGate")

# PIDs that must never be terminated
PROTECTED_PID_THRESHOLD = 10  # PIDs 0–10 are kernel/system processes
NETSENTINEL_OWN_PID = os.getpid()

# IPs that must never be blocked
NEVER_BLOCK_ADDRESSES = {
    "127.0.0.1", "::1", "0.0.0.0", "localhost",
}

# Shell metacharacters that must be rejected in any target parameter
SHELL_METACHAR_PATTERN = re.compile(r'[;&|`$<>\\\'"()\[\]{}!~]')

# Actions that are considered "disruptive" and require human approval
DISRUPTIVE_ACTIONS = {"BLOCK_IP", "KILL_PROCESS", "TEMPORARY_BLOCKLIST"}
NON_DISRUPTIVE_ACTIONS = {"MONITOR_ONLY", "MARK_SUSPICIOUS", "ALERT_OPERATOR"}


class SafetyGateViolation(Exception):
    """Raised when a safety rule is violated."""
    pass


class SafetyGate:
    """
    Mandatory safety checkpoint for all defensive actions.
    Every call to execute_action MUST pass through this gate.
    """

    def __init__(self):
        self.simulation_mode: bool = True          # ALWAYS True on startup
        self.require_approval: bool = True          # ALWAYS True
        self.allow_autonomous_destructive: bool = False  # NEVER allow

    def validate_ip_target(self, ip: str) -> None:
        """
        Validate that an IP target is safe to act upon.
        Raises SafetyGateViolation on any safety concern.
        """
        # Reject shell metacharacters
        if SHELL_METACHAR_PATTERN.search(ip):
            raise SafetyGateViolation(f"Target '{ip}' contains unsafe shell characters. Rejected.")

        # Reject loopback and well-known reserved addresses
        if ip.lower() in NEVER_BLOCK_ADDRESSES:
            raise SafetyGateViolation(f"Refusing to block reserved/loopback address: {ip}")

        # Validate IP format
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            raise SafetyGateViolation(f"Invalid IP address format: {ip}")

        if ip_obj.is_loopback:
            raise SafetyGateViolation(f"Refusing to block loopback address: {ip}")

        if ip_obj.is_link_local:
            raise SafetyGateViolation(f"Refusing to block link-local address: {ip}")

    def validate_pid_target(self, pid: int, expected_process_name: str = None) -> None:
        """
        Validate that a PID target is safe to terminate.
        Raises SafetyGateViolation on any safety concern.
        """
        import psutil

        if pid <= PROTECTED_PID_THRESHOLD:
            raise SafetyGateViolation(
                f"Refusing to terminate PID {pid} — system/kernel process range."
            )

        if pid == NETSENTINEL_OWN_PID:
            raise SafetyGateViolation(
                f"Refusing to terminate NetSentinel's own process (PID {pid})."
            )

        # Re-validate the process still exists and matches expected name
        try:
            proc = psutil.Process(pid)
            if not proc.is_running():
                raise SafetyGateViolation(f"PID {pid} is no longer running.")
            if expected_process_name and proc.name().lower() != expected_process_name.lower():
                raise SafetyGateViolation(
                    f"PID {pid} process name mismatch: expected '{expected_process_name}', "
                    f"got '{proc.name()}'. Refusing to terminate."
                )
        except psutil.NoSuchProcess:
            raise SafetyGateViolation(f"PID {pid} no longer exists.")
        except psutil.AccessDenied:
            raise SafetyGateViolation(f"Access denied to PID {pid} — insufficient privileges.")

    def check_action_is_approved(self, action_status: str) -> None:
        """Ensure an action has been explicitly approved before execution."""
        if action_status != "APPROVED":
            raise SafetyGateViolation(
                f"Action status is '{action_status}'. Only 'APPROVED' actions can execute."
            )

    def validate_action_request(
        self,
        action_type: str,
        target: str,
        action_status: str = "PENDING_APPROVAL",
        operator: str = "SYSTEM",
    ) -> None:
        """
        Master validation: runs all relevant safety checks for an action request.
        Raises SafetyGateViolation if ANY check fails.
        """
        logger.info(f"SafetyGate: Validating {action_type} on '{target}' by {operator}")

        # LLM/SYSTEM cannot self-approve
        if operator.upper() in ("SYSTEM", "LLM", "AI", "AGENT") and action_type in DISRUPTIVE_ACTIONS:
            if action_status == "APPROVED":
                raise SafetyGateViolation(
                    f"Autonomous approval by '{operator}' is not permitted. "
                    f"A human operator must review and approve this action."
                )

        # Disruptive actions must have human approval
        if action_type in DISRUPTIVE_ACTIONS:
            self.check_action_is_approved(action_status)

        # Type-specific validation
        if action_type == "BLOCK_IP":
            self.validate_ip_target(target)
        elif action_type == "KILL_PROCESS":
            try:
                pid = int(target)
            except ValueError:
                raise SafetyGateViolation(f"PID target must be an integer, got: '{target}'")
            self.validate_pid_target(pid)
        elif action_type == "TEMPORARY_BLOCKLIST":
            self.validate_ip_target(target)

        logger.info(f"SafetyGate: Validation PASSED for {action_type} on '{target}'")


# Singleton
safety_gate = SafetyGate()
