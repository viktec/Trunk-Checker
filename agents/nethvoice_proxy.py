"""
NethVoice Proxy Test Mode
Temporarily injects pjsip trunk config into FreePBX/Asterisk,
tests through the real Kamailio proxy, and cleans up after.
"""
import subprocess
import time
import re


class NethVoiceProxyTester:
    TRUNK_PREFIX = "_trunkchk_"  # Prefix for temp trunk name to avoid collisions

    def __init__(self, logger, container_name="freepbx"):
        self.logger = logger
        self.container = container_name
        self.trunk_name = None
        self.config_files = {}  # Track files we write to for cleanup
        self._secrets = []  # Passwords to mask in logs

    def _mask(self, text):
        """Mask any secrets in text before logging."""
        for secret in self._secrets:
            if secret and secret in text:
                text = text.replace(secret, "*" * 8)
        return text

    def _exec(self, cmd, timeout=10):
        """Execute command inside the FreePBX container via podman."""
        full_cmd = f'podman exec {self.container} bash -c "{cmd}"'
        self.logger.info(f"EXEC: {self._mask(full_cmd)}")
        try:
            result = subprocess.run(
                full_cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode != 0:
                self.logger.error(f"Command failed: {result.stderr.strip()}")
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out: {cmd}")
            return "", "timeout", 1
        except Exception as e:
            self.logger.error(f"Exec error: {e}")
            return "", str(e), 1

    def check_access(self):
        """Verify we can access the FreePBX container."""
        out, err, code = self._exec("asterisk -rx 'core show version'")
        if code == 0 and "Asterisk" in out:
            self.logger.info(f"FreePBX container accessible: {out[:60]}")
            return True
        self.logger.error(f"Cannot access FreePBX container '{self.container}': {err}")
        return False

    def inject_trunk(self, registrar, sip_port, trunk_number, auth_id, auth_pass, trunk_name=None):
        """Write temporary pjsip config files for the trunk."""
        self.trunk_name = f"{self.TRUNK_PREFIX}{trunk_name or 'test'}"
        safe_name = self.trunk_name
        self._secrets.append(auth_pass)  # Track for masking

        # -- Auth section --
        auth_conf = f"""
; === TrunkChecker Temp Config ===
[{safe_name}]
type=auth
auth_type=userpass
username={auth_id}
password={auth_pass}
"""

        # -- AOR section --
        aor_conf = f"""
; === TrunkChecker Temp Config ===
[{safe_name}]
type=aor
contact=sip:{registrar}:{sip_port}
qualify_frequency=60
"""

        # -- Registration section --
        reg_conf = f"""
; === TrunkChecker Temp Config ===
[{safe_name}]
type=registration
transport=transport-udp
outbound_auth={safe_name}
server_uri=sip:{registrar}:{sip_port}
client_uri=sip:{auth_id}@{registrar}:{sip_port}
retry_interval=60
expiration=300
"""

        # -- Endpoint section --
        endpoint_conf = f"""
; === TrunkChecker Temp Config ===
[{safe_name}]
type=endpoint
transport=transport-udp
context=from-pstn-toheader
disallow=all
allow=alaw
allow=ulaw
allow=g729
allow=opus
outbound_auth={safe_name}
aors={safe_name}
from_user={auth_id}
from_domain={registrar}
"""

        # -- Identify section --
        identify_conf = f"""
; === TrunkChecker Temp Config ===
[{safe_name}]
type=identify
endpoint={safe_name}
match={registrar}
"""

        files_to_write = {
            "/etc/asterisk/pjsip.auth_custom_post.conf": auth_conf,
            "/etc/asterisk/pjsip.aor_custom_post.conf": aor_conf,
            "/etc/asterisk/pjsip.registration_custom_post.conf": reg_conf,
            "/etc/asterisk/pjsip.endpoint_custom_post.conf": endpoint_conf,
            "/etc/asterisk/pjsip.identify_custom_post.conf": identify_conf,
        }

        self.config_files = files_to_write

        for filepath, content in files_to_write.items():
            # Append to file (don't overwrite existing custom config)
            escaped = content.replace('"', '\\"').replace("'", "'\\''")
            cmd = f"echo '{escaped}' >> {filepath}"
            out, err, code = self._exec(cmd)
            if code != 0:
                self.logger.error(f"Failed to write {filepath}: {err}")
                return False
            self.logger.info(f"Wrote config to {filepath}")

        return True

    def reload_asterisk(self):
        """Reload pjsip module in Asterisk."""
        self.logger.info("Reloading Asterisk pjsip...")
        out, err, code = self._exec("asterisk -rx 'module reload res_pjsip.so'", timeout=15)
        if code == 0:
            self.logger.info("pjsip reloaded successfully")
            time.sleep(3)  # Give it time to register
            return True
        self.logger.error(f"Reload failed: {err}")
        return False

    def check_registration(self, timeout=15):
        """Check if the trunk registered successfully."""
        self.logger.info(f"Checking registration for {self.trunk_name}...")
        start = time.time()
        while time.time() - start < timeout:
            out, err, code = self._exec("asterisk -rx 'pjsip show registrations'")
            if code == 0:
                for line in out.split("\n"):
                    if self.trunk_name in line:
                        if "Registered" in line:
                            self.logger.info(f"REGISTERED: {line.strip()}")
                            return True, "Registered"
                        elif "Rejected" in line:
                            self.logger.error(f"REJECTED: {line.strip()}")
                            return False, "Rejected"
                        elif "Unregistered" in line:
                            pass  # Still trying
            time.sleep(2)
        
        # Final check
        out, _, _ = self._exec("asterisk -rx 'pjsip show registrations'")
        self.logger.error(f"Registration timeout. Current state:\n{out}")
        return False, "Timeout"

    def check_endpoint(self):
        """Get endpoint details for diagnostics."""
        out, err, code = self._exec(f"asterisk -rx 'pjsip show endpoint {self.trunk_name}'")
        if code == 0:
            self.logger.info(f"Endpoint info:\n{out[:500]}")
        return out

    def test_outbound_call(self, destination, ring_time=10):
        """Make a test outbound call through the trunk."""
        self.logger.info(f"Originating test call to {destination} via {self.trunk_name}...")
        cmd = f"asterisk -rx 'channel originate PJSIP/{destination}@{self.trunk_name} application Wait {ring_time}'"
        out, err, code = self._exec(cmd, timeout=ring_time + 10)
        
        if code == 0:
            self.logger.info(f"Call originated: {out}")
            return True
        else:
            self.logger.error(f"Call failed: {err}")
            return False

    def wait_for_inbound(self, timeout=60):
        """Monitor Asterisk channels for incoming call."""
        self.logger.info(f"Waiting for inbound call (checking channels for {timeout}s)...")
        print("  (Press Ctrl+C to skip)")
        start = time.time()
        try:
            while time.time() - start < timeout:
                out, _, code = self._exec("asterisk -rx 'core show channels concise'")
                if code == 0 and out.strip():
                    if self.trunk_name in out or "from-pstn" in out:
                        self.logger.info(f"Inbound call detected: {out.strip()}")
                        return True
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n  Inbound test skipped.")
            return False
        return False

    def cleanup(self):
        """Remove temporary config and reload."""
        self.logger.info("Cleaning up temporary trunk config...")
        
        for filepath in self.config_files:
            # Remove lines between our markers
            cmd = f"sed -i '/=== TrunkChecker Temp Config ===/,/^$/d' {filepath}"
            self._exec(cmd)
            # Also remove any remaining lines with our trunk name
            cmd = f"sed -i '/{self.trunk_name}/d' {filepath}"
            self._exec(cmd)
            self.logger.info(f"Cleaned {filepath}")

        self.reload_asterisk()
        self.logger.info("Cleanup complete")

    def run_full_test(self, registrar, sip_port, trunk_number, auth_id, auth_pass, 
                      destination_number=None, trunk_name="test"):
        """Run complete NethVoice proxy test: inject, test, cleanup."""
        results = {
            "access": False,
            "inject": False,
            "registration": False,
            "registration_detail": "",
            "inbound": None,
            "outbound": None,
            "diagnostics": []
        }

        try:
            # 1. Check access
            print("\n[PROXY TEST 1/6] Checking FreePBX container access...")
            if not self.check_access():
                print("\u274c ERRORE: Cannot access FreePBX container.")
                print("  Make sure you're running from the NethVoice module")
                print("  and the 'freepbx' container is running.")
                results["diagnostics"].append("Container access failed")
                return results
            results["access"] = True
            print("OK - FreePBX container accessible")

            # 2. Inject config
            print("\n[PROXY TEST 2/6] Injecting temporary trunk config...")
            if not self.inject_trunk(registrar, sip_port, trunk_number, auth_id, auth_pass, trunk_name):
                print("ERRORE: Failed to write config files.")
                results["diagnostics"].append("Config injection failed")
                return results
            results["inject"] = True
            print(f"OK - Trunk '{self.trunk_name}' config injected")

            # 3. Reload and check registration
            print("\n[PROXY TEST 3/6] Reloading Asterisk and checking registration...")
            self.reload_asterisk()
            
            registered, detail = self.check_registration(timeout=20)
            results["registration"] = registered
            results["registration_detail"] = detail
            
            if registered:
                print("OK - Trunk registered through proxy!")
            else:
                print(f"ERRORE: Registration failed ({detail})")
                if detail == "Rejected":
                    results["diagnostics"].append("Provider rejected credentials through proxy")
                    results["diagnostics"].append("Check: auth_id, password, provider IP whitelist")
                elif detail == "Timeout":
                    results["diagnostics"].append("Registration timed out through proxy")
                    results["diagnostics"].append("Check: proxy connectivity to provider")
                    results["diagnostics"].append("Check: firewall rules on proxy")
                    results["diagnostics"].append("Check: Kamailio routing to provider domain")

            # 4. Endpoint diagnostics
            print("\n[PROXY TEST 4/6] Checking endpoint details...")
            endpoint_info = self.check_endpoint()
            if endpoint_info:
                print("OK - Endpoint configured")

            # 5. Inbound test
            print("\n[PROXY TEST 5/6] Inbound Call Test")
            from main import ask_yes_no
            if ask_yes_no("Do you want to test an INBOUND call? Call the trunk number now [y/N]"):
                print(f"Waiting for inbound call to {trunk_number} (60s timeout)...")
                if self.wait_for_inbound(timeout=60):
                    print("OK - Inbound call detected through proxy!")
                    results["inbound"] = True
                else:
                    print("ERRORE: No inbound call detected.")
                    results["inbound"] = False
                    results["diagnostics"].append("Inbound call not received through proxy")
                    results["diagnostics"].append("Check: provider inbound routing")
                    results["diagnostics"].append("Check: Kamailio identify/match for this trunk")

            # 6. Outbound test
            if destination_number:
                print(f"\n[PROXY TEST 6/6] Outbound Call Test")
                if ask_yes_no(f"Do you want to test an OUTBOUND call to {destination_number}? [y/N]"):
                    print(f"Calling {destination_number} through proxy...")
                    if self.test_outbound_call(destination_number):
                        print("OK - Outbound call initiated through proxy!")
                        results["outbound"] = True
                    else:
                        print("ERRORE: Outbound call failed.")
                        results["outbound"] = False
                        results["diagnostics"].append("Outbound call failed through proxy")
                        results["diagnostics"].append("Check: provider allows outbound from this trunk")
                        results["diagnostics"].append("Check: codec compatibility")

        finally:
            # ALWAYS cleanup
            print("\n[CLEANUP] Removing temporary trunk config...")
            self.cleanup()
            print("OK - Temporary config removed")

        # Print summary
        print("\n" + "=" * 60)
        print("   NETHVOICE PROXY TEST RESULTS")
        print("=" * 60)
        print(f"  Container Access:    {'OK' if results['access'] else 'FAIL'}")
        print(f"  Config Injection:    {'OK' if results['inject'] else 'FAIL'}")
        print(f"  Registration:        {'OK' if results['registration'] else 'FAIL'} ({results['registration_detail']})")
        if results["inbound"] is not None:
            print(f"  Inbound Call:        {'OK' if results['inbound'] else 'FAIL'}")
        if results["outbound"] is not None:
            print(f"  Outbound Call:       {'OK' if results['outbound'] else 'FAIL'}")
        
        if results["diagnostics"]:
            print(f"\n  [DIAGNOSTICA]")
            for d in results["diagnostics"]:
                print(f"    - {d}")
        
        print("=" * 60)
        
        return results
