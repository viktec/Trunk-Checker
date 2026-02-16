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
        # Check if container exists/runs
        out, err, code = self._exec("asterisk -rx 'core show version'")
        if code == 0:
            self.logger.info(f"FreePBX container accessible: {out.strip()}")
            return True
        else:
            self.logger.error(f"FreePBX access failed: {err}")
            return False

    def detect_transport(self):
        """Auto-detect the UDP transport name from Asterisk."""
        # Assuming most FreePBX use 0.0.0.0-udp or transport-udp depending on version
        
        self.logger.info("Detecting PJSIP UDP transport...")
        # Command: pjsip show transports
        # Output cols: Transport: <Name> <Type> ...
        cmd = "asterisk -rx 'pjsip show transports'"
        out, err, code = self._exec(cmd)
        
        if code != 0:
            self.logger.error("Failed to list transports")
            return "0.0.0.0-udp" # Common default

        lines = out.splitlines()
        for line in lines:
            line = line.strip()
            # Example: Transport:  <TransportId........>  <Type>
            #          Transport:  0.0.0.0-udp               udp   ...
            if line.startswith("Transport:"):
                parts = line.split()
                # parts[0]=Transport:, parts[1]=Name, parts[2]=Type
                if len(parts) >= 3 and parts[2] == "udp":
                    t_name = parts[1]
                    self.logger.info(f"Auto-detected UDP Transport: {t_name}")
                    return t_name
                    
        self.logger.warning("No explicit UDP transport found, using fallback '0.0.0.0-udp'")
        return "0.0.0.0-udp"


    def detect_outbound_proxy(self):
        """Auto-detect the outbound proxy from existing FreePBX/pjsip config."""
        self.logger.info("Detecting outbound proxy from existing config...")
        
        # Method 1: Check existing trunk registrations for outbound_proxy
        out, _, code = self._exec("grep -r 'outbound_proxy' /etc/asterisk/pjsip*.conf 2>/dev/null | head -5")
        if code == 0 and out.strip():
            for line in out.split("\n"):
                if "outbound_proxy" in line and "=" in line:
                    val = line.split("=", 1)[1].strip()
                    if val and val != "(vuoto)" and "sip:" in val:
                        self.logger.info(f"Found outbound_proxy in config: {val}")
                        return val
        
        # Method 2: Check pjsip show endpoint on existing trunks to find proxy
        reg_out, _, _ = self._exec("asterisk -rx 'pjsip show registrations'")
        if reg_out:
            for line in reg_out.split("\n"):
                if "Registered" in line and "_trunkchk_" not in line:
                    trunk_id = line.split("/")[0].strip()
                    if trunk_id:
                        ep_out, _, _ = self._exec(f"asterisk -rx 'pjsip show endpoint {trunk_id}'")
                        if ep_out and "outbound_proxy" in ep_out.lower():
                            for ep_line in ep_out.split("\n"):
                                if "outbound_proxy" in ep_line.lower() and "sip:" in ep_line:
                                    val = ep_line.split(":", 1)[1].strip() if ":" in ep_line else ""
                                    if val.startswith("sip:"):
                                        self.logger.info(f"Found proxy from existing trunk: {val}")
                                        return val
        
        # Method 3: Check transport config for external_signaling_address
        trans_out, _, _ = self._exec("asterisk -rx 'pjsip show transports'")
        if trans_out:
            self.logger.info(f"Transport info: {trans_out[:300]}")
        
        self.logger.info("No outbound proxy detected — Asterisk uses system-level routing")
        return None

    def inject_trunk(self, registrar, sip_port, trunk_number, auth_id, auth_pass, trunk_name=None, outbound_proxy=None, transport_name="0.0.0.0-udp"):
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
        reg_proxy_line = f"outbound_proxy={outbound_proxy}" if outbound_proxy else ""
        reg_conf = f"""
; === TrunkChecker Temp Config ===
[{safe_name}]
type=registration
transport={transport_name}
outbound_auth={safe_name}
{reg_proxy_line}
server_uri=sip:{registrar}:{sip_port}
client_uri=sip:{auth_id}@{registrar}:{sip_port}
retry_interval=60
expiration=300
"""

        # -- Endpoint section (use custom context so inbound calls are answered) --
        ep_proxy_line = f"outbound_proxy={outbound_proxy}" if outbound_proxy else ""
        endpoint_conf = f"""
; === TrunkChecker Temp Config ===
[{safe_name}]
type=endpoint
transport={transport_name}
context=trunkchk-inbound-test
disallow=all
allow=alaw
allow=ulaw
allow=g729
allow=opus
outbound_auth={safe_name}
{ep_proxy_line}
aors={safe_name}
from_user={auth_id}
from_domain={registrar}
"""

        # -- Identify section --
        # -- Identify section --
        # Add proxy IP to match list so inbound calls from proxy are recognized
        match_list = registrar
        if outbound_proxy:
            try:
                # Extract IP/Host from proxy string (e.g. sip:10.5.4.1:5060;lr -> 10.5.4.1)
                cleaned = outbound_proxy.replace("sip:", "")
                cleaned = cleaned.split(";")[0]  # Remove params
                proxy_host = cleaned.split(":")[0]  # Remove port
                
                if proxy_host and proxy_host != registrar:
                    match_list = f"{registrar},{proxy_host}"
            except:
                pass

        identify_conf = f"""
; === TrunkChecker Temp Config ===
[{safe_name}]
type=identify
endpoint={safe_name}
match={match_list}
"""

        # -- Dialplan: catch-all extension to answer inbound calls --
        # We inject into [trunkchk-inbound-test] for matched calls
        # AND into [from-pstn-custom](+) for anonymous/unmatched calls (fallback)
        dialplan_conf = f"""
; === TrunkChecker Temp Config ===
[trunkchk-inbound-test]
exten => {auth_id},1,Answer()
 same => n,Wait(5)
 same => n,Hangup()
exten => {trunk_number},1,Answer()
 same => n,Wait(5)
 same => n,Hangup()
exten => _X.,1,Answer()
 same => n,Wait(5)
 same => n,Hangup()
; (Continuation for cleanup safety)
[from-pstn-custom](+)
exten => {auth_id},1,Answer()
 same => n,Wait(5)
 same => n,Hangup()
exten => {trunk_number},1,Answer()
 same => n,Wait(5)
 same => n,Hangup()
; Also inject into ext-did-custom to catch calls falling through from-trunk
[ext-did-custom](+)
exten => {auth_id},1,Answer()
 same => n,Wait(5)
 same => n,Hangup()
exten => {trunk_number},1,Answer()
 same => n,Wait(5)
 same => n,Hangup()
"""

        files_to_write = {
            "/etc/asterisk/pjsip.auth_custom_post.conf": auth_conf,
            "/etc/asterisk/pjsip.aor_custom_post.conf": aor_conf,
            "/etc/asterisk/pjsip.registration_custom_post.conf": reg_conf,
            "/etc/asterisk/pjsip.endpoint_custom_post.conf": endpoint_conf,
            "/etc/asterisk/pjsip.identify_custom_post.conf": identify_conf,
            "/etc/asterisk/extensions_custom.conf": dialplan_conf,
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

    def reload_asterisk(self, dialplan=False):
        """Reload pjsip module (and optionally dialplan) in Asterisk."""
        self.logger.info("Reloading Asterisk pjsip...")
        out, err, code = self._exec("asterisk -rx 'module reload res_pjsip.so'", timeout=15)
        if code == 0:
            self.logger.info("pjsip reloaded successfully")
        else:
            self.logger.error(f"pjsip reload failed: {err}")
        
        if dialplan:
            self.logger.info("Reloading dialplan...")
            self._exec("asterisk -rx 'dialplan reload'", timeout=10)
        
        time.sleep(3)  # Give it time to register
        return code == 0

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

    def test_outbound_call(self, destination, ring_time=15):
        """Make a test outbound call through the trunk and verify it connects."""
        self.logger.info(f"Originating test call to {destination} via {self.trunk_name}...")
        cmd = f"asterisk -rx 'channel originate PJSIP/{destination}@{self.trunk_name} application Wait {ring_time}'"
        out, err, code = self._exec(cmd, timeout=5)
        
        if code != 0:
            self.logger.error(f"Originate command failed: {err}")
            return False
        
        # Monitor channel to see if call exists
        # core show channels concise format: Channel!Context!Ext!Pri!State!App!...
        # State is at index 4: Down=setup, Ringing=ringing, Up=answered
        print("  Waiting for call to connect (Ctrl+C to skip)...")
        start = time.time()
        best_state = None
        try:
            while time.time() - start < ring_time + 5:
                ch_out, _, ch_code = self._exec("asterisk -rx 'core show channels concise'")
                if ch_code == 0 and ch_out.strip():
                    for line in ch_out.split("\n"):
                        if self.trunk_name.lower() in line.lower() or destination in line:
                            parts = line.split("!")
                            state = parts[4] if len(parts) > 4 else "?"
                            self.logger.info(f"Outbound channel [{state}]: {line.strip()}")
                            
                            if state == "Up":
                                print(f"  ✅ Call answered!")
                                return True
                            elif state in ("Ringing", "Ring"):
                                print(f"  📞 Phone ringing!")
                                best_state = state
                            elif state == "Down" and not best_state:
                                best_state = "Down (setup)"
                                print(f"\r  📡 Call in progress (SIP setup)...   ", end="", flush=True)
                
                # If we saw ringing, that's already a success
                if best_state in ("Ringing", "Ring"):
                    return True
                    
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  Outbound test interrupted.")
        
        if best_state:
            print(f"\n  Call reached state: {best_state}")
            self.logger.info(f"Best call state seen: {best_state}")
            return True
        
        self.logger.error("No outbound channel detected")
        return False

    def wait_for_inbound(self, timeout=60):
        """Monitor Asterisk channels for incoming call in trunkchk-inbound-test context."""
        self.logger.info(f"Waiting for inbound call (monitoring channels for {timeout}s)...")
        print("  (Press Ctrl+C to skip)")
        
        start = time.time()
        try:
            while time.time() - start < timeout:
                elapsed = int(time.time() - start)
                remaining = timeout - elapsed
                print(f"\r  Listening... {remaining}s remaining  ", end="", flush=True)
                
                # Check for active channels in our custom context
                ch_out, _, ch_code = self._exec("asterisk -rx 'core show channels concise'")
                if ch_code == 0 and ch_out.strip():
                    if "trunkchk-inbound-test" in ch_out or self.trunk_name in ch_out:
                        self.logger.info(f"Inbound channel detected: {ch_out.strip()}")
                        print(f"\n  ✅ Inbound call detected and answered!")
                        return True
                
                # Also check core show calls (count > 0)
                calls_out, _, _ = self._exec("asterisk -rx 'core show calls'")
                if calls_out and "active call" in calls_out.lower():
                    count = calls_out.split()[0] if calls_out else "0"
                    if count != "0":
                        self.logger.info(f"Active calls: {calls_out.strip()}")
                        print(f"\n  ✅ Inbound call detected ({calls_out.strip()})!")
                        return True
                
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        
        print("\n  Inbound test completed — no call detected.")
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
            # Remove trunkchk context lines from extensions_custom.conf
            if "extensions_custom" in filepath:
                self._exec(f"sed -i '/trunkchk-inbound-test/d' {filepath}")
                self._exec(f"sed -i '/same => n,Wait/d' {filepath}")
                self._exec(f"sed -i '/same => n,Hangup/d' {filepath}")
            self.logger.info(f"Cleaned {filepath}")

        self.reload_asterisk(dialplan=True)
        self.logger.info("Cleanup complete")

    def run_full_test(self, registrar, sip_port, trunk_number, auth_id, auth_pass, 
                      destination_number=None, trunk_name="test", outbound_proxy=None):
        """Run complete NethVoice proxy test: inject, test, cleanup."""
        results = {
            "access": False,
            "inject": False,
            "registration": False,
            "registration_detail": "",
            "inbound": None,
            "outbound": None,
            "outbound_proxy": None,
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

            # 1.2 Detect Transport
            transport_name = self.detect_transport()


            # 1.5 Detect Proxy if not provided
            if not outbound_proxy:
                detected = self.detect_outbound_proxy()
                if detected:
                    print(f"  \u2139 Auto-detected Outbound Proxy: {detected}")
                    from main import ask_yes_no
                    if ask_yes_no(f"Use detected proxy {detected}? [Y/n]", default='y'):
                        outbound_proxy = detected
            
            if outbound_proxy:
                 print(f"  Using Outbound Proxy: {outbound_proxy}")
                 results["outbound_proxy"] = outbound_proxy

            # 2. Inject config
            print("\n[PROXY TEST 2/6] Injecting temporary trunk config...")
            if not self.inject_trunk(registrar, sip_port, trunk_number, auth_id, auth_pass, trunk_name, outbound_proxy, transport_name=transport_name):
                print("ERRORE: Failed to write config files.")
                results["diagnostics"].append("Config injection failed")
                return results
            results["inject"] = True
            print(f"OK - Trunk '{self.trunk_name}' config injected")

            # 3. Reload and check registration
            print("\n[PROXY TEST 3/6] Reloading Asterisk and checking registration...")
            # Reload dialplan too since we modified extensions_custom.conf
            self.reload_asterisk(dialplan=True)
            
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
                    results["diagnostics"].append("Check: NethVoice Inbound Route (DID mapping) for this number")
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
