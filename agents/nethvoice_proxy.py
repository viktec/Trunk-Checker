"""
NethVoice Proxy Test Mode
Temporarily injects pjsip trunk config into FreePBX/Asterisk,
tests through the real Kamailio proxy, and cleans up after.
"""
import base64
import signal
import subprocess
import time
import re


# Unique markers for config blocks — cleanup uses these for reliable deletion
_MARKER_START = "; === TrunkChecker START ==="
_MARKER_END = "; === TrunkChecker END ==="


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
        if code == 0:
            self.logger.info(f"FreePBX container accessible: {out.strip()}")
            return True
        else:
            self.logger.error(f"FreePBX access failed: {err}")
            return False

    def detect_transport(self):
        """Auto-detect the UDP transport name from Asterisk."""
        self.logger.info("Detecting PJSIP UDP transport...")
        cmd = "asterisk -rx 'pjsip show transports'"
        out, err, code = self._exec(cmd)
        
        if code != 0:
            self.logger.error("Failed to list transports")
            return "0.0.0.0-udp"

        lines = out.splitlines()
        for line in lines:
            line = line.strip()
            if line.startswith("Transport:"):
                parts = line.split()
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

    def _build_config_block(self, lines):
        """Build a config block wrapped in START/END markers, filtering out empty lines."""
        filtered = [l for l in lines if l.strip()]
        block = _MARKER_START + "\n"
        block += "\n".join(filtered) + "\n"
        block += _MARKER_END + "\n"
        return block

    def inject_trunk(self, registrar, sip_port, trunk_number, auth_id, auth_pass,
                     trunk_name=None, outbound_proxy=None, transport_name="0.0.0.0-udp",
                     from_domain=None, client_uri=None, server_uri=None):
        """Write temporary pjsip config files for the trunk."""
        self.trunk_name = f"{self.TRUNK_PREFIX}{trunk_name or 'test'}"
        safe_name = self.trunk_name
        self._secrets.append(auth_pass)  # Track for masking

        # Defaults for optional fields
        effective_from_domain = from_domain or registrar
        effective_server_uri = server_uri or f"sip:{registrar}:{sip_port}"
        effective_client_uri = client_uri or f"sip:{auth_id}@{registrar}:{sip_port}"

        # -- Auth section --
        auth_conf = self._build_config_block([
            f"[{safe_name}]",
            "type=auth",
            "auth_type=userpass",
            f"username={auth_id}",
            f"password={auth_pass}",
        ])

        # -- AOR section --
        aor_conf = self._build_config_block([
            f"[{safe_name}]",
            "type=aor",
            f"contact=sip:{registrar}:{sip_port}",
            "qualify_frequency=60",
        ])

        # -- Registration section --
        reg_lines = [
            f"[{safe_name}]",
            "type=registration",
            f"transport={transport_name}",
            f"outbound_auth={safe_name}",
        ]
        if outbound_proxy:
            reg_lines.append(f"outbound_proxy={outbound_proxy}")
        reg_lines.extend([
            f"server_uri={effective_server_uri}",
            f"client_uri={effective_client_uri}",
            "retry_interval=60",
            "expiration=300",
        ])
        reg_conf = self._build_config_block(reg_lines)

        # -- Endpoint section --
        ep_lines = [
            f"[{safe_name}]",
            "type=endpoint",
            f"transport={transport_name}",
            "context=trunkchk-inbound-test",
            "disallow=all",
            "allow=alaw",
            "allow=ulaw",
            "allow=g729",
            "allow=opus",
            f"outbound_auth={safe_name}",
        ]
        if outbound_proxy:
            ep_lines.append(f"outbound_proxy={outbound_proxy}")
        ep_lines.extend([
            f"aors={safe_name}",
            f"from_user={auth_id}",
            f"from_domain={effective_from_domain}",
        ])
        endpoint_conf = self._build_config_block(ep_lines)

        # -- Identify section --
        match_list = registrar
        if outbound_proxy:
            try:
                cleaned = outbound_proxy.replace("sip:", "")
                cleaned = cleaned.split(";")[0]
                proxy_host = cleaned.split(":")[0]
                if proxy_host and proxy_host != registrar:
                    match_list = f"{registrar},{proxy_host}"
            except:
                pass

        identify_conf = self._build_config_block([
            f"[{safe_name}]",
            "type=identify",
            f"endpoint={safe_name}",
            f"match={match_list}",
        ])

        # -- Dialplan --
        dialplan_lines = [
            "[trunkchk-inbound-test]",
            f"exten => {auth_id},1,Answer()",
            " same => n,Wait(5)",
            " same => n,Hangup()",
            f"exten => {trunk_number},1,Answer()",
            " same => n,Wait(5)",
            " same => n,Hangup()",
            "exten => _X.,1,Answer()",
            " same => n,Wait(5)",
            " same => n,Hangup()",
            "[from-pstn-custom](+)",
            f"exten => {auth_id},1,Answer()",
            " same => n,Wait(5)",
            " same => n,Hangup()",
            f"exten => {trunk_number},1,Answer()",
            " same => n,Wait(5)",
            " same => n,Hangup()",
            "[ext-did-custom](+)",
            f"exten => {auth_id},1,Answer()",
            " same => n,Wait(5)",
            " same => n,Hangup()",
            f"exten => {trunk_number},1,Answer()",
            " same => n,Wait(5)",
            " same => n,Hangup()",
        ]
        dialplan_conf = self._build_config_block(dialplan_lines)

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
            # Encode content as base64 to avoid all shell quoting/newline issues
            b64 = base64.b64encode(content.encode('utf-8')).decode('ascii')
            cmd = f"echo {b64} | base64 -d >> {filepath}"
            out, err, code = self._exec(cmd)
            if code != 0:
                self.logger.error(f"Failed to write {filepath}: {err}")
                return False
            self.logger.info(f"Wrote config to {filepath}")

        return True

    def enable_sip_debug(self):
        """Enable PJSIP packet logging to capture full SIP exchange."""
        self.logger.info("Enabling PJSIP SIP debug logging...")
        self._exec("asterisk -rx 'pjsip set logger on'")

    def disable_sip_debug(self):
        """Disable PJSIP packet logging."""
        self._exec("asterisk -rx 'pjsip set logger off'")

    def capture_sip_log(self, lines=200):
        """Capture the last N lines of the Asterisk log for SIP debug analysis."""
        # Asterisk full log is usually at /var/log/asterisk/full
        out, _, code = self._exec(f"tail -n {lines} /var/log/asterisk/full 2>/dev/null || tail -n {lines} /var/log/asterisk/messages 2>/dev/null", timeout=5)
        if code == 0:
            return out
        return ""

    def extract_sip_response(self, log_text, status_code=None):
        """Extract the SIP response from captured log text.
        
        Looks for the full SIP response message (e.g., 403 Forbidden) 
        including all headers and body that the provider sent back.
        """
        if not log_text:
            return None
        
        lines = log_text.split("\n")
        capturing = False
        response_lines = []
        
        for line in lines:
            # Look for the start of an inbound SIP response
            # Asterisk logs them like: <--- Received SIP response ... ---
            # Or the raw SIP line: SIP/2.0 403 Forbidden
            if f"SIP/2.0 {status_code}" in line if status_code else "SIP/2.0 4" in line:
                capturing = True
                response_lines = [line]
                continue
            
            if capturing:
                # A blank/empty line or a new log entry starts = end of SIP message
                stripped = line.strip()
                if stripped.startswith("[") and "VERBOSE" in stripped:
                    # New Asterisk log line — end of SIP message
                    break
                if stripped.startswith("<--") or stripped.startswith("---"):
                    break
                response_lines.append(line)
        
        return "\n".join(response_lines) if response_lines else None

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

    def get_registration_error(self):
        """Get detailed registration error info from Asterisk."""
        self.logger.info(f"Getting registration error details for {self.trunk_name}...")
        
        details = []
        
        # 1. Try pjsip show registration <name> for detailed status
        out, _, code = self._exec(f"asterisk -rx 'pjsip show registration {self.trunk_name}'")
        if code == 0 and out.strip():
            self.logger.info(f"Registration detail:\n{out}")
            details.append(out)
        
        # 2. Fallback: check registrations list
        if not details:
            out, _, _ = self._exec("asterisk -rx 'pjsip show registrations'")
            if out:
                for line in out.split("\n"):
                    if self.trunk_name in line:
                        details.append(line.strip())
        
        # 3. Try to capture SIP response from Asterisk log (most valuable info)
        log_text = self.capture_sip_log(lines=300)
        if log_text:
            # Look for 4xx/5xx responses related to our trunk
            for error_code in [403, 401, 404, 407, 500, 503]:
                sip_resp = self.extract_sip_response(log_text, error_code)
                if sip_resp:
                    details.append(f"\n  [SIP {error_code} Response from Provider]")
                    details.append(sip_resp)
                    break
        
        return "\n".join(details) if details else "Unable to retrieve error details"

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
                
                ch_out, _, ch_code = self._exec("asterisk -rx 'core show channels concise'")
                if ch_code == 0 and ch_out.strip():
                    if "trunkchk-inbound-test" in ch_out or self.trunk_name in ch_out:
                        self.logger.info(f"Inbound channel detected: {ch_out.strip()}")
                        print(f"\n  ✅ Inbound call detected and answered!")
                        return True
                
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
            try:
                # Delete everything between START and END markers (inclusive)
                cmd = f"sed -i '/=== TrunkChecker START ===/,/=== TrunkChecker END ===/d' {filepath}"
                self._exec(cmd)
                # Safety net: remove any remaining lines with our trunk name
                if self.trunk_name:
                    cmd = f"sed -i '/{self.trunk_name}/d' {filepath}"
                    self._exec(cmd)
                # Remove trunkchk context lines from extensions_custom.conf
                if "extensions_custom" in filepath:
                    self._exec(f"sed -i '/trunkchk-inbound-test/d' {filepath}")
                    self._exec(f"sed -i '/same => n,Wait/d' {filepath}")
                    self._exec(f"sed -i '/same => n,Hangup/d' {filepath}")
                self.logger.info(f"Cleaned {filepath}")
            except Exception as e:
                self.logger.error(f"Error cleaning {filepath}: {e}")

        self.reload_asterisk(dialplan=True)
        self.logger.info("Cleanup complete")

    def _cleanup_config_only(self):
        """Remove config files without reloading — used before re-inject in retry loop."""
        self.logger.info("Removing config (no reload)...")
        for filepath in self.config_files:
            cmd = f"sed -i '/=== TrunkChecker START ===/,/=== TrunkChecker END ===/d' {filepath}"
            self._exec(cmd)
            if self.trunk_name:
                cmd = f"sed -i '/{self.trunk_name}/d' {filepath}"
                self._exec(cmd)
            if "extensions_custom" in filepath:
                self._exec(f"sed -i '/trunkchk-inbound-test/d' {filepath}")
                self._exec(f"sed -i '/same => n,Wait/d' {filepath}")
                self._exec(f"sed -i '/same => n,Hangup/d' {filepath}")

    def _print_rejection_diagnostics(self, error_detail, registrar, auth_id, outbound_proxy):
        """Print detailed troubleshooting guide for rejected registrations."""
        print("\n  ┌──────────────────────────────────────────────────┐")
        print("  │          DIAGNOSTICA REGISTRAZIONE RIFIUTATA     │")
        print("  └──────────────────────────────────────────────────┘")
        
        # Detect specific error code from the detail
        is_403 = "403" in error_detail
        is_401 = "401" in error_detail and "403" not in error_detail
        
        if is_403:
            print("\n  Il provider ha risposto con 403 Forbidden.")
            print("  Questo significa che il provider ha RIFIUTATO le credenziali.")
            print("\n  Cause più comuni (in ordine di probabilità):")
            print("  ──────────────────────────────────────────────")
            print(f"  1. PASSWORD ERRATA")
            print(f"     → Verifica la password con il provider")
            print(f"  2. AUTH ID / USERNAME ERRATO")
            print(f"     → Attuale: '{auth_id}'")
            print(f"     → Alcuni provider usano il numero intero come auth_id")
            print(f"     → Altri usano un username alfanumerico separato")
            print(f"  3. IP NON AUTORIZZATO dal provider")
            if outbound_proxy:
                proxy_ip = outbound_proxy.replace("sip:", "").split(";")[0].split(":")[0]
                print(f"     → Il provider deve autorizzare l'IP del proxy: {proxy_ip}")
            else:
                print(f"     → Il provider deve autorizzare l'IP pubblico del server")
            print(f"     → Contatta il provider per verificare la whitelist IP")
            print(f"  4. FROM DOMAIN ERRATO")
            print(f"     → Attuale: '{registrar}'")
            print(f"     → Alcuni provider richiedono un dominio specifico")
            print(f"     → Prova a usare il numero come from_domain")
            print(f"  5. CLIENT URI FORMATO ERRATO")
            print(f"     → Prova: sip:{auth_id}@{registrar}")
            print(f"     → Alcuni provider non vogliono la porta nel client_uri")
        
        elif is_401:
            print("\n  Il provider ha risposto con 401 Unauthorized.")
            print("  L'autenticazione digest è fallita.")
            print("\n  Possibili soluzioni:")
            print(f"  1. Verifica username e password nello schema digest")
            print(f"  2. Verifica che il realm corrisponda (guardare sopra il SIP Response)")
            print(f"  3. Alcuni provider richiedono auth_type=md5 invece di userpass")
        
        else:
            print("\n  Registrazione rifiutata dal provider.")
            print("  Controlla i dettagli dell'errore SIP sopra per più informazioni.")

    def _print_timeout_diagnostics(self, registrar, outbound_proxy):
        """Print detailed troubleshooting guide for registration timeouts."""
        print("\n  ┌──────────────────────────────────────────────────┐")
        print("  │            DIAGNOSTICA TIMEOUT REGISTRAZIONE     │")
        print("  └──────────────────────────────────────────────────┘")
        print("\n  Nessuna risposta ricevuta dal provider.")
        print("\n  Possibili cause:")
        print("  ──────────────────────────────────────────────")
        print(f"  1. REGISTRAR NON RAGGIUNGIBILE")
        print(f"     → Verifica che '{registrar}' sia risolvibile via DNS")
        print(f"     → Testa: ping {registrar}")
        if outbound_proxy:
            proxy_ip = outbound_proxy.replace("sip:", "").split(";")[0].split(":")[0]
            print(f"  2. PROXY NON RAGGIUNGE IL PROVIDER")
            print(f"     → Il proxy ({proxy_ip}) deve poter raggiungere {registrar}:5060")
            print(f"     → Testa dal server: nc -zvu {registrar} 5060")
        print(f"  3. FIREWALL BLOCCA IL TRAFFICO SIP")
        print(f"     → Porta UDP 5060 deve essere aperta in uscita")
        print(f"     → Verifica iptables/firewalld sul server")
        print(f"  4. PROVIDER IGNORA IL PACCHETTO")
        print(f"     → L'IP sorgente potrebbe non essere autorizzato")
        print(f"     → Il provider potrebbe richiedere TLS (porta 5061) invece di UDP")
        print(f"  5. PORTA SIP SBAGLIATA")
        print(f"     → Prova con porta 5061 (TLS) o altre porte del provider")

    def run_full_test(self, registrar, sip_port, trunk_number, auth_id, auth_pass, 
                      destination_number=None, trunk_name="test", outbound_proxy=None,
                      from_domain=None, client_uri=None, server_uri=None):
        """Run complete NethVoice proxy test: inject, test, cleanup."""
        from main import ask_yes_no, get_input

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
                    if ask_yes_no(f"Use detected proxy {detected}? [Y/n]", default='y'):
                        outbound_proxy = detected
                    else:
                        # User rejected autodetected proxy — ask for manual one
                        if ask_yes_no("Do you want to specify a different outbound proxy? [y/N]"):
                            manual = get_input("  Outbound Proxy (e.g. sip:10.5.4.1:5060;lr)")
                            if manual.strip():
                                outbound_proxy = manual.strip()
                else:
                    # No proxy autodetected — ask if user wants to specify one
                    if ask_yes_no("No proxy detected. Do you want to specify one manually? [y/N]"):
                        manual = get_input("  Outbound Proxy (e.g. sip:10.5.4.1:5060;lr)")
                        if manual.strip():
                            outbound_proxy = manual.strip()
            
            if outbound_proxy:
                 print(f"  Using Outbound Proxy: {outbound_proxy}")
                 results["outbound_proxy"] = outbound_proxy

            # ── Registration retry loop ──
            # We loop here: inject → reload → check registration
            # If rejected, user can modify params and retry
            max_retries = 10  # Safety limit
            attempt = 0

            while attempt < max_retries:
                attempt += 1

                # 2. Inject config
                step2_label = "[PROXY TEST 2/6]" if attempt == 1 else f"[RETRY {attempt}]"
                print(f"\n{step2_label} Injecting temporary trunk config...")
                if not self.inject_trunk(
                    registrar, sip_port, trunk_number, auth_id, auth_pass,
                    trunk_name, outbound_proxy, transport_name=transport_name,
                    from_domain=from_domain, client_uri=client_uri, server_uri=server_uri
                ):
                    print("ERRORE: Failed to write config files.")
                    results["diagnostics"].append("Config injection failed")
                    return results
                results["inject"] = True
                print(f"OK - Trunk '{self.trunk_name}' config injected")

                # 3. Enable SIP debug, reload and check registration
                step3_label = "[PROXY TEST 3/6]" if attempt == 1 else f"[RETRY {attempt}]"
                print(f"\n{step3_label} Reloading Asterisk and checking registration...")
                
                # Enable SIP debug BEFORE reload to capture the full exchange
                self.enable_sip_debug()
                self.reload_asterisk(dialplan=True)
                
                registered, detail = self.check_registration(timeout=20)
                results["registration"] = registered
                results["registration_detail"] = detail
                
                # Disable debug after check
                self.disable_sip_debug()
                
                if registered:
                    print("OK - Trunk registered through proxy!")
                    break  # Exit retry loop — proceed to call tests
                
                # ── Registration failed ──
                print(f"\n❌ Registration FAILED ({detail})")
                
                # Get detailed error from provider (with full SIP response)
                error_detail = self.get_registration_error()
                print(f"\n  [PROVIDER ERROR DETAIL]")
                for line in error_detail.split("\n"):
                    print(f"  {line}")
                
                if detail == "Rejected":
                    results["diagnostics"].append("Provider rejected credentials through proxy")
                    results["diagnostics"].append("Check: auth_id, password, provider IP whitelist")
                    # Enhanced 403/401 specific diagnostics
                    self._print_rejection_diagnostics(error_detail, registrar, auth_id, outbound_proxy)
                elif detail == "Timeout":
                    results["diagnostics"].append("Registration timed out through proxy")
                    results["diagnostics"].append("Check: proxy connectivity to provider")
                    results["diagnostics"].append("Check: firewall rules on proxy")
                    results["diagnostics"].append("Check: Kamailio routing to provider domain")
                    self._print_timeout_diagnostics(registrar, outbound_proxy)

                # Ask user if they want to retry with different params
                print("\n  Current configuration:")
                print(f"    Registrar:      {registrar}")
                print(f"    Auth ID:        {auth_id}")
                print(f"    Outbound Proxy: {outbound_proxy or '(none)'}")
                print(f"    From Domain:    {from_domain or registrar}")
                print(f"    Server URI:     {server_uri or f'sip:{registrar}:{sip_port}'}")
                print(f"    Client URI:     {client_uri or f'sip:{auth_id}@{registrar}:{sip_port}'}")

                if not ask_yes_no("\nDo you want to modify the data and retry? [y/N]"):
                    print("  Registration test aborted by user.")
                    # Cleanup and return — do NOT continue to inbound/outbound tests
                    return results

                # ── User wants to retry: ask for new values ──
                # Cleanup config files first (without reload)
                self._cleanup_config_only()

                print("\n  [MODIFY DATA] Press Enter to keep the current value:")
                
                new_registrar = get_input(f"  Registrar [{registrar}]")
                if new_registrar.strip():
                    registrar = new_registrar.strip()

                new_port = get_input(f"  SIP Port [{sip_port}]")
                if new_port.strip():
                    try:
                        sip_port = int(new_port.strip())
                    except ValueError:
                        print("    Invalid port, keeping current value.")

                new_auth_id = get_input(f"  Auth ID [{auth_id}]")
                if new_auth_id.strip():
                    auth_id = new_auth_id.strip()

                import getpass
                new_pass = getpass.getpass(f"  Password [****]: ")
                if new_pass.strip():
                    auth_pass = new_pass.strip()

                new_proxy = get_input(f"  Outbound Proxy [{outbound_proxy or '(none)'}]")
                if new_proxy.strip():
                    outbound_proxy = new_proxy.strip()

                new_from_domain = get_input(f"  From Domain [{from_domain or registrar}]")
                if new_from_domain.strip():
                    from_domain = new_from_domain.strip()

                new_server_uri = get_input(f"  Server URI [{server_uri or f'sip:{registrar}:{sip_port}'}]")
                if new_server_uri.strip():
                    server_uri = new_server_uri.strip()

                new_client_uri = get_input(f"  Client URI [{client_uri or f'sip:{auth_id}@{registrar}:{sip_port}'}]")
                if new_client_uri.strip():
                    client_uri = new_client_uri.strip()

                print(f"\n  Retrying with updated configuration...")
                # Loop continues: inject → reload → check again

            else:
                # max_retries exceeded
                print(f"\n❌ Maximum retry attempts ({max_retries}) reached. Aborting.")
                return results

            # ── Registration succeeded — continue with tests ──

            # 4. Endpoint diagnostics
            print("\n[PROXY TEST 4/6] Checking endpoint details...")
            endpoint_info = self.check_endpoint()
            if endpoint_info:
                print("OK - Endpoint configured")

            # 5. Inbound test
            print("\n[PROXY TEST 5/6] Inbound Call Test")
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
            # ALWAYS cleanup — suppress SIGINT so double Ctrl+C cannot abort this
            print("\n[CLEANUP] Removing temporary trunk config...")
            try:
                old_sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
            except (OSError, ValueError):
                old_sigint = None
            try:
                self.cleanup()
                print("OK - Temporary config removed")
            except Exception as e:
                self.logger.error(f"Cleanup failed: {e}")
                print(f"WARNING: Cleanup may be incomplete. Check config files manually.")
            finally:
                if old_sigint is not None:
                    try:
                        signal.signal(signal.SIGINT, old_sigint)
                    except (OSError, ValueError):
                        pass

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
