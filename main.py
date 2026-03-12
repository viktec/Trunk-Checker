
import sys
import getpass
from agents.registration import RegistrationAgent
from agents.inbound import InboundCallAgent
from agents.outbound import OutboundCallAgent
from utils.logger import setup_logger
from core.sip_transport import SIPTransport

def print_banner():
    print("=" * 60)
    print("   SIP TRUNK CHECKER - Interactive Diagnostic Tool")
    print("=" * 60)

def get_input(prompt, hidden=False):
    if hidden:
        return getpass.getpass(f"{prompt}: ")
    return input(f"{prompt}: ")

def ask_yes_no(prompt, default='n'):
    """Ask a yes/no question. Accepts y/yes/n/no (case insensitive). Re-asks on invalid input."""
    while True:
        answer = input(f"{prompt}: ").strip().lower()
        if answer in ('y', 'yes', 'si', 's'):
            return True
        if answer in ('n', 'no', ''):
            return False
        print("  Please answer y/yes or n/no.")

def print_freepbx_guide(registrar, sip_port, trunk_number, auth_id, trunk_name, analysis_agent, outbound_proxy_uri=""):
    """Print a complete FreePBX Trunk configuration guide based on test results."""
    
    # Build codec priority list from detected codecs
    detected_codecs = analysis_agent.features.get("codecs", set())
    
    codec_priority = []
    codec_map = {
        "OPUS/48000/2": ("opus", "OPUS - HD Wideband"),
        "G722/16000": ("g722", "G.722 - HD Wideband"),
        "PCMA/8000": ("alaw", "G.711a (alaw) - Standard"),
        "PCMU/8000": ("ulaw", "G.711u (ulaw) - Standard"),
        "G729/8000": ("g729", "G.729 - Low Bandwidth"),
    }
    
    for codec_name, (short, label) in codec_map.items():
        for detected in detected_codecs:
            if codec_name in detected:
                codec_priority.append((short, label))
                break
    
    if not codec_priority:
        codec_priority = [
            ("alaw", "G.711a (alaw) - Standard"),
            ("ulaw", "G.711u (ulaw) - Standard"),
        ]

    has_dtmf = analysis_agent.features.get("rfc2833", False)
    has_srtp = analysis_agent.features.get("srtp", False)
    has_pai = analysis_agent.features.get("p_identity", False)
    
    sep = "=" * 60
    
    print(f"\n{sep}")
    print("   FREEPBX TRUNK CONFIGURATION GUIDE")
    print(f"{sep}")
    
    # ── TAB: General ──
    print(f"\n{'='*20} TAB: General {'='*26}")
    print(f"  Trunk Name:                  {trunk_name}")
    print(f"  Hide CallerID:               No")
    print(f"  Outbound CallerID:           {trunk_number}")
    print(f"  CID Options:                 Force Trunk CID")
    print(f"  Maximum Channels:            (vuoto - nessun limite)")
    print(f"  Asterisk Trunk Dial Options: System")
    print(f"  Continue if Busy:            No")
    print(f"  Disable Trunk:               No")
    print(f"  Monitor Trunk Failures:      No")
    
    # ── TAB: pjsip Settings > General ──
    print(f"\n{'='*20} TAB: pjsip > General {'='*19}")
    print(f"  Username:                    {auth_id}")
    print(f"  Auth Username:               {auth_id}")
    print(f"  Secret:                      ******* (la tua password)")
    print(f"  Authentication:              Outbound")
    print(f"  Registration:                Send")
    print(f"  Language Code:               Default")
    print(f"  SIP Server:                  {registrar}")
    print(f"  SIP Server Port:             {sip_port}")
    print(f"  Context:                     from-pstn-toheader")
    print(f"  Transport:                   0.0.0.0-udp")
    
    # ── TAB: pjsip Settings > Advanced ──
    print(f"\n{'='*20} TAB: pjsip > Advanced {'='*18}")
    print(f"  DTMF Mode:                   {'RFC 4733' if has_dtmf else 'Auto'}")
    print(f"  Send Line in Registration:   Yes")
    print(f"  Send Connected Line:         No")
    print(f"  Permanent Auth Rejection:    No")
    print(f"  Forbidden Retry Interval:    10")
    print(f"  Fatal Retry Interval:        0")
    print(f"  General Retry Interval:      60")
    print(f"  Expiration:                  300")
    print(f"  Max Retries:                 10000")
    print(f"  Qualify Frequency:           60")
    proxy_display = outbound_proxy_uri if outbound_proxy_uri else "(vuoto)"
    print(f"  Outbound Proxy:              {proxy_display}")
    print(f"  Disable TOPOS proxy header:  No")
    print(f"  Disable SRTP proxy header:   {'No' if has_srtp else 'Yes'}")
    print(f"  User = Phone:                No")
    print(f"  Contact User:                {auth_id}")
    print(f"  From Domain:                 {registrar}")
    print(f"  From User:                   {auth_id}")
    print(f"  Client URI:                  (vuoto)")
    print(f"  Server URI:                  (vuoto)")
    print(f"  Media Address:               (vuoto)")
    print(f"  AOR:                         (vuoto)")
    print(f"  AOR Contact:                 (vuoto)")
    print(f"  Match (Permit):              (vuoto)")
    print(f"  Support Path:                No")
    print(f"  Support T.38 UDPTL:          No")
    print(f"  T.38 UDPTL Error Correction: None")
    print(f"  T.38 UDPTL NAT:              No")
    print(f"  T.38 UDPTL MAXDATAGRAM:      (vuoto)")
    print(f"  Fax Detect:                  No")
    print(f"  Trust RPID/PAI:              {'Yes' if has_pai else 'No'}")
    send_rpid = "Send P-Asserted-Identity header" if has_pai else "No"
    print(f"  Send RPID/PAI:               {send_rpid}")
    print(f"  Send Private CallerID Info:  No")
    print(f"  Match Inbound Auth:          Default")
    print(f"  Inband Progress:             No")
    
    # ── TAB: Codecs ──
    print(f"\n{'='*20} TAB: Codecs {'='*27}")
    for i, (short, label) in enumerate(codec_priority, 1):
        print(f"  {i}. {short:12s}  ->  {label}")
    if has_dtmf:
        print(f"  (telephone-event auto-negotiated for DTMF)")
    
    # ── Outbound Route ──
    print(f"\n{'='*20} Outbound Route {'='*24}")
    print(f"  Route Name:                  Out-{trunk_name}")
    print(f"  Trunk:                       {trunk_name}")
    print(f"  Dial Patterns:               Segui il tuo piano di numerazione")
    print(f"                               es. 0|XXXXXXX per locali")
    print(f"                                   00|. per internazionali")
    
    # ── Inbound Route ──
    print(f"\n{'='*20} Inbound Route {'='*25}")
    print(f"  DID Number:                  {trunk_number}")
    print(f"  Trunk:                       {trunk_name}")
    print(f"  Destination:                 (IVR, Ring Group, Interno...)")
    
    print(f"\n{sep}\n")


def main():
    print_banner()
    
    # Mode selection
    print("\n[TEST MODE]")
    print("  1. Direct SIP Test (connect directly to provider)")
    print("  2. NethVoice Proxy Test (test through Kamailio proxy)")
    mode = get_input("Select mode [1/2, default: 1]")
    mode = mode.strip() if mode.strip() else "1"
    
    # Common inputs
    print("\n[STEP 1] Configuration")
    registrar = get_input("SIP Registrar Address (Domain or IP)")
    sip_port_input = get_input("SIP Port [default: 5060]")
    sip_port = int(sip_port_input) if sip_port_input.strip() else 5060
    target_trunk = get_input("Main Trunk Number (e.g. +123456789)")
    auth_id = get_input("Authentication ID / Username")
    auth_pass = get_input("Authentication Password", hidden=True)
    destination_number = get_input("Destination Number for Outbound Test (optional)")
    trunk_name_input = get_input("Trunk Name for FreePBX [default: auto]")
    trunk_name = trunk_name_input.strip() if trunk_name_input.strip() else f"Trunk-{registrar.replace('.', '-')}"
    
    # ── NethVoice Proxy Mode ──
    if mode == "2":
        from agents.nethvoice_proxy import NethVoiceProxyTester
        logger = setup_logger()
        logger.info(f"NethVoice Proxy Test for Trunk: {target_trunk} @ {registrar}")
        
        container = get_input("FreePBX container name [default: freepbx]")
        container = container.strip() if container.strip() else "freepbx"
        
        # Advanced SIP fields (Enter = use default)
        print("\n[STEP 2] Advanced SIP Settings (press Enter to keep default)")
        
        from_domain_input = get_input(f"  From Domain [default: {registrar}]")
        from_domain = from_domain_input.strip() if from_domain_input.strip() else None
        
        default_server_uri = f"sip:{registrar}:{sip_port}"
        server_uri_input = get_input(f"  Server URI [default: {default_server_uri}]")
        server_uri = server_uri_input.strip() if server_uri_input.strip() else None
        
        default_client_uri = f"sip:{auth_id}@{registrar}:{sip_port}"
        client_uri_input = get_input(f"  Client URI [default: {default_client_uri}]")
        client_uri = client_uri_input.strip() if client_uri_input.strip() else None
        
        tester = NethVoiceProxyTester(logger, container_name=container)
        results = tester.run_full_test(
            registrar=registrar,
            sip_port=sip_port,
            trunk_number=target_trunk,
            auth_id=auth_id,
            auth_pass=auth_pass,
            destination_number=destination_number,
            trunk_name=trunk_name,
            from_domain=from_domain,
            client_uri=client_uri,
            server_uri=server_uri,
        )
        
        # Show FreePBX guide if registration was successful
        if results["registration"]:
            from agents.analysis import AnalysisAgent
            dummy_agent = AnalysisAgent(logger)
            proxy_uri = results.get("outbound_proxy", "")
            print_freepbx_guide(registrar, sip_port, target_trunk, auth_id, trunk_name, dummy_agent, outbound_proxy_uri=proxy_uri)
        
        # Show log
        import glob, os
        list_of_files = glob.glob('logs/*.log')
        if list_of_files:
            latest_file = max(list_of_files, key=os.path.getctime)
            print(f"\n Full Debug Log: {os.path.abspath(latest_file)}")
        
        return
    
    # ── Direct SIP Mode (original flow) ──
    def _parse_proxy_string(raw):
        """Parse outbound proxy string into (host, port, uri) tuple."""
        uri = raw
        cleaned = raw.replace("sip:", "").split(";")[0]
        if ":" in cleaned:
            parts = cleaned.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
            except:
                port = 5060
        else:
            host = cleaned
            port = 5060
        return host, port, uri

    outbound_proxy_input = get_input("Outbound Proxy (e.g. sip:10.5.4.1:5060;lr) [leave empty for direct]")
    outbound_proxy = None
    outbound_proxy_port = 5060
    outbound_proxy_uri = ""
    if outbound_proxy_input.strip():
        outbound_proxy, outbound_proxy_port, outbound_proxy_uri = _parse_proxy_string(outbound_proxy_input.strip())
        print(f"  -> Proxy parsed: {outbound_proxy}:{outbound_proxy_port}")
    else:
        # No proxy specified — ask if intentional
        if ask_yes_no("No outbound proxy specified. Do you want to specify one? [y/N]"):
            manual = get_input("  Outbound Proxy (e.g. sip:10.5.4.1:5060;lr)")
            if manual.strip():
                outbound_proxy, outbound_proxy_port, outbound_proxy_uri = _parse_proxy_string(manual.strip())
                print(f"  -> Proxy parsed: {outbound_proxy}:{outbound_proxy_port}")
    
    
    logger = setup_logger()
    logger.info(f"Starting diagnosis for Trunk: {target_trunk} @ {registrar}")

    # 1.5 DNS Resolution
    print("\n[STEP 1.5] DNS Resolution")
    from agents.dns_agent import DNSAgent
    dns_agent = DNSAgent(logger)
    targets = dns_agent.resolve(registrar, "UDP") # Default to UDP for now
    
    target_ip = None
    target_port = sip_port  # Use the user-specified port
    
    if not targets:
        print("❌ DNS Resolution Failed (No SRV/A records).")
        print("⚠️ Attempting to proceed with raw input as Host...")
        target_ip = registrar
    else:
        print(f"✅ DNS Resolved: {len(targets)} targets found.")
        for t in targets:
             print(f"   -> Priority/Order: n/a, Target: {t[0]}, Port: {t[1]}, Transport: {t[2]}")
        # Pick first target
        target_ip = targets[0][0]
        # Only use DNS port if user left default
        if sip_port == 5060 and targets[0][1] != 5060:
            target_port = targets[0][1]
    
    # If Outbound Proxy is set, route ALL traffic through it
    using_proxy = False
    if outbound_proxy:
        using_proxy = True
        print(f"\n[PROXY MODE] Routing SIP traffic through proxy: {outbound_proxy}:{outbound_proxy_port}")
        target_ip = outbound_proxy
        target_port = outbound_proxy_port
    
    # Shared Transport
    transport = SIPTransport(bind_port=5060, logger=logger)
    
    # Analysis Agent (Listener)
    from agents.analysis import AnalysisAgent
    snoop_agent = AnalysisAgent(logger)
    
    # Wrap listener to capture direction
    def packet_sniffer(msg, addr):
        snoop_agent.check_message(msg, "IN", addr)
        
    transport.add_listener(packet_sniffer)
    
    def packet_sniffer_out(msg, addr):
        snoop_agent.check_message(msg, "OUT", addr)
        
    transport.add_outbound_listener(packet_sniffer_out)
    
    transport.start()

    try:
        # ── Registration Phase with Retry Loop ──
        print("\n[STEP 2] Verifying Registration...")
        registration_ok = False
        max_retries = 10
        attempt = 0
        reg_agent = None

        while attempt < max_retries:
            attempt += 1

            if attempt > 1:
                print(f"\n[RETRY {attempt}] Attempting registration...")

            reg_agent = RegistrationAgent(target_trunk, auth_id, auth_pass, registrar, logger, transport, target_ip=target_ip, target_port=target_port)
            
            if reg_agent.register():
                print("✅ Registration Successful!")
                if using_proxy:
                    print("   (through proxy - proxy forwards registration to provider)")
                registration_ok = True
                break
            
            # ── Registration Failed ──
            print("❌ Registration Failed.")
            
            # Show error details from the last response
            if reg_agent.last_response:
                resp = reg_agent.last_response
                error_code = resp.status_code
                error_reason = resp.reason_phrase
                print(f"\n   [PROVIDER ERROR] {error_code} {error_reason}")
                
                # Dump ALL headers from the provider response
                print(f"\n   [FULL SIP RESPONSE HEADERS]")
                for hdr_name, hdr_value in resp.headers.items():
                    print(f"     {hdr_name}: {hdr_value}")
                if resp.body:
                    print(f"     [Body]: {resp.body[:200]}")
                
                # Actionable diagnostics per error code
                print(f"\n   ┌──────────────────────────────────────────────────┐")
                print(f"   │          DIAGNOSTICA REGISTRAZIONE                │")
                print(f"   └──────────────────────────────────────────────────┘")
                
                if error_code == 403:
                    print(f"\n   Il provider ha risposto con 403 Forbidden.")
                    print(f"   Il provider ha RIFIUTATO le credenziali.\n")
                    print(f"   Cause più comuni (in ordine di probabilità):")
                    print(f"   ──────────────────────────────────────────────")
                    print(f"   1. PASSWORD ERRATA")
                    print(f"      → Verifica la password con il provider")
                    print(f"   2. AUTH ID / USERNAME ERRATO")
                    print(f"      → Attuale: '{auth_id}'")
                    print(f"      → Alcuni provider usano il numero intero come auth_id")
                    print(f"      → Altri usano un username alfanumerico separato")
                    print(f"   3. IP NON AUTORIZZATO dal provider")
                    if using_proxy:
                        print(f"      → Il provider deve autorizzare l'IP del proxy")
                    else:
                        print(f"      → Il provider deve autorizzare l'IP pubblico del server")
                    print(f"      → Contatta il provider per verificare la whitelist IP")
                    
                    # Check the realm in WWW-Authenticate
                    www_auth = resp.get_header("WWW-Authenticate")
                    if www_auth:
                        import re
                        realm_match = re.search(r'realm="([^"]+)"', www_auth)
                        if realm_match:
                            realm = realm_match.group(1)
                            print(f"   4. REALM del provider: '{realm}'")
                            if realm != registrar:
                                print(f"      ⚠️ Il realm NON corrisponde al registrar ({registrar})")
                                print(f"      → Prova a usare '{realm}' come From Domain")
                
                elif error_code == 401:
                    print(f"\n   Il provider ha risposto con 401 Unauthorized.")
                    print(f"   L'autenticazione digest è fallita dopo il challenge.\n")
                    print(f"   1. Verifica username e password")
                    print(f"   2. Controlla il realm nella risposta (sopra)")
                    print(f"   3. Potrebbe esserci un mismatch nel calcolo dell'hash digest")
                
                elif error_code == 404:
                    print(f"\n   Il provider ha risposto con 404 Not Found.\n")
                    print(f"   1. Registrar errato: '{registrar}' potrebbe non essere corretto")
                    print(f"   2. Username non esiste presso il provider")
                
                elif error_code == 407:
                    print(f"\n   Il provider richiede Proxy Authentication (407).\n")
                    print(f"   1. Serve un outbound proxy per questo provider")
                    print(f"   2. Il proxy richiede credenziali separate")
                
                else:
                    print(f"\n   Errore {error_code}: {error_reason}")
                    print(f"   Controlla i dettagli negli header sopra.")
            
            else:
                print("\n   [ERROR] No response from registrar (timeout)")
                print(f"\n   ┌──────────────────────────────────────────────────┐")
                print(f"   │            DIAGNOSTICA TIMEOUT                    │")
                print(f"   └──────────────────────────────────────────────────┘")
                print(f"   Nessuna risposta ricevuta dal provider.\n")
                print(f"   1. REGISTRAR NON RAGGIUNGIBILE")
                print(f"      → Verifica che '{registrar}' sia risolvibile via DNS")
                print(f"   2. FIREWALL BLOCCA IL TRAFFICO SIP")
                print(f"      → Porta UDP {sip_port} deve essere aperta in uscita")
                print(f"   3. PORTA SIP SBAGLIATA")
                print(f"      → Prova con porta 5061 (TLS) o altre porte del provider")
                if using_proxy:
                    print(f"   4. PROXY NON RAGGIUNGE IL PROVIDER")
                    print(f"      → Testa connettività dal proxy verso {registrar}:{sip_port}")
            
            if using_proxy:
                print(f"\n   [PROXY DIAGNOSTIC]")
                print(f"   Registration failed through proxy {outbound_proxy}:{outbound_proxy_port}")
                print("   Possible causes:")
                print(f"   1. Proxy {outbound_proxy}:{outbound_proxy_port} not reachable")
                print(f"   2. Proxy not configured to forward to {registrar}")
                print("   3. Proxy blocking this domain/auth")
                print("   4. Try testing WITHOUT proxy to isolate the issue")

            # Show current config
            print("\n   Current configuration:")
            print(f"     Registrar:       {registrar}")
            print(f"     SIP Port:        {sip_port}")
            print(f"     Auth ID:         {auth_id}")
            print(f"     Trunk Number:    {target_trunk}")
            print(f"     Outbound Proxy:  {outbound_proxy_uri or '(none)'}")

            if not ask_yes_no("\n   Do you want to modify the data and retry? [y/N]"):
                print("   Registration test aborted by user.")
                break

            # ── User wants to retry: ask for new values ──
            print("\n   [MODIFY DATA] Press Enter to keep the current value:")
            
            new_registrar = get_input(f"     Registrar [{registrar}]")
            if new_registrar.strip():
                registrar = new_registrar.strip()

            new_port = get_input(f"     SIP Port [{sip_port}]")
            if new_port.strip():
                try:
                    sip_port = int(new_port.strip())
                except ValueError:
                    print("     Invalid port, keeping current value.")

            new_auth_id = get_input(f"     Auth ID [{auth_id}]")
            if new_auth_id.strip():
                auth_id = new_auth_id.strip()

            new_pass = get_input("     Password [****]", hidden=True)
            if new_pass.strip():
                auth_pass = new_pass.strip()

            new_proxy = get_input(f"     Outbound Proxy [{outbound_proxy_uri or '(none)'}]")
            if new_proxy.strip():
                outbound_proxy, outbound_proxy_port, outbound_proxy_uri = _parse_proxy_string(new_proxy.strip())
                using_proxy = True
                target_ip = outbound_proxy
                target_port = outbound_proxy_port
            elif new_proxy == "":
                # User pressed Enter — keep current
                pass

            # Re-resolve DNS if registrar changed
            if new_registrar.strip():
                targets = dns_agent.resolve(registrar, "UDP")
                if targets:
                    target_ip = targets[0][0]
                    if sip_port == 5060 and targets[0][1] != 5060:
                        target_port = targets[0][1]
                else:
                    target_ip = registrar
                
                if using_proxy:
                    target_ip = outbound_proxy
                    target_port = outbound_proxy_port

            print(f"\n   Retrying with updated configuration...")

        # ── Only proceed with tests if registration succeeded ──
        if not registration_ok:
            print("\n⚠️  Registration not successful — skipping call tests.")
            snoop_agent.print_report()
            print_freepbx_guide(registrar, sip_port, target_trunk, auth_id, trunk_name, snoop_agent, outbound_proxy_uri)
        else:
            # 3. Inbound Call Test
            print("\n[STEP 3] Inbound Call Test")
            if ask_yes_no("Do you want to simulate an INBOUND call? (Make a call to the Trunk now) [y/N]"):
                print("Listening for incoming calls (60s timeout)...")
                inbound_agent = InboundCallAgent(logger, transport)
                # Pass reg_agent to keep NAT open
                if inbound_agent.wait_for_call(timeout=60, keepalive_agent=reg_agent):
                    print("✅ Inbound Call Detected and Answered!")
                    if using_proxy:
                        print("   (call arrived through proxy - proxy routes inbound correctly)")
                else:
                    print("❌ No call detected within timeout.")
                    if using_proxy:
                        print("\n   [PROXY DIAGNOSTIC]")
                        print("   No inbound call detected through the proxy. Possible causes:")
                        print(f"   1. Proxy not forwarding inbound calls from {registrar}")
                        print("   2. Proxy NAT/routing misconfigured for this trunk")
                        print("   3. Provider not routing calls to proxy IP")
                        print("   4. Try testing WITHOUT proxy to isolate the issue")

            # 4. Outbound Call Test
            if destination_number:
                print("\n[STEP 4] Outbound Call Test")
                if ask_yes_no(f"Do you want to CALL {destination_number}? [y/N]"):
                    print(f"Calling {destination_number}...")
                    outbound_agent = OutboundCallAgent(target_trunk, auth_id, auth_pass, registrar, destination_number, logger, transport, target_ip=target_ip, target_port=target_port)
                    if outbound_agent.make_call():
                         print("✅ Outbound Call Successful!")
                         if using_proxy:
                             print("   (call routed through proxy - proxy handles outbound correctly)")
                    else:
                         print("❌ Outbound Call Failed.")
                         if using_proxy:
                             print("\n   [PROXY DIAGNOSTIC]")
                             print("   Outbound call failed through the proxy. Possible causes:")
                             print(f"   1. Proxy not forwarding INVITE to {registrar}")
                             print("   2. Codec mismatch between proxy and provider")
                             print("   3. Proxy blocking outbound by ACL/permissions")
                             print("   4. Try testing WITHOUT proxy to isolate the issue")
            
            # 5. Report
            snoop_agent.print_report()
            
            # 6. FreePBX Configuration Guide
            print_freepbx_guide(registrar, sip_port, target_trunk, auth_id, trunk_name, snoop_agent, outbound_proxy_uri)
        
        # Show log location
        import glob
        import os
        list_of_files = glob.glob('logs/*.log') 
        if list_of_files:
            latest_file = max(list_of_files, key=os.path.getctime)
            print(f"\n📄 Full Debug Log saved to: {os.path.abspath(latest_file)}")

    except KeyboardInterrupt:
        print("\nAborted by user.")
    except Exception as e:
        logger.exception("An error occurred")
        print(f"\nExample error: {e}")
    finally:
        transport.stop()

if __name__ == "__main__":
    main()
