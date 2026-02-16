
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
        
        tester = NethVoiceProxyTester(logger, container_name=container)
        results = tester.run_full_test(
            registrar=registrar,
            sip_port=sip_port,
            trunk_number=target_trunk,
            auth_id=auth_id,
            auth_pass=auth_pass,
            destination_number=destination_number,
            trunk_name=trunk_name,
        )
        
        # Show FreePBX guide if registration was successful
        if results["registration"]:
            from agents.analysis import AnalysisAgent
            dummy_agent = AnalysisAgent(logger)
            print_freepbx_guide(registrar, sip_port, target_trunk, auth_id, trunk_name, dummy_agent, outbound_proxy_uri="")
        
        # Show log
        import glob, os
        list_of_files = glob.glob('logs/*.log')
        if list_of_files:
            latest_file = max(list_of_files, key=os.path.getctime)
            print(f"\n Full Debug Log: {os.path.abspath(latest_file)}")
        
        return
    
    # ── Direct SIP Mode (original flow) ──
    outbound_proxy_input = get_input("Outbound Proxy (e.g. sip:10.5.4.1:5060;lr) [leave empty for direct]")
    outbound_proxy = None
    outbound_proxy_port = 5060
    outbound_proxy_uri = ""
    if outbound_proxy_input.strip():
        raw = outbound_proxy_input.strip()
        outbound_proxy_uri = raw
        cleaned = raw.replace("sip:", "").split(";")[0]
        if ":" in cleaned:
            parts = cleaned.split(":")
            outbound_proxy = parts[0]
            try:
                outbound_proxy_port = int(parts[1])
            except:
                outbound_proxy_port = 5060
        else:
            outbound_proxy = cleaned
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
        # We can't easy distinguish direction in the listener callback alone without context in SIPTransport
        # But SIPTransport listeners only get INBOUND messages in current implementation
        snoop_agent.check_message(msg, "IN", addr)
        
    transport.add_listener(packet_sniffer)
    
    def packet_sniffer_out(msg, addr):
        snoop_agent.check_message(msg, "OUT", addr)
        
    transport.add_outbound_listener(packet_sniffer_out)
    
    transport.start()

    try:
        # 2. Registration Phase
        print("\n[STEP 2] Verifying Registration...")
        # Note: We pass original registrar as domain/URI, but we must config transport to use target_ip
        # Current RegistrationAgent splits registrar string. We should modify it to accept explicit target.
        # For now, let's just pass the resolved IP:PORT as "registrar" string to the agent and keep Domain in To/From?
        # Actually RegistrationAgent needs refactor to separate Domain from Target IP.
        
        # Let's pass the resolved address to transport send, but keep registrar domain for SIP headers.
        # We need to update RegistrationAgent signature or logic.
        # Quick Fix: Pass "registrar_domain" and "target_ip" separately.
        
        # Updating RegistrationAgent initiation:
        reg_agent = RegistrationAgent(target_trunk, auth_id, auth_pass, registrar, logger, transport, target_ip=target_ip, target_port=target_port)
        if reg_agent.register():
            print("✅ Registration Successful!")
            if using_proxy:
                print("   (through proxy - proxy forwards registration to provider)")
        else:
            print("❌ Registration Failed. Checking logs...")
            if using_proxy:
                print("\n   [PROXY DIAGNOSTIC]")
                print(f"   Registration failed through proxy {outbound_proxy}:{outbound_proxy_port}")
                print("   Possible causes:")
                print(f"   1. Proxy {outbound_proxy}:{outbound_proxy_port} not reachable")
                print(f"   2. Proxy not configured to forward to {registrar}")
                print("   3. Proxy blocking this domain/auth")
                print("   4. Try testing WITHOUT proxy to isolate the issue")

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

    # 3. Call Testing Phase
    # ... inputs for call testing ...

if __name__ == "__main__":
    main()
