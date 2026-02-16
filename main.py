
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

def print_freepbx_guide(registrar, sip_port, trunk_number, auth_id, trunk_name, analysis_agent):
    """Print a FreePBX Trunk configuration guide based on test results."""
    
    # Build codec priority list from detected codecs
    detected_codecs = analysis_agent.features.get("codecs", set())
    
    # Codec priority order (best quality -> most compatible)
    codec_priority = []
    codec_map = {
        "OPUS/48000/2": ("opus", "OPUS - HD Wideband"),
        "G722/16000": ("g722", "G.722 - HD Wideband"),
        "PCMA/8000": ("alaw", "G.711a (alaw) - Standard Quality"),
        "PCMU/8000": ("ulaw", "G.711u (ulaw) - Standard Quality"),
        "G729/8000": ("g729", "G.729 - Low Bandwidth"),
    }
    
    for codec_name, (short, label) in codec_map.items():
        for detected in detected_codecs:
            if codec_name in detected:
                codec_priority.append((short, label))
                break
    
    # If no codecs detected, suggest common defaults
    if not codec_priority:
        codec_priority = [
            ("alaw", "G.711a (alaw) - Standard Quality"),
            ("ulaw", "G.711u (ulaw) - Standard Quality"),
        ]

    # Feature-based recommendations
    has_dtmf = analysis_agent.features.get("rfc2833", False)
    has_srtp = analysis_agent.features.get("srtp", False)
    
    sep = "=" * 60
    line = "-" * 60
    
    print(f"\n{sep}")
    print("   FREEPBX TRUNK CONFIGURATION GUIDE")
    print(f"{sep}")
    
    print(f"\n--- General Settings {line[20:]}")
    print(f"  Trunk Name:           {trunk_name}")
    print(f"  Outbound CallerID:    {trunk_number}")
    print(f"  CID Options:          Force Trunk CID")
    
    print(f"\n--- SIP Settings (pjsip) {line[24:]}")
    print(f"  Username:             {auth_id}")
    print(f"  Secret:               ******* (your password)")
    print(f"  Authentication:       Outbound")
    print(f"  Registration:         Send")
    print(f"  SIP Server:           {registrar}")
    print(f"  SIP Server Port:      {sip_port}")
    print(f"  Transport:            UDP (0.0.0.0)")
    print(f"  Context:              from-trunk")
    
    print(f"\n--- Advanced Settings {line[21:]}")
    print(f"  From User:            {trunk_number}")
    print(f"  From Domain:          {registrar}")
    print(f"  Contact User:         {trunk_number}")
    print(f"  DTMF Mode:            {'RFC 4733 (RFC 2833)' if has_dtmf else 'Auto'}")
    print(f"  Media Encryption:     {'SRTP via in-SDP' if has_srtp else 'None (Disabled)'}")
    print(f"  Qualify Frequency:    60")
    print(f"  Match (Inbound):      {registrar}")
    
    print(f"\n--- Codec Priority {line[18:]}")
    for i, (short, label) in enumerate(codec_priority, 1):
        print(f"  {i}. {short:12s}  ->  {label}")
    if has_dtmf:
        print(f"  (telephone-event is auto-negotiated for DTMF)")
    
    print(f"\n--- Outbound Route {line[18:]}")
    print(f"  Route Name:           Out-{trunk_name}")
    print(f"  Trunk:                {trunk_name}")
    print(f"  Dial Patterns:        Match your local dialing plan")
    print(f"                        e.g. 0|XXXXXXX for local")
    print(f"                             00|. for international")
    
    print(f"\n--- Inbound Route {line[17:]}")
    print(f"  DID Number:           {trunk_number}")
    print(f"  Trunk:                {trunk_name}")
    print(f"  Destination:          (your IVR, Ring Group, Extension, etc.)")
    
    print(f"\n--- NAT Tips {line[12:]}")
    print(f"  - Asterisk SIP Settings > NAT:  Yes (force_rport, comedia)")
    print(f"  - If behind firewall, forward UDP {sip_port} + RTP range (10000-20000)")
    print(f"  - Set External IP and Local Networks in Asterisk SIP Settings")
    
    print(f"\n{sep}\n")


def main():
    print_banner()
    
    # 1. Input Phase
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
        else:
            print("❌ Registration Failed. Checking logs...")
            # We might still proceed to call testing if user wants, but typically reg failure stops us
            # sys.exit(1) 

        # 3. Inbound Call Test
        print("\n[STEP 3] Inbound Call Test")
        if ask_yes_no("Do you want to simulate an INBOUND call? (Make a call to the Trunk now) [y/N]"):
            print("Listening for incoming calls (60s timeout)...")
            inbound_agent = InboundCallAgent(logger, transport)
            # Pass reg_agent to keep NAT open
            if inbound_agent.wait_for_call(timeout=60, keepalive_agent=reg_agent):
                print("✅ Inbound Call Detected and Answered!")
            else:
                print("❌ No call detected within timeout.")

        # 4. Outbound Call Test
        if destination_number:
            print("\n[STEP 4] Outbound Call Test")
            if ask_yes_no(f"Do you want to CALL {destination_number}? [y/N]"):
                print(f"Calling {destination_number}...")
                outbound_agent = OutboundCallAgent(target_trunk, auth_id, auth_pass, registrar, destination_number, logger, transport, target_ip=target_ip, target_port=target_port)
                if outbound_agent.make_call():
                     print("✅ Outbound Call Successful!")
                else:
                     print("❌ Outbound Call Failed.")
        
        # 5. Report
        snoop_agent.print_report()
        
        # 6. FreePBX Configuration Guide
        print_freepbx_guide(registrar, sip_port, target_trunk, auth_id, trunk_name, snoop_agent)
        
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
