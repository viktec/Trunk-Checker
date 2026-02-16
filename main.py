
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

def main():
    print_banner()
    
    # 1. Input Phase
    print("\n[STEP 1] Configuration")
    target_trunk = get_input("Main Trunk Number (e.g. +123456789)")
    auth_id = get_input("Authentication ID / Username")
    auth_pass = get_input("Authentication Password", hidden=True)
    registrar = get_input("SIP Registrar Address (IP:Port or Domain)")
    destination_number = get_input("Destination Number for Outbound Test (optional)")
    
    logger = setup_logger()
    logger.info(f"Starting diagnosis for Trunk: {target_trunk} @ {registrar}")

    # 1.5 DNS Resolution
    print("\n[STEP 1.5] DNS Resolution")
    from agents.dns_agent import DNSAgent
    dns_agent = DNSAgent(logger)
    targets = dns_agent.resolve(registrar, "UDP") # Default to UDP for now
    
    if not targets:
        print("❌ DNS Resolution Failed. Cannot proceed.")
        sys.exit(1)
        
    print(f"✅ DNS Resolved: {len(targets)} targets found.")
    for t in targets:
         print(f"   -> Priority/Order: n/a, Target: {t[0]}, Port: {t[1]}, Transport: {t[2]}")
         
    # Pick first target
    target_ip = targets[0][0]
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
        do_inbound = get_input("Do you want to simulate an INBOUND call? (Make a call to the Trunk now) [y/N]")
        if do_inbound.lower() == 'y':
            print("Listening for incoming calls (60s timeout)...")
            inbound_agent = InboundCallAgent(logger, transport)
            if inbound_agent.wait_for_call(timeout=60):
                print("✅ Inbound Call Detected and Answered!")
            else:
                print("❌ No call detected within timeout.")

        # 4. Outbound Call Test
        if destination_number:
            print("\n[STEP 4] Outbound Call Test")
            do_outbound = get_input(f"Do you want to CALL {destination_number}? [y/N]")
            if do_outbound.lower() == 'y':
                print(f"Calling {destination_number}...")
                outbound_agent = OutboundCallAgent(target_trunk, auth_id, auth_pass, registrar, destination_number, logger, transport, target_ip=target_ip, target_port=target_port)
                if outbound_agent.make_call():
                     print("✅ Outbound Call Successful!")
                else:
                     print("❌ Outbound Call Failed.")
        
        # 5. Report
        snoop_agent.print_report()

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
