import time
import hashlib
from core.sip_message import SIPMessage

class OutboundCallAgent:
    def __init__(self, trunk_number, auth_id, auth_pass, registrar_domain, dest_number, logger, transport, target_ip=None, target_port=5060):
        self.trunk_number = trunk_number
        self.auth_id = auth_id
        self.auth_pass = auth_pass
        self.registrar = registrar_domain
        self.dest_number = dest_number
        self.logger = logger
        self.transport = transport
        
        if target_ip:
            self.reg_ip = target_ip
            self.reg_port = target_port
        else:
            if ":" in registrar_domain:
                self.reg_ip, self.reg_port = registrar_domain.split(":")
            else:
                self.reg_ip = registrar_domain
                self.reg_port = 5060

        self.transport.add_listener(self._handle_response)
        
        self.call_state = "IDLE"
        self.call_id = SIPMessage.generate_nonce(16)
        self.cseq = 1
        self.last_response = None
        self.local_tag = SIPMessage.generate_nonce(8)
        self.to_tag = None

        # Hack for local IP
        self.local_ip = "127.0.0.1" 
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
        except:
            pass

    def _handle_response(self, msg, addr):
        if msg.get_header("Call-ID") == self.call_id:
            self.last_response = msg
            if msg.status_code and msg.status_code >= 100:
                self.logger.info(f"Outbound Call Status: {msg.status_code} {msg.reason_phrase}")

    def make_call(self):
        # 1. Initial INVITE
        contact = f"{self.local_ip}:{self.transport.bind_port}"
        to_uri = f"sip:{self.dest_number}@{self.registrar}"
        from_uri = f"sip:{self.trunk_number}@{self.registrar}"
        sdp = f"v=0\r\no=- 123456 123456 IN IP4 {self.local_ip}\r\ns=TrunkChecker\r\nc=IN IP4 {self.local_ip}\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000"

        msg = self._build_invite(to_uri, from_uri, contact, sdp)
        self._send(msg)

        # Wait for 401/407 or 1xx
        resp = self._wait_for_response()
        if not resp:
             self.logger.error("Timeout on initial INVITE")
             return False

        if resp.status_code in [401, 407]:
            # Authenticate
            self.logger.info("Authenticating Outbound Call...")
            # We must send ACK to the 401
            ack = self._build_ack(resp)
            self._send(ack)

            self.cseq += 1
            auth_header = resp.get_header("WWW-Authenticate") or resp.get_header("Proxy-Authenticate")
            realm = self._extract_param(auth_header, "realm")
            nonce = self._extract_param(auth_header, "nonce")
            opaque = self._extract_param(auth_header, "opaque")

            msg = self._build_invite(to_uri, from_uri, contact, sdp)
            
            response_hash = self._calc_digest("INVITE", f"sip:{self.dest_number}@{self.registrar}", realm, nonce)
            auth_val = f'Digest username="{self.auth_id}", realm="{realm}", nonce="{nonce}", uri="sip:{self.dest_number}@{self.registrar}", response="{response_hash}", algorithm=MD5'
            if opaque:
                auth_val += f', opaque="{opaque}"'
            msg.add_header("Authorization", auth_val)
            
            self.last_response = None
            self._send(msg)
            
            resp = self._wait_for_response()

        # Handle Progress
        while resp and resp.status_code < 200:
            self.logger.info(f"Progress: {resp.status_code}")
            resp = self._wait_for_response(timeout=10) # Wait longer for ringing
        
        if resp and resp.status_code == 200:
            self.logger.info("Call Answered!")
            self.to_tag = self._extract_tag(resp.get_header("To"))
            
            # Send ACK
            ack = self._build_ack(resp)
            self._send(ack)
            
            # Start RTP? (Simulated)
            time.sleep(5)
            
            # Send BYE
            bye = self._build_bye(to_uri, from_uri)
            self._send(bye)
            return True
        else:
            code = resp.status_code if resp else "Timeout"
            self.logger.error(f"Call failed. Final status: {code}")
            return False

    def _send(self, msg):
        self.transport.send(msg, self.reg_ip, self.reg_port)

    def _build_invite(self, to_uri, from_uri, contact, sdp):
        msg = SIPMessage("INVITE", to_uri)
        msg.add_header("Via", f"SIP/2.0/UDP {contact};branch=z9hG4bK{SIPMessage.generate_nonce()}")
        msg.add_header("Max-Forwards", "70")
        msg.add_header("To", to_uri)
        msg.add_header("From", f"{from_uri};tag={self.local_tag}")
        msg.add_header("Call-ID", self.call_id)
        msg.add_header("CSeq", f"{self.cseq} INVITE")
        msg.add_header("Contact", f"<sip:{contact}>")
        msg.add_header("Content-Type", "application/sdp")
        msg.add_header("User-Agent", "TrunkChecker/1.0")
        msg.body = sdp
        return msg

    def _build_ack(self, resp):
        ack = SIPMessage("ACK", resp.get_header("To").split(";", 1)[0].replace("<", "").replace(">", "").strip()) # Request URI is the To URI usually
        # But actually ACK URI matches Request-URI of INVITE.
        # Simplification: Use the To URI from response
        ack_uri = f"sip:{self.dest_number}@{self.registrar}"
        ack.uri = ack_uri
        
        ack.add_header("Via", resp.get_header("Via"))
        ack.add_header("Max-Forwards", "70")
        ack.add_header("To", resp.get_header("To")) # Include tag
        ack.add_header("From", resp.get_header("From"))
        ack.add_header("Call-ID", resp.get_header("Call-ID"))
        ack.add_header("CSeq", f"{self.cseq} ACK")
        return ack

    def _build_bye(self, to_uri, from_uri):
        self.cseq += 1
        msg = SIPMessage("BYE", to_uri)
        msg.add_header("Via", f"SIP/2.0/UDP {self.local_ip}:5060;branch=z9hG4bK{SIPMessage.generate_nonce()}")
        msg.add_header("Max-Forwards", "70")
        msg.add_header("To", f"{to_uri};tag={self.to_tag}")
        msg.add_header("From", f"{from_uri};tag={self.local_tag}")
        msg.add_header("Call-ID", self.call_id)
        msg.add_header("CSeq", f"{self.cseq} BYE")
        return msg

    def _wait_for_response(self, timeout=5):
        start = time.time()
        while time.time() - start < timeout:
            if self.last_response:
                res = self.last_response
                if res.status_code >= 100: # Dont clear if it's 100/180, we might get more
                    if res.status_code >= 200:
                         self.last_response = None
                    return res
            time.sleep(0.1)
        return None

    def _extract_param(self, header, key):
        import re
        match = re.search(f'{key}="([^"]+)"', header)
        if match:
            return match.group(1)
        match = re.search(f'{key}=([^, ]+)', header)
        return match.group(1) if match else None

    def _extract_tag(self, header):
        if "tag=" in header:
            return header.split("tag=")[1].split(";")[0]
        return None

    def _calc_digest(self, method, uri, realm, nonce):
        ha1_str = f"{self.auth_id}:{realm}:{self.auth_pass}"
        ha1 = hashlib.md5(ha1_str.encode()).hexdigest()
        ha2_str = f"{method}:{uri}"
        ha2 = hashlib.md5(ha2_str.encode()).hexdigest()
        resp_str = f"{ha1}:{nonce}:{ha2}"
        return hashlib.md5(resp_str.encode()).hexdigest()
