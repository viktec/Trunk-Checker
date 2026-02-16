import time
import hashlib
import socket
from core.sip_message import SIPMessage
from core.sip_transport import SIPTransport

class RegistrationAgent:
    def __init__(self, trunk_number, auth_id, auth_pass, registrar_domain, logger, transport=None, target_ip=None, target_port=5060):
        self.trunk_number = trunk_number
        self.auth_id = auth_id
        self.auth_pass = auth_pass
        self.registrar = registrar_domain # This is the Domain for From/To headers
        self.logger = logger
        
        # Target for sending packets
        if target_ip:
            self.reg_ip = target_ip
            self.reg_port = target_port
        else:
             # Legacy fallback
            if ":" in registrar_domain:
                self.reg_ip, self.reg_port = registrar_domain.split(":")
            else:
                self.reg_ip = registrar_domain
                self.reg_port = 5060

        if transport:
            self.transport = transport
        else:
            self.transport = SIPTransport(bind_port=5060, logger=logger) # Fixed local port for now
            
        self.transport.add_listener(self._handle_response)
        
        self.registered = False
        self.last_response = None
        self.cseq = 1
        self.call_id = SIPMessage.generate_nonce(16)
        
        # Determine local IP (quick hack)
        self.local_ip = "127.0.0.1" 
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
        except:
            pass

    def _handle_response(self, msg, addr):
        # Filter for this registration transaction
        cseq_header = msg.get_header("CSeq")
        if cseq_header and str(self.cseq) in cseq_header and "REGISTER" in cseq_header:
            self.last_response = msg

    def register(self):
        self.transport.start()
        
        # 1. Initial REGISTER (No Auth)
        contact = f"{self.local_ip}:{self.transport.bind_port}"
        to_uri = f"sip:{self.trunk_number}@{self.registrar}"
        from_uri = f"sip:{self.trunk_number}@{self.registrar}"
        
        msg = SIPMessage.build_register(to_uri, from_uri, contact, self.call_id, self.cseq)
        self.transport.send(msg, self.reg_ip, self.reg_port)
        
        # Wait for response
        resp = self._wait_for_response()
        if not resp:
            self.logger.error("Timeout: No response from registrar.")
            return False

        if resp.status_code == 200:
             self.logger.info("Registration Successful immediately (No Auth?)")
             self.registered = True
             return True

        if resp.status_code in [401, 407]:
            self.logger.info(f"Got challenge {resp.status_code}. Authenticating...")
            self.cseq += 1
            
            # Parse Challenge
            auth_header = resp.get_header("WWW-Authenticate") or resp.get_header("Proxy-Authenticate")
            if not auth_header:
                self.logger.error("No WWW-Authenticate header found.")
                return False
                
            realm = self._extract_param(auth_header, "realm")
            nonce = self._extract_param(auth_header, "nonce")
            opaque = self._extract_param(auth_header, "opaque")
            
            # 2. Authenticated REGISTER
            msg = SIPMessage.build_register(to_uri, from_uri, contact, self.call_id, self.cseq)
            
            # Calculate Digest Response
            response_hash = self._calc_digest("REGISTER", f"sip:{self.trunk_number}@{self.registrar}", realm, nonce)
            
            auth_val = f'Digest username="{self.auth_id}", realm="{realm}", nonce="{nonce}", uri="sip:{self.trunk_number}@{self.registrar}", response="{response_hash}", algorithm=MD5'
            if opaque:
                auth_val += f', opaque="{opaque}"'
            
            msg.add_header("Authorization", auth_val)
            self.last_response = None # Clear previous
            self.transport.send(msg, self.reg_ip, self.reg_port)
            
            resp = self._wait_for_response()
            if resp and resp.status_code == 200:
                self.logger.info("Registration Successful with Auth!")
                self.registered = True
                return True
            else:
                code = resp.status_code if resp else "Timeout"
                self.logger.error(f"Registration Failed. Code: {code}")
                return False
                
        self.logger.error(f"Unexpected response: {resp.status_code} {resp.reason_phrase}")
        return False

    def _wait_for_response(self, timeout=5):
        start = time.time()
        while time.time() - start < timeout:
            if self.last_response:
                res = self.last_response
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

    def _calc_digest(self, method, uri, realm, nonce):
        # HA1 = MD5(username:realm:password)
        ha1_str = f"{self.auth_id}:{realm}:{self.auth_pass}"
        ha1 = hashlib.md5(ha1_str.encode()).hexdigest()
        
        # HA2 = MD5(method:digestURI)
        ha2_str = f"{method}:{uri}"
        ha2 = hashlib.md5(ha2_str.encode()).hexdigest()
        
        # Response = MD5(HA1:nonce:HA2)
        resp_str = f"{ha1}:{nonce}:{ha2}"
        return hashlib.md5(resp_str.encode()).hexdigest()
