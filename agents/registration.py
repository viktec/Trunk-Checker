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
        
        # Determine IP for Contact Header
        # Try to get Public IP first for better NAT traversal
        self.local_ip = "127.0.0.1"
        try:
            import urllib.request
            self.local_ip = urllib.request.urlopen('https://api.ipify.org', timeout=3).read().decode('utf8')
            self.logger.info(f"Detected Public IP: {self.local_ip}")
        except:
             # Fallback to local private IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                self.local_ip = s.getsockname()[0]
                s.close()
                self.logger.info(f"Using Local IP: {self.local_ip}")
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
            qop = self._extract_param(auth_header, "qop")
            
            # 2. Authenticated REGISTER
            msg = SIPMessage.build_register(to_uri, from_uri, contact, self.call_id, self.cseq)
            
            cnonce = None
            nc = None
            if qop:
                cnonce = SIPMessage.generate_nonce(16)
                nc = "00000001"

            # Calculate Digest Response
            response_hash = self._calc_digest("REGISTER", f"sip:{self.trunk_number}@{self.registrar}", realm, nonce, qop, cnonce, nc)
            
            auth_val = f'Digest username="{self.auth_id}", realm="{realm}", nonce="{nonce}", uri="sip:{self.trunk_number}@{self.registrar}", response="{response_hash}", algorithm=MD5'
            
            if opaque:
                auth_val += f', opaque="{opaque}"'
            if qop:
                 auth_val += f', qop=auth, cnonce="{cnonce}", nc={nc}'
            
            msg.add_header("Authorization", auth_val)
            
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
                msg_text = resp.reason_phrase if resp else "No Response"
                self.logger.error(f"Registration Failed. Code: {code} {msg_text}")
                
                if resp and code == 403:
                    self.logger.warning("403 Forbidden usually means:")
                    self.logger.warning("1. Wrong Password")
                    self.logger.warning("2. Wrong Username/Auth ID")
                    self.logger.warning("3. IP Address not whitelisted by provider")
                    warning_header = resp.get_header("Warning")
                    if warning_header:
                        self.logger.warning(f"Server Warning: {warning_header}")
                
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

    def send_keepalive(self):
        """
        Sends an OPTIONS packet to keep NAT open.
        """
        try:
            msg = SIPMessage("OPTIONS", f"sip:{self.registrar}")
            msg.add_header("Via", f"SIP/2.0/UDP {self.local_ip}:{self.transport.bind_port};rport;branch=z9hG4bK{SIPMessage.generate_nonce()}")
            msg.add_header("Max-Forwards", "70")
            msg.add_header("To", f"sip:{self.registrar}")
            msg.add_header("From", f"sip:{self.trunk_number}@{self.registrar};tag={SIPMessage.generate_nonce()}")
            msg.add_header("Call-ID", SIPMessage.generate_nonce(16))
            msg.add_header("CSeq", f"{int(time.time())} OPTIONS")
            msg.add_header("Contact", f"<sip:{self.local_ip}:{self.transport.bind_port}>")
            msg.add_header("User-Agent", "TrunkChecker/KeepAlive")
            msg.add_header("Content-Length", "0")
            
            self.transport.send(msg, self.reg_ip, self.reg_port)
        except Exception as e:
            self.logger.error(f"KeepAlive Error: {e}")

    def _extract_param(self, header, key):
        import re
        match = re.search(f'{key}="([^"]+)"', header)
        if match:
            return match.group(1)
        match = re.search(f'{key}=([^, ]+)', header)
        return match.group(1) if match else None

    def _calc_digest(self, method, uri, realm, nonce, qop=None, cnonce=None, nc=None):
        # HA1 = MD5(username:realm:password)
        ha1_str = f"{self.auth_id}:{realm}:{self.auth_pass}"
        ha1 = hashlib.md5(ha1_str.encode()).hexdigest()
        
        # HA2 = MD5(method:digestURI)
        ha2_str = f"{method}:{uri}"
        ha2 = hashlib.md5(ha2_str.encode()).hexdigest()
        
        # Response = MD5(HA1:nonce:HA2) for no qop
        # Response = MD5(HA1:nonce:nc:cnonce:qop:HA2) for qop=auth
        if qop and (qop == "auth" or "auth" in qop):
            resp_str = f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}"
        else:
            resp_str = f"{ha1}:{nonce}:{ha2}"
            
        return hashlib.md5(resp_str.encode()).hexdigest()
