import time
from core.sip_message import SIPMessage

class InboundCallAgent:
    def __init__(self, logger, transport):
        self.logger = logger
        self.transport = transport
        self.call_state = "IDLE"
        self.remote_addr = None
        self.local_tag = SIPMessage.generate_nonce(8)
        
        self.transport.add_listener(self._handle_request)

    def _handle_request(self, msg, addr):
        if msg.method == "INVITE":
            self.logger.info(f"Incoming Call from {addr}")
            self._handle_invite(msg, addr)
        elif msg.method == "ACK":
            if self.call_state == "RINGING" or self.call_state == "ANSWERED":
                self.logger.info("Call Established (ACK received)")
                self.call_state = "ACTIVE"
        elif msg.method == "BYE":
            self.logger.info("Call Terminated by remote")
            self._send_response(msg, 200, "OK", addr)
            self.call_state = "ENDED"

    def _handle_invite(self, msg, addr):
        self.remote_addr = addr
        self.call_state = "RINGING"
        
        # 1. Send 100 Trying
        self._send_response(msg, 100, "Trying", addr)
        
        # 2. Send 180 Ringing
        time.sleep(0.5)
        self._send_response(msg, 180, "Ringing", addr)
        
        # 3. Answer (200 OK) after delay
        time.sleep(2)
        self.call_state = "ANSWERED"
        
        # Simple SDP
        # Need to determine local IP properly, for now use a placeholder or try to reuse transport info
        local_ip = "127.0.0.1" # TODO: Fix this
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            pass

        sdp = f"v=0\r\no=- 123456 123456 IN IP4 {local_ip}\r\ns=TrunkChecker\r\nc=IN IP4 {local_ip}\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0 8 18\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:18 G729/8000"
        
        self._send_response(msg, 200, "OK", addr, body=sdp)

    def _send_response(self, req, code, reason, addr, body=""):
        res = SIPMessage(status_code=code, reason_phrase=reason)
        # Copy headers
        res.add_header("Via", req.get_header("Via"))
        res.add_header("From", req.get_header("From"))
        to_hdr = req.get_header("To")
        if code > 100:
            if "tag=" not in to_hdr:
                to_hdr += f";tag={self.local_tag}"
        res.add_header("To", to_hdr)
        res.add_header("Call-ID", req.get_header("Call-ID"))
        res.add_header("CSeq", req.get_header("CSeq"))
        
        if code == 200 and req.method == "INVITE":
             # Need Contact
             local_ip = "127.0.0.1" # Same hack
             try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
             except:
                pass
             res.add_header("Contact", f"<sip:checker@{local_ip}:5060>")
             res.add_header("Content-Type", "application/sdp")
        
        res.body = body
        self.transport.send(res, addr[0], addr[1])

    def wait_for_call(self, timeout=60):
        start = time.time()
        while time.time() - start < timeout:
            if self.call_state == "ACTIVE":
                return True
            if self.call_state == "ENDED":
                return True
            time.sleep(0.5)
        return False
