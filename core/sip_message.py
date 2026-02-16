import hashlib
import random
import string

class SIPMessage:
    def __init__(self, method=None, uri=None, headers=None, body="", status_code=None, reason_phrase=None):
        self.method = method # REGISTER, INVITE, etc. or None if response
        self.uri = uri
        self.status_code = status_code
        self.reason_phrase = reason_phrase
        self.headers = headers if headers else {}
        self.body = body

    def add_header(self, name, value):
        self.headers[name] = value

    def get_header(self, name):
        # Case-insensitive search
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None

    def __str__(self):
        # Build raw string
        lines = []
        if self.method:
            lines.append(f"{self.method} {self.uri} SIP/2.0")
        else:
            lines.append(f"SIP/2.0 {self.status_code} {self.reason_phrase}")
        
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        
        lines.append(f"Content-Length: {len(self.body)}")
        lines.append("") # Empty line before body
        lines.append(self.body)
        
        return "\r\n".join(lines)

    @staticmethod
    def parse(raw_data):
        try:
            raw_str = raw_data.decode('utf-8')
        except:
            raw_str = raw_data.decode('utf-8', errors='ignore') # Fallback

        parts = raw_str.split("\r\n\r\n", 1)
        header_part = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_part.split("\r\n")
        first_line = lines[0]
        headers = {}
        
        method = None
        uri = None
        status_code = None
        reason_phrase = None

        if first_line.startswith("SIP/2.0"):
            # Response
            fl_parts = first_line.split(" ", 2)
            status_code = int(fl_parts[1])
            reason_phrase = fl_parts[2]
        else:
            # Request
            fl_parts = first_line.split(" ", 2)
            method = fl_parts[0]
            uri = fl_parts[1]

        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k] = v
        
        return SIPMessage(method, uri, headers, body, status_code, reason_phrase)

    @staticmethod
    def build_register(to_uri, from_uri, contact_uri, call_id, cseq, expire=3600):
        msg = SIPMessage("REGISTER", to_uri)
        msg.add_header("Via", f"SIP/2.0/UDP {contact_uri};rport;branch=z9hG4bK{SIPMessage.generate_nonce()}")
        msg.add_header("Max-Forwards", "70")
        msg.add_header("To", to_uri)
        msg.add_header("From", f"{from_uri};tag={SIPMessage.generate_nonce()}")
        msg.add_header("Call-ID", call_id)
        msg.add_header("CSeq", f"{cseq} REGISTER")
        msg.add_header("Contact", f"<sip:{contact_uri}>")
        msg.add_header("Expires", str(expire))
        return msg

    @staticmethod
    def generate_nonce(length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
