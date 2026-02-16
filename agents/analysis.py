from core.sip_message import SIPMessage

class AnalysisAgent:
    def __init__(self, logger):
        self.logger = logger
        self.messages = []
        self.warnings = []
        self.errors = []
        self.features = {
            "rinstance": False,
            "rfc2833": False,
            "prack": False,
            "session_timer": False,
            "p_identity": False,
            "rtcp": False,
            "srtp": False,
            "codecs": set()
        }

    def check_message(self, msg, direction, addr):
        """
        Main entry point for analysis.
        msg: SIPMessage object
        direction: "IN" or "OUT"
        addr: tuple (ip, port)
        """
        self.messages.append((direction, msg))
        
        # 1. Base RFC Compliance
        self._check_mandatory_headers(msg)
        
        # 2. Method Specific Checks
        if msg.method == "INVITE":
            self._check_invite_compliance(msg)
        
        # 3. Response Checks
        if msg.status_code:
            self._check_response_compliance(msg)
            
        # 4. Security Headers
        if msg.method == "INVITE" or (msg.status_code and msg.status_code == 200):
            self._check_security_headers(msg)

        # 5. SDP Analysis
        if msg.body:
            self._analyze_body(msg)

    def print_report(self):
        self.logger.info("\n" + "="*40)
        self.logger.info("      TRUNK ANALYSIS REPORT")
        self.logger.info("="*40)
        
        # Feature Checklist
        self.logger.info("\n[Feature Support]")
        features_map = {
            "Source Identification (rinstance)": "rinstance",
            "RFC 2833 DTMF": "rfc2833",
            "PRACK (Reliability)": "prack",
            "Session Timers": "session_timer",
            "P-Identity Headers": "p_identity",
            "RTCP": "rtcp",
            "SRTP (Secure RTP)": "srtp"
        }
        
        for label, key in features_map.items():
            status = "[OK] YES" if self.features[key] else "[NO]  NO"
            self.logger.info(f"{status} - {label}")
        
        self.logger.info(f"[OK] Codecs Detected: {', '.join(self.features['codecs']) if self.features['codecs'] else 'None'}")

        self.logger.info("\n[Compliance Checks]")
        if not self.warnings and not self.errors:
             self.logger.info("[OK] No obvious RFC violations found.")
        
        if self.warnings:
            self.logger.info("[WARN] WARNINGS:")
            for w in self.warnings:
                self.logger.info(f"  - {w}")
        
        if self.errors:
            self.logger.info("[FAIL] ERRORS:")
            for e in self.errors:
                self.logger.info(f"  - {e}")
        self.logger.info("-----------------------\n")

    def _check_mandatory_headers(self, msg):
        mandatory = ["Via", "From", "To", "Call-ID", "CSeq"]
        for h in mandatory:
            if not msg.get_header(h):
                self.errors.append(f"Missing mandatory header: {h} in {msg.method or msg.status_code}")
        
        # Content-Length check
        cl = msg.get_header("Content-Length")
        if cl:
            if int(cl) != len(msg.body):
                self.warnings.append(f"Content-Length mismatch: Header={cl}, Actual={len(msg.body)}")
        else:
            self.warnings.append("Missing Content-Length header")

    def _check_invite_compliance(self, msg):
        if not msg.get_header("Max-Forwards"):
            self.errors.append("Missing Max-Forwards in INVITE (RFC 3261)")
        if not msg.get_header("Contact"):
            self.warnings.append("Missing Contact in INVITE")
            
        if msg.get_header("Contact") and "rinstance=" in msg.get_header("Contact"):
             self.features["rinstance"] = True

        # Session Timer check
        if msg.get_header("Session-Expires") or (msg.get_header("Supported") and "timer" in msg.get_header("Supported")):
             self.logger.info("Session-Expires header present (RFC 4028 Support detected).")
             self.features["session_timer"] = True
        
        # PRACK check
        supported = msg.get_header("Supported")
        if supported and "100rel" in supported:
             self.logger.info("Remote supports 100rel (PRACK).")
             self.features["prack"] = True

    def _check_response_compliance(self, msg):
        pass

    def _check_security_headers(self, msg):
        pai = msg.get_header("P-Asserted-Identity")
        if pai:
            self.logger.info(f"Found P-Asserted-Identity: {pai}")
            self.features["p_identity"] = True
        ppi = msg.get_header("P-Preferred-Identity")
        if ppi:
            self.logger.info(f"Found P-Preferred-Identity: {ppi}")
            self.features["p_identity"] = True
        rpid = msg.get_header("Remote-Party-ID")
        if rpid:
            self.warnings.append("Remote-Party-ID found (Depreciated, use PAI/PPI).")

    def _analyze_body(self, msg):
        ct = msg.get_header("Content-Type")
        if ct and "application/sdp" in ct:
            self._analyze_sdp(msg.body)

    def _analyze_sdp(self, sdp):
        for line in sdp.split("\r\n"):
            if line.startswith("m=audio"):
                self.logger.info(f"SDP Audio Media Line: {line}")
            if line.startswith("a=rtpmap"):
                codec = line.split(" ", 1)[1]
                self.features["codecs"].add(codec)
                if "telephone-event" in codec:
                    self.features["rfc2833"] = True
            if line.startswith("a=crypto"):
                 self.logger.info("SRTP Crypto attribute found.")
                 self.features["srtp"] = True
            if line.startswith("a=rtcp") or "a=rtcp-mux" in line:
                 self.features["rtcp"] = True
        
        if self.features["codecs"]:
            self.logger.info(f"Negotiated/Offered Codecs: {', '.join(self.features['codecs'])}")
