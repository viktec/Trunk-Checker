import socket
import threading
from core.sip_message import SIPMessage

class SIPTransport:
    def __init__(self, bind_ip="0.0.0.0", bind_port=5060, logger=None):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.sock = None
        self.running = False
        self.logger = logger
        self.listeners = [] # List of callbacks

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.bind_ip, self.bind_port))
        self.running = True
        self.logger.info(f"SIP Transport listening on {self.bind_ip}:{self.bind_port}")
        
        t = threading.Thread(target=self._receive_loop, daemon=True)
        t.start()

    def _receive_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if self.logger:
                    self.logger.debug(f"Received {len(data)} bytes from {addr}")
                    self.logger.debug(f"\n<<< INBOUND <<<\n{data.decode('utf-8', errors='ignore')}\n")
                
                msg = SIPMessage.parse(data)
                for listener in self.listeners:
                    listener(msg, addr)
            except Exception as e:
                if self.running:
                    print(f"Error receiving data: {e}")

    def send(self, sip_message, target_ip, target_port):
        data = str(sip_message).encode('utf-8')
        if self.logger:
             self.logger.debug(f"Sending {len(data)} bytes to {target_ip}:{target_port}")
             self.logger.debug(f"\n>>> OUTBOUND >>>\n{sip_message}\n")
        
        if self.sock:
            self.sock.sendto(data, (target_ip, int(target_port)))
            self._notify_outbound(sip_message, target_ip, target_port)
            # Notify listeners for OUTBOUND traffic analysis
            # We pass a tuple or special object to indicate direction context if needed, 
            # or just rely on the listener to know it's being called from send.
            # For simplicity, let's keep the signature same: listener(msg, addr)
            # But we might need to tag it. 
            # Actually, let's just trigger listeners. The listener might need to deduce direction.
            # Better: add a specific outbound listener list or change signature.
            # Changing signature breaks existing consumers.
            # Let's add a separate method `add_outbound_listener`.
    
    def add_listener(self, callback):
        self.listeners.append(callback)

    def add_outbound_listener(self, callback):
        if not hasattr(self, 'outbound_listeners'):
            self.outbound_listeners = []
        self.outbound_listeners.append(callback)

    def _notify_outbound(self, msg, target_ip, target_port):
         if hasattr(self, 'outbound_listeners'):
             for listener in self.outbound_listeners:
                 listener(msg, (target_ip, target_port))
