import dns.resolver

class DNSAgent:
    def __init__(self, logger):
        self.logger = logger
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = 2.0 # Timeout
        
    def resolve(self, domain, transport="UDP"):
        """
        Resolves a domain to a list of (priority, target, port, transport).
        Follows RFC 3263: NAPTR -> SRV -> A/AAAA.
        default_transport: UDP, TCP, TLS
        """
        self.logger.info(f"Resolving Domain: {domain}")
        
        # 0. Check if domain is already an IP
        import re
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            self.logger.info("Input is an IP address. Skipping DNS.")
            return [(0, domain, 5060 if transport != "TLS" else 5061, transport)]
        
        # 1. NAPTR
        try:
            naptr_answers = self.resolver.resolve(domain, 'NAPTR')
            # Sort by order and preference
            naptr_answers = sorted(naptr_answers, key=lambda r: (r.order, r.preference))
            for r in naptr_answers:
                flag = r.flags.decode()
                service = r.service.decode()
                if "S" in flag:
                    if "SIP+D2U" in service:
                        return self._resolve_srv(r.replacement.decode(), "UDP")
                    elif "SIP+D2T" in service:
                        return self._resolve_srv(r.replacement.decode(), "TCP")
                    elif "SIPS+D2T" in service:
                        return self._resolve_srv(r.replacement.decode(), "TLS")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
             self.logger.debug("No NAPTR records found.")

        # 2. SRV (If no NAPTR or if NAPTR failed)
        # Try default SRV records based on transport
        transport = transport.upper()
        srv_prefix = "_sip._udp"
        if transport == "TCP":
            srv_prefix = "_sip._tcp"
        elif transport == "TLS":
            srv_prefix = "_sips._tcp"
            
        target_srv = f"{srv_prefix}.{domain}"
        results = self._resolve_srv(target_srv, transport)
        if results:
            return results

        # 3. A/AAAA (Fallback)
        self.logger.info(f"No SRV records found. Falling back to A record for {domain}")
        return self._resolve_a(domain, 5060 if transport != "TLS" else 5061, transport)

    def _resolve_srv(self, srv_domain, transport):
        try:
            self.logger.debug(f"Querying SRV: {srv_domain}")
            answers = self.resolver.resolve(srv_domain, 'SRV')
            results = []
            for r in answers:
                # Target is usually "host.example.com."
                target = r.target.to_text(omit_final_dot=True)
                # Now resolve IP for this target
                ips = self._resolve_a(target, r.port, transport)
                for res in ips:
                    # Prepend Priority/Weight info? For now just flatten
                    results.append(res)
            return results
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []

    def _resolve_a(self, host, port, transport):
        results = []
        try:
            # IPv4
            answers = self.resolver.resolve(host, 'A')
            for r in answers:
                results.append( (r.to_text(), port, transport) )
        except:
            pass
            
        if not results: # Try IPv6 if no IPv4
             try:
                answers = self.resolver.resolve(host, 'AAAA')
                for r in answers:
                    results.append( (r.to_text(), port, transport) )
             except:
                pass
        
        return results
