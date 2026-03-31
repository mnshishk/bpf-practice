import subprocess
import time
from collections import defaultdict

class IP_blocking:
    def __init__(self, threshold=5, whitelist=None):
        self.threshold = threshold
        # Default whitelist: Localhost and private network range
        self.whitelist = whitelist or ['127.0.0.1']
        self.alert_counts = defaultdict(int)
        self.blocked_ips = {}

    def _is_whitelisted(self, ip):
        return ip in self.whitelist

    def _execute_block(self, ip, permanent=False):
        """Internal method to call system iptables."""
        try:
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            print(f"[{'PERMANENT' if permanent else 'TEMPORARY'}] Blocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking {ip}: {e}")

    def process_incident(self, ip):
        """Main entry point: Blocks IP after 5 alerts."""
        if self._is_whitelisted(ip):
            print(f"Ignored whitelisted IP: {ip}")
            return

        self.alert_counts[ip] += 1
        
        # Check if threshold has been reached
        if self.alert_counts[ip] >= self.threshold:
            if ip not in self.blocked_ips:
                self._execute_block(ip, permanent=False)
                self.blocked_ips[ip] = time.time() + 3600
                print(f"Threshold reached: {ip} blocked for 1 hour.")
        else:
            remaining = self.threshold - self.alert_counts[ip]
            print(f"Alert for {ip}. {remaining} more alerts until blocking.")

        # OG Blocking Logic, commenting out temporarily as we consider rather to include temporary block based on threat severity
    #     if self.alert_counts[ip] >= self.threshold:
    #         if severity >= 0.8: 
    #             self._execute_block(ip, permanent=True)
    #             self.blocked_ips[ip] = float('inf') 
    #         else:
    #             self._execute_block(ip, permanent=False)
    #             self.blocked_ips[ip] = time.time() + 3600

    def cleanup_expired_blocks(self):
        """Call this periodically to unblock temporary bans."""
        now = time.time()
        for ip, expiry in list(self.blocked_ips.items()):
            if now > expiry:
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
                del self.blocked_ips[ip]
                print(f"Temporary block expired for {ip}")