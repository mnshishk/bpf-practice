import subprocess
import time
from collections import defaultdict

class IP_blocking:
    def __init__(self, threshold=5):
        self.threshold = threshold
        self.alert_counts = defaultdict(int)
        self.blocked_ips = {}

    def _execute_block(self, ip, permanent=False):
        """Internal method to call system iptables."""
        try:
            # check if IP is already blocked
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            print(f"[{'PERMANENT' if permanent else 'TEMPORARY'}] Blocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking {ip}: {e}")

    def process_incident(self, ip):
        """Main entry point: Blocks IP after threshold is reached."""
        self.alert_counts[ip] += 1
        
        # Check if threshold has been reached
        if self.alert_counts[ip] >= self.threshold:
            if ip not in self.blocked_ips:
                self._execute_block(ip, permanent=False)
                # Block for 1 hour (3600 seconds)
                self.blocked_ips[ip] = time.time() + 3600
                print(f"Threshold reached: {ip} blocked for 1 hour.")
        else:
            remaining = self.threshold - self.alert_counts[ip]
            print(f"Alert for {ip}. {remaining} more alerts until blocking.")

    def cleanup_expired_blocks(self):
        """Call this periodically to unblock temporary bans."""
        now = time.time()
        for ip, expiry in list(self.blocked_ips.items()):
            if now > expiry:
                try:
                    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                    del self.blocked_ips[ip]
                    # Reset alert count so they can be blocked again if they keep attacking
                    self.alert_counts[ip] = 0 
                    print(f"Temporary block expired for {ip}")
                except subprocess.CalledProcessError:
                    print(f"Failed to remove iptables rule for {ip}")