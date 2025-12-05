#!/usr/bin/env python3
"""
SSH EDR that reads logs from systemd journal (journalctl) or stdin.

Usage examples:
  # Tail journal directly (recommended on systemd systems)
  python3 ssh_edr_journal.py --unit ssh
  python3 ssh_edr_journal.py --unit sshd

  # Or pipe journalctl into the script (e.g. for remote processing)
  journalctl -u ssh -f -o cat | python3 ssh_edr_journal.py --stdin

Notes:
 - The script expects journal lines in the typical OpenSSH format (Failed password, Invalid user, Accepted ...).
 - If you run with --block the script will print iptables commands; it will only execute them if run as root and --execute-block is given.
"""

import argparse
import re
import json
import os
import sys
import time
import subprocess
from collections import deque, defaultdict
from datetime import datetime, timedelta

FAILED_RE = re.compile(r'Failed password for (?:(invalid user )?(\S+) )?from (\d+\.\d+\.\d+\.\d+)')
INVALID_USER_RE = re.compile(r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)')
ACCEPTED_RE = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)')
PAM_FAILED_RE = re.compile(r'authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)')

# Default alert file; change to a writable path if running as non-root
ALERT_FILE = "/var/log/ssh_edr_alerts.jsonl"

class SSHEdr:
    def __init__(self, failed_threshold=5, window_seconds=60, invalid_threshold=8, dry_run=True, execute_block=False):
        self.failed_threshold = failed_threshold
        self.window = timedelta(seconds=window_seconds)
        self.invalid_threshold = invalid_threshold
        self.failed = defaultdict(deque)
        self.invalid_user = defaultdict(deque)
        self.successful_logins = defaultdict(lambda: deque(maxlen=50))
        self.known_user_ips = defaultdict(set)
        self.alerts = []
        self.dry_run = dry_run
        self.execute_block = execute_block

    def _now(self):
        return datetime.utcnow()

    def _prune(self, dq, cutoff):
        while dq and dq[0] < cutoff:
            dq.popleft()

    def record_failed(self, ip):
        now = self._now()
        dq = self.failed[ip]
        dq.append(now)
        cutoff = now - self.window
        self._prune(dq, cutoff)
        if len(dq) >= self.failed_threshold:
            self._alert('brute_force_suspected', {'ip': ip, 'count': len(dq), 'window_s': int(self.window.total_seconds())})
            if not self.dry_run:
                self._block_ip(ip)

    def record_invalid_user(self, ip, user):
        now = self._now()
        dq = self.invalid_user[ip]
        dq.append(now)
        cutoff = now - self.window
        self._prune(dq, cutoff)
        if len(dq) >= self.invalid_threshold:
            self._alert('invalid_user_burst', {'ip': ip, 'user': user, 'count': len(dq)})
            if not self.dry_run:
                self._block_ip(ip)

    def record_success(self, user, ip):
        now = self._now()
        fail_count = len(self.failed[ip])
        if fail_count >= max(1, self.failed_threshold//2):
            self._alert('successful_after_failures', {'user': user, 'ip': ip, 'recent_failed': fail_count})
        if ip not in self.known_user_ips[user]:
            self._alert('login_from_new_ip', {'user': user, 'ip': ip})
            self.known_user_ips[user].add(ip)
        self.successful_logins[user].append((ip, now))

    def _alert(self, kind, info):
        alert = {
            'ts': datetime.utcnow().isoformat() + 'Z',
            'kind': kind,
            'info': info
        }
        print('[ALERT]', json.dumps(alert))
        self.alerts.append(alert)
        # try to persist to file (best-effort)
        try:
            with open(ALERT_FILE, 'a') as f:
                f.write(json.dumps(alert) + "\\n")
        except Exception as e:
            # not fatal; just print
            print("Could not write alert to file:", e, file=sys.stderr)

    def _block_ip(self, ip):
        # Example: print iptables command and execute if allowed
        cmd = ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP']
        print("[ACTION] block ip:", ' '.join(cmd))
        if self.execute_block:
            try:
                subprocess.check_call(cmd)
            except Exception as e:
                print("Failed to execute block command:", e, file=sys.stderr)

    def parse_line(self, line):
        # Try multiple regex to extract event
        m = FAILED_RE.search(line)
        if m:
            ip = m.group(3)
            self.record_failed(ip)
            return

        m = INVALID_USER_RE.search(line)
        if m:
            user = m.group(1)
            ip = m.group(2)
            self.record_invalid_user(ip, user)
            return

        m = ACCEPTED_RE.search(line)
        if m:
            user = m.group(1)
            ip = m.group(2)
            self.record_success(user, ip)
            return

        m = PAM_FAILED_RE.search(line)
        if m:
            ip = m.group(1)
            self.record_failed(ip)
            return

    def tail_journal(self, unit):
        # Spawn journalctl -u <unit> -f -o cat and yield lines
        cmd = ['journalctl', '-u', unit, '-f', '-o', 'cat']
        try:
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as p:
                for raw in p.stdout:
                    yield raw.rstrip('\\n')
        except FileNotFoundError:
            print("journalctl not found on this system. Use --stdin to pipe journal output into the script.", file=sys.stderr)
            sys.exit(2)
        except Exception as e:
            print("Error running journalctl:", e, file=sys.stderr)
            sys.exit(3)

    def run(self, args):
        if args.stdin:
            print("Reading logs from stdin...")
            for ln in sys.stdin:
                self.parse_line(ln.rstrip('\\n'))
        else:
            print(f"Tailing journal unit '{args.unit}' (press Ctrl+C to stop)...")
            for ln in self.tail_journal(args.unit):
                self.parse_line(ln)

def build_parser():
    p = argparse.ArgumentParser()
    p.add_argument('--unit', default='ssh', help='systemd unit name to follow (ssh, sshd, ssh.service, etc.)')
    p.add_argument('--failed-threshold', type=int, default=5, help='failed attempts threshold for alerting')
    p.add_argument('--window', type=int, default=60, help='time window (seconds) for counting failed attempts')
    p.add_argument('--invalid-threshold', type=int, default=8, help='invalid user burst threshold')
    p.add_argument('--stdin', action='store_true', help='read journal lines from stdin instead of running journalctl')
    p.add_argument('--block', action='store_true', help='print iptables block commands when a brute force is detected')
    p.add_argument('--execute-block', action='store_true', help='execute the iptables block commands (requires root)')
    return p

if __name__ == '__main__':
    parser = build_parser()
    args = parser.parse_args()

    edr = SSHEdr(failed_threshold=args.failed_threshold, window_seconds=args.window, invalid_threshold=args.invalid_threshold,
                 dry_run=not args.block, execute_block=args.execute_block)
    try:
        edr.run(args)
    except KeyboardInterrupt:
        print("\\nStopped by user. Collected alerts:")
        print(json.dumps(edr.alerts, indent=2))
