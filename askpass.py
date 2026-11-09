#!/usr/bin/env python3
"""Ask SSH credentials with a native macOS dialog, never through the web app."""
import subprocess
import sys


def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else "SSH 身份验证"
    # ProxyJump helpers may use their own host-key policy. Host-key trust must
    # be established in a normal terminal, never through a hidden password box.
    if "are you sure you want to continue connecting" in prompt.lower():
        return 1
    script = '''on run argv
        set question to item 1 of argv
        set answer to display dialog question with title "Tunnel Desk · SSH 认证" default answer "" with hidden answer buttons {"取消", "连接"} default button "连接" cancel button "取消" giving up after 120
        if gave up of answer then error number -128
        return text returned of answer
    end run'''
    try:
        result = subprocess.run(
            ["/usr/bin/osascript", "-e", script, prompt],
            capture_output=True, timeout=130,
        )
        if result.returncode:
            return 1
        # The answer only travels over the private pipe created by OpenSSH.
        sys.stdout.buffer.write(result.stdout)
        sys.stdout.buffer.flush()
        return 0
    except (OSError, subprocess.TimeoutExpired):
        return 1


if __name__ == "__main__":
    sys.exit(main())
