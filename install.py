#!/usr/bin/env python3
"""
Squawk DNS Client Installer
Cross-platform installer for Windows, macOS, and Linux (especially Debian)
Sets up DNS client as a system service/daemon and configures system DNS
"""

import os
import sys
import platform
import subprocess
import shutil
import argparse
import json
import tempfile
from pathlib import Path

class SquawkInstaller:
    def __init__(self):
        self.system = platform.system()
        self.is_admin = self.check_admin_privileges()
        self.install_path = self.get_install_path()
        self.config_path = self.get_config_path()
        self.service_name = "squawk-dns"

    def check_admin_privileges(self):
        """Check if running with admin/root privileges"""
        if self.system == "Windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:
            return os.geteuid() == 0

    def get_install_path(self):
        """Get installation path based on OS"""
        if self.system == "Windows":
            return Path(os.environ.get('PROGRAMFILES', 'C:\\Program Files')) / "Squawk"
        elif self.system == "Darwin":  # macOS
            return Path("/usr/local/squawk")
        else:  # Linux
            return Path("/opt/squawk")

    def get_config_path(self):
        """Get configuration path based on OS"""
        if self.system == "Windows":
            return Path(os.environ.get('PROGRAMDATA', 'C:\\ProgramData')) / "Squawk"
        else:
            return Path("/etc/squawk")

    def install_dependencies(self):
        """Install Python dependencies"""
        print("Installing Python dependencies...")
        requirements = [
            "dnspython>=2.4.2",
            "requests>=2.31.0",
            "PyYAML>=6.0.1",
            "cryptography>=41.0.7",
            "pystray>=0.19.5",
            "Pillow>=10.0.0"
        ]

        for req in requirements:
            subprocess.run([sys.executable, "-m", "pip", "install", req], check=True)

    def create_directories(self):
        """Create installation directories"""
        print(f"Creating directories at {self.install_path}...")
        self.install_path.mkdir(parents=True, exist_ok=True)
        self.config_path.mkdir(parents=True, exist_ok=True)

        # Create log directory
        log_path = self.install_path / "logs"
        log_path.mkdir(exist_ok=True)

    def copy_files(self):
        """Copy application files to installation directory"""
        print("Copying application files...")

        # Copy client files
        client_src = Path(__file__).parent / "squawk-client"
        if client_src.exists():
            shutil.copytree(client_src / "bins", self.install_path / "bins", dirs_exist_ok=True)
            shutil.copytree(client_src / "libs", self.install_path / "libs", dirs_exist_ok=True)

        # Make scripts executable on Unix systems
        if self.system != "Windows":
            for script in (self.install_path / "bins").glob("*.py"):
                script.chmod(0o755)

    def create_config(self):
        """Create default configuration file"""
        print("Creating configuration file...")

        config = {
            "dns_server_url": os.getenv("SQUAWK_SERVER_URL", "https://dns.google/resolve"),
            "auth_token": os.getenv("SQUAWK_AUTH_TOKEN", ""),
            "listen_udp": True,
            "listen_tcp": False,
            "udp_port": 53,
            "tcp_port": 53,
            "auto_start": True,
            "console_url": os.getenv("SQUAWK_CONSOLE_URL", "http://localhost:8080/health"),
            "cache_enabled": os.getenv("CACHE_ENABLED", "true").lower() == "true",
            "cache_ttl": int(os.getenv("CACHE_TTL", "300")),
            "valkey_url": os.getenv("VALKEY_URL", ""),
            "log_level": os.getenv("LOG_LEVEL", "INFO")
        }

        config_file = self.config_path / "config.yaml"
        with open(config_file, 'w') as f:
            import yaml
            yaml.dump(config, f, default_flow_style=False)

        print(f"Configuration saved to {config_file}")
        return config_file

    def install_windows_service(self):
        """Install Windows service"""
        print("Installing Windows service...")

        # Create service wrapper script
        service_script = self.install_path / "service.py"
        service_content = f'''
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys
import os
import time

sys.path.insert(0, r"{self.install_path / 'bins'}")
from client import DNSOverHTTPSClient, DNSForwarder, load_config

class SquawkDNSService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SquawkDNS"
    _svc_display_name_ = "Squawk DNS Client"
    _svc_description_ = "Local DNS resolver with DoH support"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.running = False

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                            servicemanager.PYS_SERVICE_STARTED,
                            (self._svc_name_, ''))
        self.main()

    def main(self):
        config = load_config(r"{self.config_path / 'config.yaml'}")

        dns_client = DNSOverHTTPSClient(
            config.get('dns_server_url'),
            config.get('auth_token')
        )

        forwarder = DNSForwarder(
            dns_client,
            udp_port=config.get('udp_port', 53),
            tcp_port=config.get('tcp_port', 53),
            listen_udp=config.get('listen_udp', True),
            listen_tcp=config.get('listen_tcp', False)
        )

        # Run in a thread
        import threading
        forwarder_thread = threading.Thread(target=forwarder.start)
        forwarder_thread.daemon = True
        forwarder_thread.start()

        # Wait for stop signal
        while self.running:
            time.sleep(1)

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(SquawkDNSService)
'''

        with open(service_script, 'w') as f:
            f.write(service_content)

        # Install pywin32
        subprocess.run([sys.executable, "-m", "pip", "install", "pywin32"], check=True)

        # Install the service
        subprocess.run([sys.executable, str(service_script), "install"], check=True)

        # Configure service to start automatically
        subprocess.run(["sc", "config", "SquawkDNS", "start=", "auto"], check=True)

        print("Windows service installed successfully")

    def install_macos_daemon(self):
        """Install macOS launchd daemon"""
        print("Installing macOS daemon...")

        plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.squawk.dns</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{self.install_path / "bins" / "client.py"}</string>
        <string>-c</string>
        <string>{self.config_path / "config.yaml"}</string>
        <string>--listen-udp</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>{self.install_path / "logs" / "error.log"}</string>
    <key>StandardOutPath</key>
    <string>{self.install_path / "logs" / "output.log"}</string>
    <key>WorkingDirectory</key>
    <string>{self.install_path}</string>
</dict>
</plist>'''

        plist_path = Path("/Library/LaunchDaemons/com.squawk.dns.plist")
        with open(plist_path, 'w') as f:
            f.write(plist_content)

        # Set correct permissions
        os.chown(plist_path, 0, 0)
        os.chmod(plist_path, 0o644)

        # Load the daemon
        subprocess.run(["launchctl", "load", str(plist_path)], check=True)

        print("macOS daemon installed successfully")

    def install_systemd_service(self):
        """Install systemd service for Linux"""
        print("Installing systemd service...")

        service_content = f'''[Unit]
Description=Squawk DNS Client
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={self.install_path}
ExecStart={sys.executable} {self.install_path / "bins" / "client.py"} -c {self.config_path / "config.yaml"} --listen-udp
Restart=always
RestartSec=10
StandardOutput=append:{self.install_path / "logs" / "squawk.log"}
StandardError=append:{self.install_path / "logs" / "squawk-error.log"}

# Security hardening
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={self.install_path / "logs"} {self.config_path}
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target'''

        service_path = Path("/etc/systemd/system/squawk-dns.service")
        with open(service_path, 'w') as f:
            f.write(service_content)

        # Reload systemd and enable service
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "squawk-dns.service"], check=True)

        print("Systemd service installed successfully")

    def configure_system_dns(self):
        """Configure system to use local DNS resolver"""
        print("Configuring system DNS...")

        if self.system == "Windows":
            # Configure Windows DNS
            print("Configuring Windows DNS settings...")
            # Get network adapters
            result = subprocess.run(
                ["netsh", "interface", "ip", "show", "config"],
                capture_output=True, text=True
            )

            # Set DNS for primary adapter
            subprocess.run([
                "netsh", "interface", "ip", "set", "dns",
                "name=\"Ethernet\"", "static", "127.0.0.1", "primary"
            ], check=False)

            subprocess.run([
                "netsh", "interface", "ip", "set", "dns",
                "name=\"Wi-Fi\"", "static", "127.0.0.1", "primary"
            ], check=False)

        elif self.system == "Darwin":
            # Configure macOS DNS
            print("Configuring macOS DNS settings...")
            # Get network services
            result = subprocess.run(
                ["networksetup", "-listallnetworkservices"],
                capture_output=True, text=True
            )

            services = [s.strip() for s in result.stdout.split('\n')[1:] if s.strip()]

            for service in services:
                if not service.startswith('*'):
                    subprocess.run([
                        "networksetup", "-setdnsservers", service, "127.0.0.1"
                    ], check=False)

        else:
            # Configure Linux DNS
            print("Configuring Linux DNS settings...")

            # Check if using systemd-resolved
            if Path("/etc/systemd/resolved.conf").exists():
                # Configure systemd-resolved
                resolved_conf = """[Resolve]
DNS=127.0.0.1
FallbackDNS=8.8.8.8 8.8.4.4
"""
                with open("/etc/systemd/resolved.conf.d/squawk.conf", 'w') as f:
                    f.write(resolved_conf)

                subprocess.run(["systemctl", "restart", "systemd-resolved"], check=False)

            # Traditional resolv.conf
            else:
                # Backup original resolv.conf
                resolv_conf = Path("/etc/resolv.conf")
                if resolv_conf.exists():
                    shutil.copy(resolv_conf, "/etc/resolv.conf.backup")

                # Write new resolv.conf
                with open(resolv_conf, 'w') as f:
                    f.write("# Managed by Squawk DNS\n")
                    f.write("nameserver 127.0.0.1\n")
                    f.write("# Fallback DNS servers\n")
                    f.write("nameserver 8.8.8.8\n")
                    f.write("nameserver 8.8.4.4\n")

    def start_service(self):
        """Start the installed service"""
        print("Starting service...")

        if self.system == "Windows":
            subprocess.run(["net", "start", "SquawkDNS"], check=False)
        elif self.system == "Darwin":
            subprocess.run(["launchctl", "start", "com.squawk.dns"], check=False)
        else:
            subprocess.run(["systemctl", "start", "squawk-dns.service"], check=False)

    def install(self):
        """Main installation process"""
        print(f"Squawk DNS Client Installer - {self.system}")
        print("=" * 50)

        if not self.is_admin:
            print("ERROR: This installer requires administrator/root privileges")
            if self.system == "Windows":
                print("Please run as Administrator")
            else:
                print("Please run with sudo")
            sys.exit(1)

        try:
            # Step 1: Install dependencies
            self.install_dependencies()

            # Step 2: Create directories
            self.create_directories()

            # Step 3: Copy files
            self.copy_files()

            # Step 4: Create configuration
            self.create_config()

            # Step 5: Install service/daemon
            if self.system == "Windows":
                self.install_windows_service()
            elif self.system == "Darwin":
                self.install_macos_daemon()
            else:
                self.install_systemd_service()

            # Step 6: Configure system DNS
            self.configure_system_dns()

            # Step 7: Start service
            self.start_service()

            print("\n" + "=" * 50)
            print("Installation completed successfully!")
            print(f"Configuration file: {self.config_path / 'config.yaml'}")
            print(f"Logs directory: {self.install_path / 'logs'}")
            print("\nThe DNS service is now running and your system is configured to use it.")
            print("\nTo configure the service, edit the configuration file and restart the service.")

            if self.system == "Windows":
                print("\nService management:")
                print("  Start: net start SquawkDNS")
                print("  Stop: net stop SquawkDNS")
                print("  Status: sc query SquawkDNS")
            elif self.system == "Darwin":
                print("\nService management:")
                print("  Start: sudo launchctl start com.squawk.dns")
                print("  Stop: sudo launchctl stop com.squawk.dns")
                print("  Status: sudo launchctl list | grep squawk")
            else:
                print("\nService management:")
                print("  Start: sudo systemctl start squawk-dns")
                print("  Stop: sudo systemctl stop squawk-dns")
                print("  Status: sudo systemctl status squawk-dns")
                print("  Logs: sudo journalctl -u squawk-dns -f")

        except Exception as e:
            print(f"\nERROR: Installation failed: {e}")
            sys.exit(1)

    def uninstall(self):
        """Uninstall the service"""
        print("Uninstalling Squawk DNS Client...")

        if not self.is_admin:
            print("ERROR: Uninstallation requires administrator/root privileges")
            sys.exit(1)

        try:
            # Stop and remove service
            if self.system == "Windows":
                subprocess.run(["net", "stop", "SquawkDNS"], check=False)
                subprocess.run([sys.executable, str(self.install_path / "service.py"), "remove"], check=False)
            elif self.system == "Darwin":
                subprocess.run(["launchctl", "stop", "com.squawk.dns"], check=False)
                subprocess.run(["launchctl", "unload", "/Library/LaunchDaemons/com.squawk.dns.plist"], check=False)
                Path("/Library/LaunchDaemons/com.squawk.dns.plist").unlink(missing_ok=True)
            else:
                subprocess.run(["systemctl", "stop", "squawk-dns.service"], check=False)
                subprocess.run(["systemctl", "disable", "squawk-dns.service"], check=False)
                Path("/etc/systemd/system/squawk-dns.service").unlink(missing_ok=True)
                subprocess.run(["systemctl", "daemon-reload"], check=False)

            # Restore DNS settings
            if self.system == "Linux" and Path("/etc/resolv.conf.backup").exists():
                shutil.move("/etc/resolv.conf.backup", "/etc/resolv.conf")

            # Remove directories
            if self.install_path.exists():
                shutil.rmtree(self.install_path)
            if self.config_path.exists():
                shutil.rmtree(self.config_path)

            print("Uninstallation completed successfully!")

        except Exception as e:
            print(f"ERROR: Uninstallation failed: {e}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Squawk DNS Client Installer")
    parser.add_argument('action', choices=['install', 'uninstall'],
                       help='Action to perform')
    parser.add_argument('--server-url', help='DNS server URL',
                       default=os.getenv('SQUAWK_SERVER_URL'))
    parser.add_argument('--auth-token', help='Authentication token',
                       default=os.getenv('SQUAWK_AUTH_TOKEN'))

    args = parser.parse_args()

    # Set environment variables if provided
    if args.server_url:
        os.environ['SQUAWK_SERVER_URL'] = args.server_url
    if args.auth_token:
        os.environ['SQUAWK_AUTH_TOKEN'] = args.auth_token

    installer = SquawkInstaller()

    if args.action == 'install':
        installer.install()
    else:
        installer.uninstall()

if __name__ == "__main__":
    main()
