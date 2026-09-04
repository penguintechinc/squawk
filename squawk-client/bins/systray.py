#!/usr/bin/env python3

import pystray
from PIL import Image, ImageDraw
import threading
import sys
import os
import subprocess
import logging
import time
from client import DNSOverHTTPSClient, DNSForwarder, load_config


class DNSClientTray:
    def __init__(self, config_file=None):
        self.config_file = config_file
        self.config = {}
        self.dns_client = None
        self.forwarder = None
        self.forwarder_thread = None
        self.running = False
        self.health_monitor_thread = None
        self.health_check_running = False
        self.server_health = {"status": "unknown", "last_check": None, "failures": 0}
        self.original_dns_servers = self.get_system_dns_servers()
        self.dns_fallback_active = False

        if config_file:
            self.config = load_config(config_file)

        self.setup_logging()
        self.create_icon()

        # Start health monitoring
        self.start_health_monitoring()

    def setup_logging(self):
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    def create_image(self, health_status="unknown"):
        """Create a simple DNS icon for the system tray with health indicator"""
        width = 64
        height = 64
        image = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)

        # Choose main color based on health status
        if health_status == "healthy":
            main_color = (0, 200, 100, 255)  # Green
            outline_color = (0, 150, 75, 255)
        elif health_status == "degraded":
            main_color = (255, 200, 0, 255)  # Yellow
            outline_color = (200, 150, 0, 255)
        elif health_status == "unhealthy":
            main_color = (255, 100, 100, 255)  # Red
            outline_color = (200, 75, 75, 255)
        else:
            main_color = (128, 128, 128, 255)  # Gray
            outline_color = (96, 96, 96, 255)

        # Draw a simple DNS server icon (circle with network connections)
        # Main circle
        draw.ellipse([16, 16, 48, 48], fill=main_color, outline=outline_color, width=2)

        # DNS text
        try:
            from PIL import ImageFont

            font = ImageFont.load_default()
            draw.text((24, 26), "DNS", fill=(255, 255, 255, 255), font=font)
        except Exception:
            # If font loading fails, just draw simple lines
            draw.text((24, 26), "DNS", fill=(255, 255, 255, 255))

        # Network dots with health-based color
        dot_color = main_color
        for x, y in [(8, 8), (56, 8), (8, 56), (56, 56)]:
            draw.ellipse([x - 3, y - 3, x + 3, y + 3], fill=dot_color)
            # Lines to center
            draw.line([(x, y), (32, 32)], fill=(*dot_color[:3], 128), width=1)

        return image

    def create_icon(self):
        """Create the system tray icon"""
        self.icon = pystray.Icon(
            "squawk_dns",
            self.create_image(self.server_health["status"]),
            "Squawk DNS Client",
            menu=self.create_menu(),
        )

    def create_menu(self):
        """Create the system tray menu"""
        health_text = f"Server Health: {self.server_health['status'].title()}"
        fallback_text = "Restore Original DNS" if self.dns_fallback_active else "Fallback to Original DNS"

        return pystray.Menu(
            pystray.MenuItem(
                "Start DNS Service",
                self.start_service,
                enabled=lambda item: not self.running,
            ),
            pystray.MenuItem("Stop DNS Service", self.stop_service, enabled=lambda item: self.running),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(health_text, self.check_server_health_manual),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                fallback_text,
                self.toggle_dns_fallback,
                enabled=lambda item: len(self.original_dns_servers) > 0,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open Console", self.open_console),
            pystray.MenuItem("Settings", self.open_settings),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Status", self.show_status),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self.quit_app),
        )

    def start_service(self, icon=None, item=None):
        """Start the DNS forwarding service"""
        if self.running:
            return

        try:
            # Load configuration
            dns_server_url = self.config.get("dns_server_url", "https://dns.google/resolve")
            auth_token = self.config.get("auth_token")
            listen_udp = self.config.get("listen_udp", False)
            listen_tcp = self.config.get("listen_tcp", False)
            udp_port = self.config.get("udp_port", 53)
            tcp_port = self.config.get("tcp_port", 53)

            # Get mTLS configuration
            client_cert = self.config.get("client_cert")
            client_key = self.config.get("client_key")
            ca_cert = self.config.get("ca_cert")
            verify_ssl = self.config.get("verify_ssl", True)

            # Create DNS client and forwarder
            self.dns_client = DNSOverHTTPSClient(
                dns_server_url,
                auth_token,
                client_cert=client_cert,
                client_key=client_key,
                ca_cert=ca_cert,
                verify_ssl=verify_ssl,
            )
            self.forwarder = DNSForwarder(
                self.dns_client,
                udp_port=udp_port,
                tcp_port=tcp_port,
                listen_udp=listen_udp,
                listen_tcp=listen_tcp,
            )

            # Start forwarder in background thread
            if listen_udp or listen_tcp:
                self.forwarder_thread = threading.Thread(target=self.forwarder.start, daemon=True)
                self.forwarder_thread.start()

            self.running = True
            logging.info("DNS service started successfully")

            # Update icon to show active status
            self.update_icon_status(True)

            # Start health monitoring if not already running
            if not self.health_check_running:
                self.start_health_monitoring()

            # Update menu
            self.icon.menu = self.create_menu()

        except Exception as e:
            logging.error(f"Failed to start DNS service: {e}")
            self.show_notification("Error", f"Failed to start DNS service: {e}")

    def stop_service(self, icon=None, item=None):
        """Stop the DNS forwarding service"""
        if not self.running:
            return

        try:
            # Stop the service
            self.running = False

            # The threads will naturally exit when the service stops
            if self.forwarder_thread:
                self.forwarder_thread = None

            self.dns_client = None
            self.forwarder = None

            logging.info("DNS service stopped")

            # Update icon to show inactive status
            self.update_icon_status(False)

            # Stop health monitoring
            self.health_check_running = False

            # Update menu
            self.icon.menu = self.create_menu()

        except Exception as e:
            logging.error(f"Failed to stop DNS service: {e}")

    def update_icon_status(self, active):
        """Update the icon to reflect active/inactive status"""
        if active:
            health_status = self.server_health["status"]
        else:
            health_status = "unknown"

        # Create new image with health status
        image = self.create_image(health_status)
        draw = ImageDraw.Draw(image)

        # Add service status indicator dot
        if active:
            # Green dot for active service
            draw.ellipse([50, 50, 62, 62], fill=(0, 255, 0, 255))
        else:
            # Red dot for inactive service
            draw.ellipse([50, 50, 62, 62], fill=(255, 0, 0, 255))

        self.icon.icon = image

    def open_console(self, icon=None, item=None):
        """Open the web console"""
        import webbrowser

        console_url = self.config.get("console_url", "http://localhost:8080/dns_console")
        webbrowser.open(console_url)

    def open_settings(self, icon=None, item=None):
        """Open settings dialog or file"""
        if self.config_file and os.path.exists(self.config_file):
            # Open config file in default editor
            if sys.platform == "win32":
                os.startfile(self.config_file)
            elif sys.platform == "darwin":
                subprocess.run(["open", self.config_file])
            else:
                subprocess.run(["xdg-open", self.config_file])
        else:
            self.show_notification("Info", "No configuration file found")

    def show_status(self, icon=None, item=None):
        """Show current service status"""
        status = "Running" if self.running else "Stopped"
        server = self.config.get("dns_server_url", "Not configured")
        health = self.server_health["status"].title()
        last_check = self.server_health.get("last_check")
        failures = self.server_health.get("failures", 0)

        message = f"Service: {status}\nServer: {server}\nHealth: {health}"

        if last_check:
            message += f"\nLast Check: {last_check.strftime('%H:%M:%S')}"

        if failures > 0:
            message += f"\nFailures: {failures}"

        if self.dns_fallback_active:
            message += f"\nFallback: Active (using original DNS)"

        if self.original_dns_servers:
            message += f"\nOriginal DNS: {', '.join(self.original_dns_servers)}"

        if self.running and self.forwarder:
            if self.forwarder.listen_udp:
                message += f"\nUDP Port: {self.forwarder.udp_port}"
            if self.forwarder.listen_tcp:
                message += f"\nTCP Port: {self.forwarder.tcp_port}"

        self.show_notification("DNS Service Status", message)

    def show_notification(self, title, message):
        """Show a system notification"""
        if hasattr(self.icon, "notify"):
            self.icon.notify(message, title)
        else:
            logging.info(f"{title}: {message}")

    def start_health_monitoring(self):
        """Start background health monitoring"""
        if self.health_check_running:
            return

        self.health_check_running = True
        self.health_monitor_thread = threading.Thread(target=self._health_monitor_loop, daemon=True)
        self.health_monitor_thread.start()
        logging.info("Started DNS server health monitoring")

    def _health_monitor_loop(self):
        """Background loop for health monitoring"""
        while self.health_check_running:
            try:
                self._check_server_health()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logging.error(f"Health monitor error: {e}")
                time.sleep(30)

    def _check_server_health(self):
        """Check DNS server health"""
        if not self.running or not self.dns_client:
            self.server_health = {
                "status": "unknown",
                "last_check": time.time(),
                "failures": 0,
            }
            self.update_icon_status(self.running)
            return

        try:
            # Test DNS resolution with a simple query
            import requests

            # Get server URLs from config
            server_urls = self.config.get("dns_server_urls", [])
            if isinstance(server_urls, str):
                server_urls = [server_urls]
            elif not server_urls:
                server_url = self.config.get("dns_server_url")
                if server_url:
                    server_urls = [server_url]

            if not server_urls:
                self.server_health = {
                    "status": "unhealthy",
                    "last_check": time.time(),
                    "failures": self.server_health.get("failures", 0) + 1,
                }
                self._handle_server_failure("No DNS servers configured")
                return

            healthy_servers = 0
            total_servers = len(server_urls)

            for server_url in server_urls:
                try:
                    # Build test query URL
                    if "/resolve" in server_url or "dns.google" in server_url:
                        test_url = f"{server_url}?name=google.com&type=A"
                    else:
                        test_url = f"{server_url}?name=google.com&type=A"

                    # Make request with timeout
                    response = requests.get(
                        test_url,
                        timeout=5,
                        headers={
                            "Authorization": f"Bearer {self.config.get('auth_token', '')}",
                            "User-Agent": "Squawk-DNS-Client/1.1.1",
                        },
                    )

                    if response.status_code == 200:
                        healthy_servers += 1

                except Exception as e:
                    logging.debug(f"Health check failed for {server_url}: {e}")
                    continue

            # Determine overall health
            if healthy_servers == 0:
                new_status = "unhealthy"
                failures = self.server_health.get("failures", 0) + 1
                self._handle_server_failure(f"All {total_servers} DNS servers are unreachable")
            elif healthy_servers < total_servers:
                new_status = "degraded"
                failures = max(0, self.server_health.get("failures", 0) - 1)  # Reduce failures but don't go negative
            else:
                new_status = "healthy"
                failures = 0
                # Clear any previous failure notifications
                if self.server_health.get("status") in ["unhealthy", "degraded"]:
                    self.show_notification(
                        "DNS Servers Recovered",
                        f"All {total_servers} DNS servers are now healthy",
                    )

            # Update health status
            old_status = self.server_health.get("status")
            self.server_health = {
                "status": new_status,
                "last_check": time.time(),
                "failures": failures,
                "healthy_servers": healthy_servers,
                "total_servers": total_servers,
            }

            # Update icon if status changed
            if old_status != new_status:
                self.update_icon_status(self.running)
                self.icon.menu = self.create_menu()
                logging.info(f"DNS server health changed: {old_status} -> {new_status}")

        except Exception as e:
            logging.error(f"Health check error: {e}")
            self.server_health = {
                "status": "unknown",
                "last_check": time.time(),
                "failures": self.server_health.get("failures", 0) + 1,
            }
            self.update_icon_status(self.running)

    def _handle_server_failure(self, message):
        """Handle DNS server failure with notification"""
        failures = self.server_health.get("failures", 0)

        # Show notification on first failure or every 5th failure to avoid spam
        if failures <= 1 or failures % 5 == 0:
            self.show_notification("DNS Server Alert", f"{message}\n\nFailure count: {failures}")

        logging.warning(f"DNS server failure: {message} (failure #{failures})")
        self.update_icon_status(self.running)

    def get_system_dns_servers(self):
        """Get the original DNS servers from system configuration"""
        dns_servers = []

        try:
            if sys.platform == "win32":
                # Windows: Use nslookup to get DNS servers
                result = subprocess.run(["nslookup"], input="\n", text=True, capture_output=True, timeout=5)
                for line in result.stdout.split("\n"):
                    if "Default Server:" in line or "Address:" in line:
                        # Extract IP address
                        import re

                        ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", line)
                        if ip_match:
                            dns_servers.append(ip_match.group())

            elif sys.platform == "darwin":
                # macOS: Use scutil to get DNS servers
                result = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, timeout=5)
                import re

                dns_servers = re.findall(r"nameserver\[\d+\] : ([0-9.]+)", result.stdout)

            else:
                # Linux: Check common DNS configuration locations
                dns_files = ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"]
                for dns_file in dns_files:
                    if os.path.exists(dns_file):
                        with open(dns_file, "r") as f:
                            for line in f:
                                if line.strip().startswith("nameserver"):
                                    parts = line.strip().split()
                                    if len(parts) >= 2:
                                        dns_servers.append(parts[1])
                        if dns_servers:
                            break

            # Remove duplicates and localhost addresses
            dns_servers = list(dict.fromkeys(dns_servers))  # Remove duplicates
            dns_servers = [dns for dns in dns_servers if not dns.startswith("127.") and dns != "::1"]

        except Exception as e:
            logging.error(f"Failed to get system DNS servers: {e}")

        logging.info(f"Detected original DNS servers: {dns_servers}")
        return dns_servers

    def set_system_dns_servers(self, dns_servers):
        """Set system DNS servers"""
        try:
            if sys.platform == "win32":
                # Windows: Use netsh to set DNS servers
                # Get network interface name
                result = subprocess.run(
                    ["netsh", "interface", "show", "interface"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                # Find the first connected interface
                interface_name = None
                for line in result.stdout.split("\n"):
                    if "Connected" in line and "Dedicated" in line:
                        parts = line.split()
                        interface_name = " ".join(parts[3:])
                        break

                if interface_name:
                    if dns_servers:
                        # Set primary DNS
                        subprocess.run(
                            [
                                "netsh",
                                "interface",
                                "ip",
                                "set",
                                "dns",
                                interface_name,
                                "static",
                                dns_servers[0],
                            ],
                            capture_output=True,
                            timeout=10,
                        )
                        # Set secondary DNS if available
                        if len(dns_servers) > 1:
                            subprocess.run(
                                [
                                    "netsh",
                                    "interface",
                                    "ip",
                                    "add",
                                    "dns",
                                    interface_name,
                                    dns_servers[1],
                                    "index=2",
                                ],
                                capture_output=True,
                                timeout=10,
                            )
                    else:
                        # Reset to DHCP
                        subprocess.run(
                            [
                                "netsh",
                                "interface",
                                "ip",
                                "set",
                                "dns",
                                interface_name,
                                "dhcp",
                            ],
                            capture_output=True,
                            timeout=10,
                        )

            elif sys.platform == "darwin":
                # macOS: Use networksetup to set DNS servers
                # Get network interfaces
                result = subprocess.run(
                    ["networksetup", "-listallnetworkservices"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                interfaces = [
                    line.strip() for line in result.stdout.split("\n") if line.strip() and not line.startswith("*")
                ]

                for interface in interfaces[:2]:  # Try first two interfaces
                    try:
                        if dns_servers:
                            subprocess.run(
                                ["networksetup", "-setdnsservers", interface] + dns_servers,
                                capture_output=True,
                                timeout=10,
                            )
                        else:
                            subprocess.run(
                                ["networksetup", "-setdnsservers", interface, "empty"],
                                capture_output=True,
                                timeout=10,
                            )
                    except (OSError, subprocess.SubprocessError):
                        continue

            else:
                # Linux: This typically requires root privileges
                # We'll show a notification with instructions instead
                self.show_notification(
                    "DNS Fallback",
                    "Manual DNS change required on Linux.\n"
                    + "Please run as root:\n"
                    + f"echo 'nameserver {dns_servers[0] if dns_servers else '8.8.8.8'}' > /etc/resolv.conf",
                )
                return False

        except Exception as e:
            logging.error(f"Failed to set system DNS servers: {e}")
            return False

        return True

    def toggle_dns_fallback(self, icon=None, item=None):
        """Toggle between custom DNS and original DHCP DNS"""
        if not self.original_dns_servers:
            self.show_notification("DNS Fallback", "No original DNS servers detected")
            return

        try:
            if self.dns_fallback_active:
                # Restore to localhost (our DNS service)
                success = self.set_system_dns_servers(["127.0.0.1"])
                if success:
                    self.dns_fallback_active = False
                    self.show_notification("DNS Restored", "Switched back to Squawk DNS service")
                    logging.info("Restored system DNS to use Squawk service")
                else:
                    self.show_notification("DNS Change Failed", "Could not restore DNS settings")
            else:
                # Fallback to original DNS servers
                success = self.set_system_dns_servers(self.original_dns_servers)
                if success:
                    self.dns_fallback_active = True
                    servers_text = ", ".join(self.original_dns_servers[:2])
                    self.show_notification(
                        "DNS Fallback Active",
                        f"Using original DNS servers:\n{servers_text}",
                    )
                    logging.info(f"Switched to original DNS servers: {self.original_dns_servers}")
                else:
                    self.show_notification("DNS Change Failed", "Could not change DNS settings")

        except Exception as e:
            logging.error(f"DNS fallback toggle failed: {e}")
            self.show_notification("DNS Fallback Error", f"Failed to change DNS settings: {e}")

        # Update menu
        self.icon.menu = self.create_menu()

    def check_server_health_manual(self, icon=None, item=None):
        """Manually trigger server health check"""
        if not self.running:
            self.show_notification("Health Check", "DNS service is not running")
            return

        # Run health check in background thread to avoid blocking UI
        threading.Thread(target=self._check_server_health, daemon=True).start()
        self.show_notification("Health Check", "Checking DNS server health...")

    def quit_app(self, icon=None, item=None):
        """Quit the application"""
        self.health_check_running = False

        # Restore original DNS if fallback is active
        if self.dns_fallback_active:
            try:
                self.set_system_dns_servers(["127.0.0.1"])  # Restore to localhost
                logging.info("Restored DNS settings on exit")
            except Exception as e:
                logging.error(f"Failed to restore DNS on exit: {e}")

        self.stop_service()
        self.icon.stop()
        sys.exit(0)

    def run(self):
        """Run the system tray application"""
        # Auto-start service if configured
        if self.config.get("auto_start", False):
            self.start_service()

        self.icon.run()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Squawk DNS Client System Tray")
    parser.add_argument("-c", "--config", help="Configuration file path")
    args = parser.parse_args()

    app = DNSClientTray(config_file=args.config)
    app.run()


if __name__ == "__main__":
    main()
