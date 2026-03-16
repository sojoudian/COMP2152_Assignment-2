"""
Author: Ifrad Hossain
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# Import required modules
import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print Python version and operating system name
print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Dictionary mapping common port numbers to their well-known service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}




class NetworkTool:
    """Parent class representing a generic network tool."""

    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter allows us to control how the private
    # attribute self.__target is accessed and modified from outside the class.
    # The setter lets us add validation logic (such as rejecting empty strings)
    # before a value is assigned, which would not be possible with direct access.
    # This approach follows the principle of encapsulation, keeping the internal
    # data safe while providing a clean, attribute-like interface to the user.

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool using class PortScanner(NetworkTool),
# which means it automatically gains access to all of NetworkTool's methods and
# properties, including the __init__ constructor, the target property, and the
# destructor. For example, PortScanner calls super().__init__(target) in its own
# constructor to reuse the parent's initialization logic for storing the target
# as a private attribute, avoiding code duplication.

class PortScanner(NetworkTool):
    """Child class that inherits from NetworkTool and scans ports on a target machine."""

    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        """Scan a single port on the target machine."""
        # Q4: What would happen without try-except here?
        # Without try-except, if the program tried to connect to a port on a machine
        # that is unreachable or down, Python would raise an unhandled socket.error
        # exception, which would crash the entire thread and potentially the program.
        # The try-except block catches these network errors gracefully, allowing the
        # scanner to continue checking other ports instead of stopping on the first
        # failure. The finally block also ensures the socket is always closed.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        """Use a list comprehension to return only the tuples where the status is Open."""
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be scanned simultaneously rather than
    # waiting for each port's connection attempt to complete before moving on.
    # Each port scan has a 1-second timeout, so scanning 1024 ports one at a time
    # could take up to 1024 seconds (over 17 minutes) in the worst case. With
    # threading, all ports are scanned concurrently, reducing the total scan time
    # to roughly 1 second regardless of the number of ports.

    def scan_range(self, start_port, end_port):
        """Scan a range of ports using threads."""
        threads = []

        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def save_results(target, results):
    """Save scan results to a SQLite database."""
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)

        for port, status, service in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )

        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    """Load and display all past scan results from the database."""
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        for row in rows:
            scan_id, target, port, status, service, scan_date = row
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")

        conn.close()
    except (sqlite3.OperationalError, sqlite3.Error):
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    try:
        target_ip = input("Enter target IP address (default 127.0.0.1): ")
        if target_ip == "":
            target_ip = "127.0.0.1"

        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

        if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("Port must be between 1 and 1024.")
        else:
            scanner = PortScanner(target_ip)
            print(f"Scanning {target_ip} from port {start_port} to {end_port}...")

            scanner.scan_range(start_port, end_port)
            open_ports = scanner.get_open_ports()

            print(f"\n--- Scan Results for {target_ip} ---")
            for port, status, service in open_ports:
                print(f"Port {port}: {status} ({service})")
            print("------")
            print(f"Total open ports found: {len(open_ports)}")

            save_results(target_ip, scanner.scan_results)

            history = input("\nWould you like to see past scan history? (yes/no): ")
            if history.lower() == "yes":
                load_past_scans()
    except ValueError:
        print("Invalid input. Please enter a valid integer.")


# Q5: New Feature Proposal
# I would add a Port Risk Classifier feature that categorizes each open port by
# security risk level (HIGH, MEDIUM, or LOW). It would use a nested if-statement
# to check if the port number belongs to high-risk services (FTP, SSH, Telnet,
# RDP — ports 21, 22, 23, 3389), medium-risk services (SMTP, POP3, IMAP, MySQL
# — ports 25, 110, 143, 3306), or otherwise classify it as low risk. This would
# help system administrators quickly identify which open ports need immediate
# attention during a security audit.
# Diagram: See diagram_101587843.png in the repository root
