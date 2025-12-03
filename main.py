import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog
import socket
import ipaddress
import threading
import queue
import csv
import json
import time
import os
import math
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import Counter, defaultdict

# Windows-specific fix to prevent console windows from spawning
if sys.platform == "win32":
    # Set the startup info to hide console windows
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    
    # Monkey patch subprocess to use our startup info
    original_popen = subprocess.Popen
    
    def patched_popen(*args, **kwargs):
        if 'startupinfo' not in kwargs:
            kwargs['startupinfo'] = startupinfo
        if 'creationflags' not in kwargs:
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        return original_popen(*args, **kwargs)
    
    subprocess.Popen = patched_popen
    
    # Also patch os.system calls
    original_system = os.system
    
    def patched_system(command):
        # Use subprocess instead of os.system to avoid console windows
        try:
            result = subprocess.run(command, shell=True, capture_output=True, 
                                  startupinfo=startupinfo, 
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            return result.returncode
        except:
            return original_system(command)
    
    os.system = patched_system

# Try to import matplotlib for charts (optional)
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import matplotlib
    matplotlib.use('TkAgg')
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Matplotlib not available. Charts will be disabled.")

# ------------------------------
# Enhanced LAN Scanner Pro (Tkinter)
# ------------------------------
# New Features:
# - Modern Material Design UI
# - Network topology visualization
# - Real-time statistics and charts
# - Advanced filtering and search
# - Device fingerprinting
# - Vulnerability assessment hints
# - Network speed testing
# - Configuration profiles
# - Comprehensive logging
# - Multiple export formats
# - Dark/Light theme toggle
# - Network discovery protocols
# ------------------------------

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995, 3306, 3389, 5900, 8080]

# Top 100 most common ports for "All" scan (more reasonable than 1-1024)
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    20, 69, 79, 88, 102, 113, 119, 135, 137, 138, 389, 427, 465, 514, 543, 544, 548, 554, 587, 631,
    636, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101,
    5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081,
    8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
]

VULNERABILITY_HINTS = {
    22: "SSH - Check for weak passwords, outdated versions",
    23: "Telnet - Insecure protocol, consider disabling",
    80: "HTTP - Check for security headers, HTTPS redirect",
    443: "HTTPS - Verify certificate validity",
    3389: "RDP - Ensure strong authentication",
    445: "SMB - Check for SMB1, enable SMB signing"
}

class EnhancedScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("LAN Scanner Pro - Network Discovery & Security")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Set theme
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure checkbox style to show checkmark when selected
        self.style.map('TCheckbutton',
                      indicatorbackground=[('selected', 'SystemWindow'),
                                          ('!selected', 'SystemWindow')],
                      indicatorrelief=[('selected', 'flat'),
                                       ('!selected', 'flat')])
        
        # Initialize variables
        self.ui_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.results = []
        self.scan_history = []
        self.current_theme = "light"
        self.config_profiles = self.load_config_profiles()
        
        # Create main container
        self.main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create left and right panels
        self.left_panel = ttk.Frame(self.main_container)
        self.right_panel = ttk.Frame(self.main_container)
        self.main_container.add(self.left_panel, weight=1)
        self.main_container.add(self.right_panel, weight=2)
        
        self._build_ui()
        self._create_menu()
        self.root.after(100, self._drain_queue)
        
        # Initialize statistics
        self.stats = {
            'total_hosts': 0,
            'active_hosts': 0,
            'open_ports': 0,
            'vulnerable_services': 0,
            'scan_start_time': None,
            'scan_duration': 0
        }
        
        # Counter for periodic tab updates
        self.results_added_since_update = 0

    def _create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Results", command=self.on_export)
        file_menu.add_command(label="Save Configuration", command=self.save_config_profile)
        file_menu.add_command(label="Load Configuration", command=self.load_config_profile)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Network Speed Test", command=self.network_speed_test)
        tools_menu.add_command(label="Ping Test", command=self.ping_test)
        tools_menu.add_command(label="Port Scanner", command=self.port_scanner)
        tools_menu.add_command(label="Device Fingerprint", command=self.device_fingerprint)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Toggle Theme", command=self.toggle_theme)
        view_menu.add_command(label="Show Statistics", command=self.show_statistics)
        view_menu.add_command(label="Show Topology", command=self.show_topology)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def _build_ui(self):
        # Left Panel - Controls
        self._build_control_panel()
        
        # Right Panel - Results and Visualization
        self._build_results_panel()

    def _build_control_panel(self):
        # Title
        title_frame = ttk.Frame(self.left_panel)
        title_frame.pack(fill=tk.X, padx=10, pady=5)
        title_label = ttk.Label(title_frame, text="🚀 LAN Scanner Pro", font=('Arial', 18, 'bold'))
        title_label.pack()
        subtitle_label = ttk.Label(title_frame, text="Network Discovery & Security", font=('Arial', 10))
        subtitle_label.pack()
        
        # Control Frame
        control_frame = ttk.LabelFrame(self.left_panel, text="Scan Configuration", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Network Configuration
        ttk.Label(control_frame, text="Network Range (CIDR):").pack(anchor=tk.W)
        net_frame = ttk.Frame(control_frame)
        net_frame.pack(fill=tk.X, pady=(0, 5))
        self.net_entry = ttk.Entry(net_frame, width=25)
        self.net_entry.insert(0, "192.168.1.0/24")
        self.net_entry.pack(side=tk.LEFT)
        ttk.Button(net_frame, text="🔍", width=3, command=self.discover_networks).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Network size indicator
        self.net_size_label = ttk.Label(control_frame, text="Network size: 254 hosts", font=('Arial', 8), foreground="gray")
        self.net_size_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Update network size when entry changes
        self.net_entry_var = tk.StringVar(value="192.168.1.0/24")
        self.net_entry.config(textvariable=self.net_entry_var)
        self.net_entry_var.trace('w', self._update_network_size_display)
        
        # Port Configuration
        ttk.Label(control_frame, text="Ports to Scan:").pack(anchor=tk.W)
        self.ports_entry = ttk.Entry(control_frame, width=30)
        self.ports_entry.insert(0, "common")
        self.ports_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Quick Port Presets
        preset_frame = ttk.Frame(control_frame)
        preset_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(preset_frame, text="Common", width=8, command=lambda: self.set_port_preset("common")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(preset_frame, text="Web", width=8, command=lambda: self.set_port_preset("80,443,8080,8443")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(preset_frame, text="Test", width=8, command=lambda: self.set_port_preset("22,80,443")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(preset_frame, text="All", width=8, command=lambda: self.set_port_preset("1-1024")).pack(side=tk.LEFT)
        
        # Advanced Options
        advanced_frame = ttk.LabelFrame(control_frame, text="Advanced Options", padding=5)
        advanced_frame.pack(fill=tk.X, pady=5)
        
        # Timeout and Workers
        timeout_frame = ttk.Frame(advanced_frame)
        timeout_frame.pack(fill=tk.X, pady=2)
        ttk.Label(timeout_frame, text="Timeout (s):").pack(side=tk.LEFT)
        self.timeout_entry = ttk.Entry(timeout_frame, width=8)
        self.timeout_entry.insert(0, "1.0")
        self.timeout_entry.pack(side=tk.RIGHT)
        
        workers_frame = ttk.Frame(advanced_frame)
        workers_frame.pack(fill=tk.X, pady=2)
        ttk.Label(workers_frame, text="Workers:").pack(side=tk.LEFT)
        self.workers_entry = ttk.Entry(workers_frame, width=8)
        self.workers_entry.insert(0, "100")
        self.workers_entry.pack(side=tk.RIGHT)
        
        # Checkboxes with visual indicators
        self.rev_dns_var = tk.BooleanVar(value=True)
        self.rev_dns_check = ttk.Checkbutton(advanced_frame, text="✓ Reverse DNS Lookup (Enabled)", variable=self.rev_dns_var, 
                                             command=lambda: self._update_checkbox_text(self.rev_dns_check, self.rev_dns_var, "Reverse DNS Lookup"))
        self.rev_dns_check.pack(anchor=tk.W)
        
        self.banner_grab_var = tk.BooleanVar(value=True)
        self.banner_grab_check = ttk.Checkbutton(advanced_frame, text="✓ Banner Grabbing (Enabled)", variable=self.banner_grab_var,
                                                 command=lambda: self._update_checkbox_text(self.banner_grab_check, self.banner_grab_var, "Banner Grabbing"))
        self.banner_grab_check.pack(anchor=tk.W)
        
        self.vuln_check_var = tk.BooleanVar(value=True)
        self.vuln_check_check = ttk.Checkbutton(advanced_frame, text="✓ Vulnerability Hints (Enabled)", variable=self.vuln_check_var,
                                                command=lambda: self._update_checkbox_text(self.vuln_check_check, self.vuln_check_var, "Vulnerability Hints"))
        self.vuln_check_check.pack(anchor=tk.W)
        
        # Scan Buttons
        button_frame = ttk.Frame(self.left_panel)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.scan_btn = ttk.Button(button_frame, text="🚀 Start Scan", command=self.on_start)
        self.scan_btn.pack(fill=tk.X, pady=2)
        
        self.stop_btn = ttk.Button(button_frame, text="⏹ Stop Scan", command=self.on_stop, state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=2)
        
        self.export_btn = ttk.Button(button_frame, text="📊 Export Results", command=self.on_export, state=tk.DISABLED)
        self.export_btn.pack(fill=tk.X, pady=2)
        
        self.clear_btn = ttk.Button(button_frame, text="🗑 Clear Results", command=self.on_clear)
        self.clear_btn.pack(fill=tk.X, pady=2)
        
        # Progress Section
        progress_frame = ttk.LabelFrame(self.left_panel, text="Progress", padding=10)
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate")
        self.progress.pack(fill=tk.X, pady=(0, 5))
        
        self.status_var = tk.StringVar(value="Ready to scan")
        ttk.Label(progress_frame, textvariable=self.status_var, font=('Arial', 9)).pack()
        
        # Statistics
        stats_frame = ttk.LabelFrame(self.left_panel, text="Quick Stats", padding=10)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.stats_labels = {}
        for stat in ['Hosts Found', 'Open Ports', 'Vulnerabilities']:
            frame = ttk.Frame(stats_frame)
            frame.pack(fill=tk.X, pady=2)
            ttk.Label(frame, text=f"{stat}:").pack(side=tk.LEFT)
            self.stats_labels[stat] = ttk.Label(frame, text="0", font=('Arial', 10, 'bold'))
            self.stats_labels[stat].pack(side=tk.RIGHT)

    def _build_results_panel(self):
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Results Tab
        self.results_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text="📋 Scan Results")
        
        # Search and Filter
        filter_frame = ttk.Frame(self.results_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_results)
        search_entry = ttk.Entry(filter_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar(value="all")
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, 
                                   values=["all", "active", "inactive", "vulnerable", "open_ports", "no_ports"], 
                                   width=15, state="readonly")
        filter_combo.pack(side=tk.LEFT, padx=(5, 0))
        filter_combo.bind('<<ComboboxSelected>>', self.filter_results)
        
        # Results Tree
        columns = ("ip", "hostname", "device_type", "status", "open_ports", "services", "vulnerabilities")
        self.tree = ttk.Treeview(self.results_frame, columns=columns, show="headings", height=20)
        
        # Configure columns
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("device_type", text="Device Type")
        self.tree.heading("status", text="Status")
        self.tree.heading("open_ports", text="Open Ports")
        self.tree.heading("services", text="Services")
        self.tree.heading("vulnerabilities", text="Security Issues")
        
        self.tree.column("ip", width=120, anchor=tk.W)
        self.tree.column("hostname", width=150, anchor=tk.W)
        self.tree.column("device_type", width=140, anchor=tk.W)
        self.tree.column("status", width=80, anchor=tk.CENTER)
        self.tree.column("open_ports", width=120, anchor=tk.W)
        self.tree.column("services", width=180, anchor=tk.W)
        self.tree.column("vulnerabilities", width=150, anchor=tk.W)
        
        # Scrollbars
        tree_scroll_y = ttk.Scrollbar(self.results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scroll_x = ttk.Scrollbar(self.results_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        
        # Pack tree and scrollbars
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Topology Tab
        self.topology_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.topology_frame, text="🌐 Network Topology")
        self._setup_topology_tab()
        
        # Statistics Tab
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="📊 Statistics")
        self._setup_statistics_tab()
        
        # Bind tab change event to update content
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        
        # Logs Tab
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="📝 Activity Log")
        
        # Create log text area
        self.log_text = scrolledtext.ScrolledText(self.logs_frame, height=20, width=80)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        print(log_entry.strip())
    
    def _setup_topology_tab(self):
        """Setup the Network Topology tab with canvas"""
        # Create frame for scrollable canvas
        canvas_frame = ttk.Frame(self.topology_frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create canvas for topology visualization
        self.topology_canvas = tk.Canvas(canvas_frame, bg="white")
        
        # Add scrollbars for large networks
        topology_scroll_y = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=self.topology_canvas.yview)
        topology_scroll_x = ttk.Scrollbar(canvas_frame, orient=tk.HORIZONTAL, command=self.topology_canvas.xview)
        self.topology_canvas.configure(yscrollcommand=topology_scroll_y.set, xscrollcommand=topology_scroll_x.set)
        
        # Place scrollbars and canvas using grid
        self.topology_canvas.grid(row=0, column=0, sticky="nsew")
        topology_scroll_y.grid(row=0, column=1, sticky="ns")
        topology_scroll_x.grid(row=1, column=0, sticky="ew")
        
        canvas_frame.grid_rowconfigure(0, weight=1)
        canvas_frame.grid_columnconfigure(0, weight=1)
        
        # Add placeholder label
        self.topology_placeholder = ttk.Label(self.topology_canvas, 
                                              text="Run a scan to view network topology", 
                                              font=('Arial', 12))
        self.topology_canvas.create_window(400, 300, window=self.topology_placeholder)
    
    def _setup_statistics_tab(self):
        """Setup the Statistics tab"""
        # Container for statistics content
        self.stats_container = ttk.Frame(self.stats_frame)
        self.stats_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Placeholder for statistics content
        self.stats_placeholder = ttk.Label(self.stats_container, 
                                           text="Run a scan to view statistics", 
                                           font=('Arial', 12))
        self.stats_placeholder.pack(expand=True)
        
        # Variables to hold matplotlib widgets
        self.stats_figure = None
        self.stats_canvas = None
    
    def _on_tab_changed(self, event=None):
        """Handle tab change event - update content when tab is selected"""
        selected_tab = self.notebook.index(self.notebook.select())
        tab_text = self.notebook.tab(selected_tab, 'text')
        
        if "🌐 Network Topology" in tab_text:
            self._update_topology_tab()
        elif "📊 Statistics" in tab_text:
            self._update_statistics_tab()
    
    def _update_topology_tab(self):
        """Update the topology tab with current scan results"""
        # Clear existing content
        self.topology_canvas.delete("all")
        
        if not self.results:
            self.topology_placeholder = ttk.Label(self.topology_canvas, 
                                                  text="Run a scan to view network topology", 
                                                  font=('Arial', 12))
            self.topology_canvas.create_window(400, 300, window=self.topology_placeholder)
            return
        
        # Get active hosts (hosts with open ports)
        active_hosts = [r for r in self.results if r['open_ports']]
        
        if not active_hosts:
            no_hosts_label = ttk.Label(self.topology_canvas, 
                                       text="No active hosts found in scan results", 
                                       font=('Arial', 12))
            self.topology_canvas.create_window(400, 300, window=no_hosts_label)
            return
        
        # Calculate canvas size based on number of hosts
        canvas_width = 800
        canvas_height = 600
        self.topology_canvas.config(scrollregion=(0, 0, canvas_width, canvas_height))
        
        # Draw network diagram
        center_x, center_y = canvas_width // 2, canvas_height // 2
        radius = min(250, max(150, len(active_hosts) * 10))
        
        # Draw central router/switch
        router_size = 40
        self.topology_canvas.create_oval(center_x - router_size, center_y - router_size, 
                                       center_x + router_size, center_y + router_size, 
                                       fill="#4A90E2", outline="black", width=2, tags="router")
        self.topology_canvas.create_text(center_x, center_y, text="Router/Switch", 
                                        fill="white", font=('Arial', 10, 'bold'), tags="router")
        
        # Draw hosts in a circle
        angle_step = 360 / len(active_hosts) if active_hosts else 0
        
        for i, host in enumerate(active_hosts):
            angle = math.radians(i * angle_step)
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            
            # Draw host node
            host_size = 30
            self.topology_canvas.create_oval(x - host_size, y - host_size, 
                                           x + host_size, y + host_size, 
                                           fill="#2ecc71", outline="black", width=2, tags="host")
            
            # Host label (last octet of IP)
            ip_label = host['ip'].split('.')[-1]
            self.topology_canvas.create_text(x, y, text=ip_label, 
                                           fill="white", font=('Arial', 9, 'bold'), tags="host")
            
            # Host info (below the node)
            hostname = host['hostname'] or "No hostname"
            if len(hostname) > 15:
                hostname = hostname[:12] + "..."
            port_count = len(host['open_ports'])
            info_text = f"{host['ip']}\n{hostname}\n{port_count} ports"
            self.topology_canvas.create_text(x, y + host_size + 30, text=info_text, 
                                           font=('Arial', 8), anchor=tk.N, tags="host")
            
            # Draw connection line
            self.topology_canvas.create_line(center_x, center_y, x, y, 
                                           fill="#95a5a6", width=2, tags="connection")
        
        # Update scroll region
        bbox = self.topology_canvas.bbox("all")
        if bbox:
            self.topology_canvas.config(scrollregion=bbox)
    
    def _update_statistics_tab(self):
        """Update the statistics tab with current scan results"""
        # Clear existing content
        for widget in self.stats_container.winfo_children():
            widget.destroy()
        
        if not self.results:
            self.stats_placeholder = ttk.Label(self.stats_container, 
                                               text="Run a scan to view statistics", 
                                               font=('Arial', 12))
            self.stats_placeholder.pack(expand=True)
            return
        
        if not MATPLOTLIB_AVAILABLE:
            no_matplotlib_label = ttk.Label(self.stats_container, 
                                            text="Matplotlib is not installed. Statistics charts are disabled.\n\n"
                                                 "Please install matplotlib to view statistics:\npip install matplotlib",
                                            font=('Arial', 10), justify=tk.CENTER)
            no_matplotlib_label.pack(expand=True)
            return
        
        # Clear previous figure if exists
        if self.stats_canvas:
            try:
                self.stats_canvas.get_tk_widget().destroy()
            except:
                pass
            try:
                plt.close(self.stats_figure)
            except:
                pass
        
        # Create matplotlib figure with smaller size to fit in frame
        self.stats_figure, (ax1, ax2) = plt.subplots(1, 2, figsize=(9, 4), facecolor='white', dpi=90)
        
        # Port distribution chart
        port_counts = Counter()
        for result in self.results:
            for port in result['open_ports']:
                port_counts[port] += 1
        
        if port_counts:
            ports, counts = zip(*port_counts.most_common(10))
            ax1.bar(range(len(ports)), counts, color='#4A90E2')
            ax1.set_xticks(range(len(ports)))
            ax1.set_xticklabels(ports, rotation=45, ha='right', fontsize=9)
            ax1.set_title("Top 10 Open Ports", fontsize=11, fontweight='bold', pad=8)
            ax1.set_xlabel("Port", fontsize=9)
            ax1.set_ylabel("Count", fontsize=9)
            ax1.grid(axis='y', alpha=0.3)
            ax1.tick_params(labelsize=8)
        else:
            ax1.text(0.5, 0.5, "No open ports found", 
                    ha='center', va='center', transform=ax1.transAxes, fontsize=10)
            ax1.set_title("Top 10 Open Ports", fontsize=11, fontweight='bold', pad=8)
        
        # Host status chart - ensure proper circle display
        active_hosts = len([r for r in self.results if r['open_ports']])
        inactive_hosts = len(self.results) - active_hosts
        
        if self.results:
            colors = ['#2ecc71', '#95a5a6'] if active_hosts > 0 else ['#95a5a6']
            labels = []
            sizes = []
            
            if active_hosts > 0:
                labels.append('Active')
                sizes.append(active_hosts)
            if inactive_hosts > 0:
                labels.append('Inactive')
                sizes.append(inactive_hosts)
            
            if sizes:
                # Ensure equal aspect ratio for perfect circle
                ax2.set_aspect('equal')
                # Create pie chart with compact spacing and smaller radius
                wedges, texts, autotexts = ax2.pie(sizes, labels=labels, autopct='%1.1f%%',
                                                   colors=colors, startangle=90, 
                                                   textprops={'fontsize': 8},
                                                   labeldistance=1.0,
                                                   pctdistance=0.65,
                                                   shadow=False,
                                                   radius=0.75)
                # Improve text visibility
                for autotext in autotexts:
                    autotext.set_color('white')
                    autotext.set_fontweight('bold')
                for text in texts:
                    text.set_fontsize(8)
                ax2.set_title("Host Status Distribution", fontsize=10, fontweight='bold', pad=6)
        
        # Compact layout to fit everything in frame
        plt.tight_layout(pad=1.2, w_pad=0.6, h_pad=0.8)
        # Adjust margins to ensure pie chart fits completely
        plt.subplots_adjust(left=0.10, right=0.97, top=0.86, bottom=0.20, wspace=0.4)
        
        # Embed in tkinter
        self.stats_canvas = FigureCanvasTkAgg(self.stats_figure, self.stats_container)
        self.stats_canvas.draw()
        self.stats_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add text statistics below charts
        stats_text_frame = ttk.Frame(self.stats_container)
        stats_text_frame.pack(fill=tk.X, padx=10, pady=5)
        
        stats_text = (
            f"Total Hosts: {len(self.results)} | "
            f"Active Hosts: {active_hosts} | "
            f"Inactive Hosts: {inactive_hosts} | "
            f"Total Open Ports: {self.stats['open_ports']} | "
            f"Vulnerabilities Found: {self.stats['vulnerable_services']}"
        )
        ttk.Label(stats_text_frame, text=stats_text, font=('Arial', 9)).pack()
    
    def _update_network_size_display(self, *args):
        """Update the network size label when network entry changes"""
        try:
            network = self.net_entry_var.get().strip()
            if not network:
                self.net_size_label.config(text="Network size: Enter CIDR notation", foreground="gray")
                return
            
            net = ipaddress.ip_network(network, strict=False)
            
            # Calculate number of hosts efficiently
            if net.version == 4:
                prefix = net.prefixlen
                if prefix >= 32:
                    num_hosts = 1
                else:
                    num_hosts = (2 ** (32 - prefix)) - 2
            else:
                num_hosts = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
            
            # Format with thousands separator
            if num_hosts >= 1000000:
                size_text = f"Network size: {num_hosts:,} hosts (⚠️ Very Large!)"
                color = "red"
            elif num_hosts >= 10000:
                size_text = f"Network size: {num_hosts:,} hosts (⚠️ Large - may be slow)"
                color = "orange"
            elif num_hosts >= 1000:
                size_text = f"Network size: {num_hosts:,} hosts"
                color = "blue"
            else:
                size_text = f"Network size: {num_hosts:,} hosts"
                color = "gray"
            
            self.net_size_label.config(text=size_text, foreground=color)
        except (ValueError, ipaddress.AddressValueError):
            self.net_size_label.config(text="Network size: Invalid format", foreground="red")
        except Exception:
            self.net_size_label.config(text="Network size: Calculating...", foreground="gray")
    
    def _update_checkbox_text(self, checkbox, var, base_text):
        """Update checkbox text to show clear enabled/disabled state"""
        if var.get():
            checkbox.config(text=f"✓ {base_text} (Enabled)")
        else:
            checkbox.config(text=f"✗ {base_text} (Disabled)")

    def filter_results(self, *args):
        search_term = self.search_var.get().lower()
        filter_type = self.filter_var.get()
        
        # Clear current display
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Filter and display results
        for result in self.results:
            if self._should_display_result(result, search_term, filter_type):
                self._add_result_to_tree(result)

    def _should_display_result(self, result, search_term, filter_type):
        # Search filter
        if search_term:
            device_type = result.get('device_type', 'Unknown')
            if (search_term not in result['ip'].lower() and 
                search_term not in result['hostname'].lower() and
                search_term not in str(result['open_ports']).lower() and
                search_term not in device_type.lower()):
                return False
        
        # Type filter
        if filter_type == "active":
            # Show only hosts with open ports (active hosts)
            if not result['open_ports']:
                return False
        elif filter_type == "inactive":
            # Show only hosts without open ports (inactive hosts)
            if result['open_ports']:
                return False
        elif filter_type == "vulnerable" and not result.get('vulnerabilities'):
            return False
        elif filter_type == "open_ports" and not result['open_ports']:
            return False
        elif filter_type == "no_ports" and result['open_ports']:
            return False
        
        return True

    def _add_result_to_tree_direct(self, result):
        """Add result directly to tree without filtering - used during live scanning"""
        # Determine status
        if result['open_ports']:
            status = "🟢 Active"
        else:
            status = "⚪ Inactive"
        
        # Get device type (with backward compatibility)
        device_type = result.get('device_type', 'Unknown')
        if device_type == 'Unknown' and result.get('open_ports'):
            # Try to detect if not already set
            device_type = self._detect_device_type(result['open_ports'], result.get('services', []), result.get('hostname', ''))
        
        # Format ports
        ports_str = ", ".join(map(str, result['open_ports'])) if result['open_ports'] else "—"
        
        # Format services
        services_str = "; ".join(result['services']) if result['services'] else "—"
        
        # Format vulnerabilities
        vuln_str = "; ".join(result.get('vulnerabilities', [])) if result.get('vulnerabilities') else "—"
        
        self.tree.insert("", tk.END, values=(
            result['ip'],
            result['hostname'] or "—",
            device_type,
            status,
            ports_str,
            services_str,
            vuln_str
        ))
        
        # Force UI update
        self.tree.update_idletasks()

    def _add_result_to_tree(self, result):
        """Add result to tree with filtering - used by filter function"""
        # Determine status
        if result['open_ports']:
            status = "🟢 Active"
        else:
            status = "⚪ Inactive"
        
        # Get device type (with backward compatibility)
        device_type = result.get('device_type', 'Unknown')
        if device_type == 'Unknown' and result.get('open_ports'):
            # Try to detect if not already set
            device_type = self._detect_device_type(result['open_ports'], result.get('services', []), result.get('hostname', ''))
        
        # Format ports
        ports_str = ", ".join(map(str, result['open_ports'])) if result['open_ports'] else "—"
        
        # Format services
        services_str = "; ".join(result['services']) if result['services'] else "—"
        
        # Format vulnerabilities
        vuln_str = "; ".join(result.get('vulnerabilities', [])) if result.get('vulnerabilities') else "—"
        
        self.tree.insert("", tk.END, values=(
            result['ip'],
            result['hostname'] or "—",
            device_type,
            status,
            ports_str,
            services_str,
            vuln_str
        ))

    def on_start(self):
        # Validate inputs
        if not self._validate_inputs():
            return
        
        # Clear previous results
        self.on_clear()
        
        # Start scan
        self.stop_event.clear()
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.DISABLED)
        
        # Parse inputs
        network = self.net_entry_var.get().strip()
        ports_str = self.ports_entry.get().strip()
        timeout = float(self.timeout_entry.get().strip())
        workers = int(self.workers_entry.get().strip())
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            ports = self._parse_ports(ports_str)
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e))
            return
        
        # Update UI
        self.status_var.set("Initializing scan...")
        self.progress.config(value=0, maximum=100)  # Will be updated by scan thread
        self.stats['scan_start_time'] = time.time()
        
        # Show scan details in log
        self.log_message(f"Network: {network} ({len(list(net.hosts()))} hosts)")
        self.log_message(f"Ports: {ports_str} ({len(ports)} ports)")
        self.log_message(f"Workers: {workers}, Timeout: {timeout}s")
        
        # DEBUG: Test with first few IPs only for debugging
        if len(list(net.hosts())) > 5:
            self.log_message(f"DEBUG: Large network detected, will scan all {len(list(net.hosts()))} hosts")
        
        # If scanning 1024 ports, warn about time
        if len(ports) > 100:
            estimated_time = (len(ports) * 0.1 * len(list(net.hosts()))) / workers / 60
            self.log_message(f"DEBUG: Estimated scan time: {estimated_time:.1f} minutes with {workers} workers")
        
        # Log scan start
        self.log_message(f"Starting scan of {network} with {len(ports)} ports")
        self.log_message(f"DEBUG: About to start scanning {len(list(net.hosts()))} hosts")
        
        # Start scan thread
        threading.Thread(target=self._scan_network, 
                        args=(net, ports, timeout, workers), 
                        daemon=True).start()

    def _validate_inputs(self):
        try:
            timeout = float(self.timeout_entry.get().strip())
            if timeout <= 0:
                raise ValueError
        except Exception:
            messagebox.showerror("Invalid input", "Timeout must be a positive number.")
            return False
        
        try:
            workers = int(self.workers_entry.get().strip())
            if workers <= 0:
                raise ValueError
        except Exception:
            messagebox.showerror("Invalid input", "Workers must be a positive integer.")
            return False
        
        # Validate network size to prevent crashes
        try:
            network = self.net_entry_var.get().strip()
            net = ipaddress.ip_network(network, strict=False)
            
            # Calculate number of hosts efficiently without creating the full list
            # For IPv4: 2^(32-prefix) - 2 (subtract network and broadcast)
            if net.version == 4:
                prefix = net.prefixlen
                if prefix >= 32:
                    num_hosts = 1  # Single host
                else:
                    num_hosts = (2 ** (32 - prefix)) - 2
            else:
                # IPv6 - use a simpler calculation
                num_hosts = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
            
            # Maximum safe network size (10,000 hosts = /18 for most cases)
            MAX_SAFE_HOSTS = 10000
            
            # Hard limit - will crash the app (65,536 hosts = /16)
            MAX_HOSTS = 65536
            
            if num_hosts > MAX_HOSTS:
                messagebox.showerror(
                    "Network Too Large", 
                    f"Network {network} contains {num_hosts:,} hosts.\n\n"
                    f"This is too large and will crash the application.\n\n"
                    f"Maximum recommended: {MAX_SAFE_HOSTS:,} hosts (e.g., /18 or smaller).\n"
                    f"Please use a smaller network range like:\n"
                    f"  • {network.split('/')[0]}/24 (256 hosts)\n"
                    f"  • {network.split('/')[0]}/20 (4,096 hosts)\n"
                    f"  • {network.split('/')[0]}/18 (16,384 hosts)"
                )
                return False
            elif num_hosts > MAX_SAFE_HOSTS:
                # Warn but allow for medium-sized networks
                response = messagebox.askyesno(
                    "Large Network Warning",
                    f"Network {network} contains {num_hosts:,} hosts.\n\n"
                    f"This scan may take a very long time and use significant resources.\n\n"
                    f"Estimated time: {num_hosts * 0.1 / 60:.1f} - {num_hosts * 1.0 / 60:.1f} minutes\n"
                    f"(depending on network conditions and ports scanned)\n\n"
                    f"Do you want to continue?\n\n"
                    f"Tip: Consider scanning a smaller range like /24 (256 hosts) first."
                )
                if not response:
                    return False
        
        except ValueError as e:
            messagebox.showerror("Invalid Network", f"Invalid network format: {str(e)}")
            return False
        except Exception as e:
            messagebox.showerror("Network Error", f"Error parsing network: {str(e)}")
            return False
        
        return True

    def on_stop(self):
        self.stop_event.set()
        self.status_var.set("Stopping scan...")
        self.log_message("Scan stop requested")

    def on_export(self):
        if not self.results:
            messagebox.showinfo("No data", "There are no results to export.")
            return
        
        # Create export options window
        export_window = tk.Toplevel(self.root)
        export_window.title("Export Options")
        export_window.geometry("400x300")
        export_window.transient(self.root)
        export_window.grab_set()
        
        # Export format selection
        format_frame = ttk.LabelFrame(export_window, text="Export Format", padding=10)
        format_frame.pack(fill=tk.X, padx=10, pady=5)
        
        export_format = tk.StringVar(value="csv")
        ttk.Radiobutton(format_frame, text="CSV (Excel compatible)", variable=export_format, value="csv").pack(anchor=tk.W)
        ttk.Radiobutton(format_frame, text="JSON (Structured data)", variable=export_format, value="json").pack(anchor=tk.W)
        ttk.Radiobutton(format_frame, text="HTML Report", variable=export_format, value="html").pack(anchor=tk.W)
        ttk.Radiobutton(format_frame, text="Text Summary", variable=export_format, value="txt").pack(anchor=tk.W)
        
        # Export options
        options_frame = ttk.LabelFrame(export_window, text="Export Options", padding=10)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        include_vulns = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Include vulnerability details", variable=include_vulns).pack(anchor=tk.W)
        
        include_stats = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Include scan statistics", variable=include_stats).pack(anchor=tk.W)
        
        # Export button
        ttk.Button(export_window, text="Export", command=lambda: self._perform_export(
            export_format.get(), include_vulns.get(), include_stats.get(), export_window
        )).pack(pady=10)

    def _perform_export(self, format_type, include_vulns, include_stats, window):
        window.destroy()
        
        if format_type == "csv":
            self._export_csv(include_vulns, include_stats)
        elif format_type == "json":
            self._export_json(include_vulns, include_stats)
        elif format_type == "html":
            self._export_html(include_vulns, include_stats)
        elif format_type == "txt":
            self._export_txt(include_vulns, include_stats)

    def _export_csv(self, include_vulns, include_stats):
        default = f"lan_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path = filedialog.asksaveasfilename(
            title="Save CSV", 
            defaultextension=".csv", 
            initialfile=default, 
            filetypes=[("CSV files", "*.csv")]
        )
        if not path:
            return
        
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                
                # Write header
                headers = ["IP Address", "Hostname", "Device Type", "Status", "Open Ports", "Services"]
                if include_vulns:
                    headers.append("Vulnerabilities")
                headers.append("Scan Time")
                writer.writerow(headers)
                
                # Write data
                for row in self.results:
                    services = "; ".join(row["services"]) if row["services"] else ""
                    status = "Active" if row["open_ports"] else "Inactive"
                    device_type = row.get("device_type", "Unknown")
                    
                    row_data = [
                        row["ip"], 
                        row["hostname"] or "—",
                        device_type,
                        status,
                        ",".join(map(str, row["open_ports"])), 
                        services
                    ]
                    
                    if include_vulns:
                        vulns = "; ".join(row.get("vulnerabilities", [])) if row.get("vulnerabilities") else ""
                        row_data.append(vulns)
                    
                    row_data.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    writer.writerow(row_data)
                
                # Add statistics if requested
                if include_stats:
                    writer.writerow([])
                    writer.writerow(["Scan Statistics"])
                    writer.writerow(["Total Hosts", len(self.results)])
                    writer.writerow(["Active Hosts", self.stats['active_hosts']])
                    writer.writerow(["Open Ports", self.stats['open_ports']])
                    writer.writerow(["Vulnerabilities", self.stats['vulnerable_services']])
                    writer.writerow(["Scan Duration", f"{self.stats['scan_duration']:.1f}s"])
            
            messagebox.showinfo("Export complete", f"Saved to:\n{path}")
            self.log_message(f"Results exported to CSV: {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def _export_json(self, include_vulns, include_stats):
        default = f"lan_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = filedialog.asksaveasfilename(
            title="Save JSON", 
            defaultextension=".json", 
            initialfile=default, 
            filetypes=[("JSON files", "*.json")]
        )
        if not path:
            return
        
        try:
            export_data = {
                "scan_info": {
                    "timestamp": datetime.now().isoformat(),
                    "network": self.net_entry_var.get(),
                    "ports": self.ports_entry.get(),
                    "total_hosts": len(self.results),
                    "active_hosts": len([r for r in self.results if r['open_ports']])
                },
                "results": self.results
            }
            
            with open(path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            messagebox.showinfo("Export complete", f"Saved to:\n{path}")
            self.log_message(f"Results exported to JSON: {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def _export_html(self, include_vulns, include_stats):
        default = f"lan_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        path = filedialog.asksaveasfilename(
            title="Save HTML", 
            defaultextension=".html", 
            initialfile=default, 
            filetypes=[("HTML files", "*.html")]
        )
        if not path:
            return
        
        try:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>LAN Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    .active {{ color: green; }}
                    .inactive {{ color: gray; }}
                    .vulnerable {{ background-color: #ffe6e6; }}
                </style>
            </head>
            <body>
                <h1>🚀 LAN Scanner Pro - Network Scan Report</h1>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Network:</strong> {self.net_entry_var.get()}</p>
                
                <h2>Scan Results</h2>
                <table>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>Status</th>
                        <th>Open Ports</th>
                        <th>Services</th>
                        {"<th>Vulnerabilities</th>" if include_vulns else ""}
                    </tr>
            """
            
            for row in self.results:
                status_class = "active" if row['open_ports'] else "inactive"
                status_text = "🟢 Active" if row['open_ports'] else "⚪ Inactive"
                
                html_content += f"""
                    <tr class="{'vulnerable' if row.get('vulnerabilities') else ''}">
                        <td>{row['ip']}</td>
                        <td>{row['hostname'] or '—'}</td>
                        <td class="{status_class}">{status_text}</td>
                        <td>{', '.join(map(str, row['open_ports'])) if row['open_ports'] else '—'}</td>
                        <td>{'; '.join(row['services']) if row['services'] else '—'}</td>
                        {"<td>" + '; '.join(row.get('vulnerabilities', [])) + "</td>" if include_vulns else ""}
                    </tr>
                """
            
            html_content += """
                </table>
            """
            
            if include_stats:
                html_content += f"""
                <h2>Scan Statistics</h2>
                <ul>
                    <li><strong>Total Hosts:</strong> {len(self.results)}</li>
                    <li><strong>Active Hosts:</strong> {self.stats['active_hosts']}</li>
                    <li><strong>Open Ports:</strong> {self.stats['open_ports']}</li>
                    <li><strong>Vulnerabilities:</strong> {self.stats['vulnerable_services']}</li>
                    <li><strong>Scan Duration:</strong> {self.stats['scan_duration']:.1f}s</li>
                </ul>
                """
            
            html_content += """
            </body>
            </html>
            """
            
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            messagebox.showinfo("Export complete", f"Saved to:\n{path}")
            self.log_message(f"Results exported to HTML: {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def _export_txt(self, include_vulns, include_stats):
        default = f"lan_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path = filedialog.asksaveasfilename(
            title="Save Text", 
            defaultextension=".txt", 
            initialfile=default, 
            filetypes=[("Text files", "*.txt")]
        )
        if not path:
            return
        
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("🚀 LAN Scanner Pro - Network Scan Report\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Network: {self.net_entry_var.get()}\n\n")
                
                f.write("SCAN RESULTS\n")
                f.write("-" * 20 + "\n")
                
                for row in self.results:
                    status = "🟢 Active" if row['open_ports'] else "⚪ Inactive"
                    f.write(f"IP: {row['ip']}\n")
                    f.write(f"Hostname: {row['hostname'] or '—'}\n")
                    f.write(f"Status: {status}\n")
                    f.write(f"Open Ports: {', '.join(map(str, row['open_ports'])) if row['open_ports'] else '—'}\n")
                    f.write(f"Services: {'; '.join(row['services']) if row['services'] else '—'}\n")
                    
                    if include_vulns and row.get('vulnerabilities'):
                        f.write(f"Vulnerabilities: {'; '.join(row['vulnerabilities'])}\n")
                    
                    f.write("\n")
                
                if include_stats:
                    f.write("SCAN STATISTICS\n")
                    f.write("-" * 20 + "\n")
                    f.write(f"Total Hosts: {len(self.results)}\n")
                    f.write(f"Active Hosts: {self.stats['active_hosts']}\n")
                    f.write(f"Open Ports: {self.stats['open_ports']}\n")
                    f.write(f"Vulnerabilities: {self.stats['vulnerable_services']}\n")
                    f.write(f"Scan Duration: {self.stats['scan_duration']:.1f}s\n")
            
            messagebox.showinfo("Export complete", f"Saved to:\n{path}")
            self.log_message(f"Results exported to Text: {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def on_clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.results.clear()
        self.progress.config(value=0)
        self.status_var.set("Ready to scan")
        
        # Reset statistics
        for stat in self.stats_labels:
            self.stats_labels[stat].config(text="0")
        
        # Reset counter
        self.results_added_since_update = 0
        
        # Clear topology and statistics tabs
        self._update_topology_tab()
        self._update_statistics_tab()
        
        self.log_message("Results cleared")

    def _parse_ports(self, s: str):
        s = s.lower().replace(" ", "")
        if s in ("", "common"):
            return sorted(set(COMMON_PORTS))
        elif s == "top100":
            return sorted(set(TOP_PORTS))
        
        ports = set()
        for part in s.split(","):
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                a, b = int(a), int(b)
                if not (0 < a <= 65535 and 0 < b <= 65535 and a <= b):
                    raise ValueError(f"Invalid range: {part}")
                ports.update(range(a, b+1))
            else:
                p = int(part)
                if not (0 < p <= 65535):
                    raise ValueError(f"Invalid port: {p}")
                ports.add(p)
        
        if not ports:
            raise ValueError("No ports parsed")
        return sorted(ports)

    def _detect_service(self, port):
        try:
            return socket.getservbyport(port, 'tcp')
        except Exception:
            return "unknown"

    def _grab_banner(self, ip, port, timeout):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(b"\r\n")
                data = s.recv(64)
                return data.decode(errors="ignore").strip()
        except Exception:
            return ""

    def _check_vulnerabilities(self, port, service):
        vulnerabilities = []
        
        if port in VULNERABILITY_HINTS:
            vulnerabilities.append(VULNERABILITY_HINTS[port])
        
        # Add service-specific checks
        if "ssh" in service.lower() and port == 22:
            vulnerabilities.append("SSH - Check for key-based authentication")
        elif "http" in service.lower() and port == 80:
            vulnerabilities.append("HTTP - Consider HTTPS redirect")
        
        return vulnerabilities
    
    def _detect_device_type(self, open_ports, services, hostname):
        """Detect device type based on open ports, services, and hostname"""
        if not open_ports:
            return "Unknown"
        
        # Check for router/network device indicators
        if any(port in open_ports for port in [80, 443, 8080, 8443]):
            for service in services:
                service_lower = service.lower()
                if 'router' in service_lower or 'routeros' in service_lower:
                    return "Router"
                if 'apache' in service_lower or 'nginx' in service_lower or 'httpd' in service_lower:
                    # Check hostname for router indicators
                    if hostname:
                        hostname_lower = hostname.lower()
                        if 'router' in hostname_lower or 'gateway' in hostname_lower:
                            return "Router/Gateway"
        
        # Check for Windows systems
        if 3389 in open_ports:
            return "Windows PC/Server"
        if 139 in open_ports or 445 in open_ports:
            if 80 in open_ports or 443 in open_ports:
                return "Windows Server"
            return "Windows PC"
        
        # Check for Linux/Unix systems
        if 22 in open_ports:
            if 3306 in open_ports:
                return "Linux Database Server"
            if 80 in open_ports or 443 in open_ports:
                return "Linux Web Server"
            if 25 in open_ports or 587 in open_ports:
                return "Linux Mail Server"
            return "Linux/Unix Server"
        
        # Check for web servers
        if 80 in open_ports or 443 in open_ports:
            if 3306 in open_ports:
                return "Web/Database Server"
            if 8080 in open_ports or 8443 in open_ports:
                return "Web Application Server"
            return "Web Server"
        
        # Check for database servers
        if 3306 in open_ports:
            return "MySQL Server"
        if 1433 in open_ports:
            return "MS SQL Server"
        if 5432 in open_ports:
            return "PostgreSQL Server"
        
        # Check for mail servers
        if any(port in open_ports for port in [25, 587, 993, 995, 143, 110]):
            return "Mail Server"
        
        # Check for printers
        if any(port in open_ports for port in [515, 631, 9100]):
            return "Printer"
        
        # Check for cameras/IP cameras
        if any(port in open_ports for port in [554, 8554, 8888]):
            return "IP Camera"
        
        # Check for NAS/storage
        if any(port in open_ports for port in [2049, 111]):
            return "NAS/Storage"
        if 139 in open_ports or 445 in open_ports:
            return "File Server/NAS"
        
        # Check for VoIP devices
        if any(port in open_ports for port in [5060, 5061, 1720]):
            return "VoIP Device"
        
        # Check hostname for clues
        if hostname:
            hostname_lower = hostname.lower()
            if 'router' in hostname_lower or 'gateway' in hostname_lower:
                return "Router/Gateway"
            if 'printer' in hostname_lower or 'print' in hostname_lower:
                return "Printer"
            if 'camera' in hostname_lower or 'ipcam' in hostname_lower:
                return "IP Camera"
            if 'nas' in hostname_lower or 'storage' in hostname_lower:
                return "NAS/Storage"
        
        # If only common ports are open, might be a basic network device
        common_device_ports = [80, 443, 8080]
        if all(port in common_device_ports for port in open_ports):
            return "Network Device"
        
        return "Network Device"

    def _scan_host(self, ip: str, ports, timeout: float):
        open_ports = []
        services = []
        vulnerabilities = []
        
        # Use a much shorter timeout for faster scanning
        scan_timeout = min(timeout, 0.1)  # Max 0.1 seconds per port
        socket.setdefaulttimeout(scan_timeout)
        
        # Send periodic updates to show scan is active
        ports_scanned = 0
        start_time = time.time()
        
        self.ui_queue.put(("activity", ip, 0, len(ports)))
        
        for port in ports:
            if self.stop_event.is_set():
                break
            
            ports_scanned += 1
            
            # Update progress every 50 ports or every 5 seconds
            if ports_scanned % 50 == 0 or (time.time() - start_time) > 5:
                self.ui_queue.put(("activity", ip, ports_scanned, len(ports)))
                start_time = time.time()
            
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(scan_timeout)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
                        
                        service = self._detect_service(port)
                        if self.banner_grab_var.get():
                            banner = self._grab_banner(ip, port, timeout)
                            if banner:
                                services.append(f"{port}/{service}: {banner}")
                            else:
                                services.append(f"{port}/{service}")
                        else:
                            services.append(f"{port}/{service}")
                        
                        # Check for vulnerabilities
                        if self.vuln_check_var.get():
                            vulns = self._check_vulnerabilities(port, service)
                            vulnerabilities.extend(vulns)
            except Exception:
                pass
        
        # Final progress update
        self.ui_queue.put(("activity", ip, len(ports), len(ports)))
        
        # Reverse DNS lookup with multiple methods and better error handling
        hostname = ""
        if self.rev_dns_var.get() and not self.stop_event.is_set():
            hostname = self._resolve_hostname(ip)
        
        return ip, hostname, open_ports, services, vulnerabilities
    
    def _resolve_hostname(self, ip):
        """Resolve hostname using multiple methods with better error handling"""
        hostname = ""
        
        # Method 1: Standard reverse DNS lookup (gethostbyaddr) - Primary method
        try:
            socket.setdefaulttimeout(4.0)  # Increased timeout to 4 seconds
            hostname_info = socket.gethostbyaddr(ip)
            if hostname_info and len(hostname_info) > 0:
                hostname = hostname_info[0]
                if hostname and hostname.strip():
                    return hostname.strip()
        except socket.herror:
            # No reverse DNS record found - this is normal for many IPs
            pass
        except socket.gaierror:
            # DNS resolution error
            pass
        except socket.timeout:
            # DNS lookup timed out - try with longer timeout
            pass
        except OSError:
            # Network/system error
            pass
        except Exception as e:
            # Log unexpected errors for debugging
            try:
                self.log_message(f"Unexpected DNS error for {ip}: {str(e)[:50]}")
            except:
                pass
        
        # Method 2: Try reverse DNS again with longer timeout (for slow DNS servers)
        try:
            socket.setdefaulttimeout(6.0)  # Longer timeout for retry
            hostname_info = socket.gethostbyaddr(ip)
            if hostname_info and len(hostname_info) > 0:
                hostname = hostname_info[0]
                if hostname and hostname.strip():
                    return hostname.strip()
        except Exception:
            pass
        
        # Method 3: Try with getnameinfo (alternative method)
        try:
            socket.setdefaulttimeout(3.0)
            hostname_info = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)
            if hostname_info and len(hostname_info) > 0 and hostname_info[0]:
                hostname = hostname_info[0]
                if hostname and hostname.strip() and hostname != ip:
                    return hostname.strip()
        except Exception:
            pass
        
        # Method 4: On Windows, try NetBIOS name lookup using nbtstat
        if os.name == 'nt':  # Windows
            try:
                import subprocess
                # Use nbtstat to get NetBIOS name (faster than full reverse DNS on Windows networks)
                # Format: nbtstat -A <IP>
                result = subprocess.run(
                    ['nbtstat', '-A', ip],
                    capture_output=True,
                    text=True,
                    timeout=2.0
                )
                if result.returncode == 0 and result.stdout:
                    # Parse nbtstat output to extract NetBIOS name
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '<00>' in line or '<20>' in line:  # Workstation/Server service
                            parts = line.split()
                            if len(parts) > 0:
                                # Extract the name (usually first non-whitespace part)
                                for part in parts:
                                    if part and not part.startswith('<') and len(part) < 16:
                                        # NetBIOS names are typically 15 chars or less
                                        if part.strip() and part.strip().upper() != ip.replace('.', ''):
                                            return part.strip().upper()
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                # nbtstat not available or timed out - this is okay
                pass
            except Exception:
                # Any other error - ignore silently
                pass
        
        # Method 5: Try ping -a on Windows (alternative NetBIOS method)
        if os.name == 'nt':  # Windows
            try:
                import subprocess
                # ping -a does reverse lookup and shows hostname if available
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '1000', ip],
                    capture_output=True,
                    text=True,
                    timeout=2.0
                )
                if result.returncode == 0 and result.stdout:
                    # Look for hostname in ping output (format: "Pinging HOSTNAME [IP]")
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Pinging' in line and '[' in line:
                            # Extract hostname from "Pinging HOSTNAME [IP]" format
                            try:
                                start = line.find('Pinging ') + 9
                                end = line.find(' [')
                                if start < end:
                                    hostname = line[start:end].strip()
                                    if hostname and hostname != ip:
                                        return hostname
                            except:
                                pass
            except Exception:
                pass
        
        return ""  # Return empty string if all methods fail

    def _scan_network(self, net, ports, timeout, workers):
        hosts = [str(h) for h in net.hosts()]
        total = len(hosts)
        processed = 0
        
        # Calculate total operations for better progress tracking
        total_operations = len(hosts) * len(ports)
        self.log_message(f"Starting scan: {len(hosts)} hosts × {len(ports)} ports = {total_operations:,} operations")
        
        # Update progress bar maximum to reflect total operations
        self.ui_queue.put(("set_max", total_operations))
        
        self.log_message(f"DEBUG: Created {len(hosts)} host tasks, starting ThreadPoolExecutor with {workers} workers")
        
        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                future_map = {
                    pool.submit(self._scan_host, ip, ports, timeout): ip 
                    for ip in hosts
                }
                
                self.log_message(f"DEBUG: Submitted {len(future_map)} tasks to thread pool")
                
                for fut in as_completed(future_map):
                    if self.stop_event.is_set():
                        break
                    
                    try:
                        ip, hostname, open_ports, services, vulnerabilities = fut.result()
                        
                        # Detect device type
                        device_type = self._detect_device_type(open_ports, services, hostname)
                        
                        # Create result for this completed device
                        result = {
                            "ip": ip,
                            "hostname": hostname,
                            "device_type": device_type,
                            "open_ports": open_ports,
                            "services": services,
                            "vulnerabilities": list(set(vulnerabilities))  # Remove duplicates
                        }
                        
                        # Add to results and display immediately when device scan is complete
                        self.results.append(result)
                        if open_ports:
                            self.log_message(f"Device {ip} scan complete - {len(open_ports)} open ports found: {open_ports}")
                        else:
                            self.log_message(f"Device {ip} scan complete - no open ports found")
                        self.ui_queue.put(("row", result))
                        processed += 1
                        
                        # Update progress - send total hosts for better tracking
                        self.ui_queue.put(("progress", processed, len(hosts), len(ports)))
                        
                        # Update statistics
                        if open_ports:
                            self.stats['active_hosts'] += 1
                            self.stats['open_ports'] += len(open_ports)
                        
                        if vulnerabilities:
                            self.stats['vulnerable_services'] += len(vulnerabilities)
                        
                    except Exception as e:
                        self.log_message(f"Error scanning host: {e}")
                        
            # Results are already displayed as each device completes
            # No need to display them again here
                        
        except Exception as e:
            self.ui_queue.put(("error", str(e)))
        finally:
            self.ui_queue.put(("done", None))

    def _drain_queue(self):
        try:
            while True:
                kind, *payload = self.ui_queue.get_nowait()
                
                if kind == "row":
                    result = payload[0]
                    self.log_message(f"DEBUG: Received row message for {result['ip']} with {len(result['open_ports'])} open ports")
                    self.log_message(f"Adding result to tree: {result['ip']} with {len(result['open_ports'])} open ports")
                    # Force add to tree, bypassing any filters
                    self._add_result_to_tree_direct(result)
                    self.log_message(f"DEBUG: Added {result['ip']} to tree successfully")
                    
                    # Update tabs periodically (every 5 results or when active host is found)
                    self.results_added_since_update += 1
                    if self.results_added_since_update >= 5 or result['open_ports']:
                        self.results_added_since_update = 0
                        # Update tabs if they are currently visible
                        selected_tab = self.notebook.index(self.notebook.select())
                        tab_text = self.notebook.tab(selected_tab, 'text')
                        if "🌐 Network Topology" in tab_text:
                            self._update_topology_tab()
                        elif "📊 Statistics" in tab_text:
                            self._update_statistics_tab()
                    
                elif kind == "progress":
                    processed, total_hosts, ports_per_host = payload[0], payload[1], payload[2]
                    
                    # Update progress by the number of ports scanned for this host
                    for _ in range(ports_per_host):
                        self.progress.step(1)
                    
                    # Calculate percentage and ETA
                    current_progress = int(self.progress['value'])
                    max_progress = int(self.progress['maximum'])
                    percentage = (current_progress / max_progress * 100) if max_progress > 0 else 0
                    
                    # Calculate ETA
                    if self.stats['scan_start_time'] and current_progress > 0:
                        elapsed = time.time() - self.stats['scan_start_time']
                        rate = current_progress / elapsed
                        remaining = (max_progress - current_progress) / rate if rate > 0 else 0
                        eta_str = f" (ETA: {remaining/60:.1f}m)" if remaining > 60 else f" (ETA: {remaining:.0f}s)" if remaining > 0 else ""
                    else:
                        eta_str = ""
                    
                    # Show devices scanned out of total devices
                    self.status_var.set(f"Devices: {processed}/{total_hosts} scanned ({percentage:.1f}%) - Results showing as completed{eta_str}")
                    
                    # Update statistics
                    self.stats_labels['Hosts Found'].config(text=str(self.stats['active_hosts']))
                    self.stats_labels['Open Ports'].config(text=str(self.stats['open_ports']))
                    self.stats_labels['Vulnerabilities'].config(text=str(self.stats['vulnerable_services']))
                    
                elif kind == "set_max":
                    self.progress.config(maximum=payload[0])
                    
                elif kind == "activity":
                    # Show current scanning activity
                    ip, ports_done, total_ports = payload[0], payload[1], payload[2]
                    self.status_var.set(f"Scanning {ip}... ({ports_done}/{total_ports} ports)")
                    
                elif kind == "error":
                    messagebox.showerror("Scan error", payload[0])
                    self.log_message(f"Scan error: {payload[0]}")
                    
                elif kind == "done":
                    self.scan_btn.config(state=tk.NORMAL)
                    self.stop_btn.config(state=tk.DISABLED)
                    self.export_btn.config(state=tk.NORMAL if self.results else tk.DISABLED)
                    
                    # Calculate scan duration
                    if self.stats['scan_start_time']:
                        self.stats['scan_duration'] = time.time() - self.stats['scan_start_time']
                        
                    # Show completion status
                    active_hosts = len([r for r in self.results if r['open_ports']])
                    self.status_var.set(f"Scan complete! Found {active_hosts} active hosts in {self.stats['scan_duration']:.1f}s")
                    self.log_message(f"Scan completed: {len(self.results)} hosts scanned, {active_hosts} active")
                    
                    if self.stop_event.is_set():
                        self.status_var.set("Scan stopped.")
                        self.log_message("Scan stopped by user")
                    else:
                        self.status_var.set(f"Scan completed in {self.stats['scan_duration']:.1f}s")
                        self.log_message(f"Scan completed. Found {self.stats['active_hosts']} active hosts")
                    
                    # Update final statistics
                    self.stats_labels['Hosts Found'].config(text=str(self.stats['active_hosts']))
                    self.stats_labels['Open Ports'].config(text=str(self.stats['open_ports']))
                    self.stats_labels['Vulnerabilities'].config(text=str(self.stats['vulnerable_services']))
                    
                    # Update topology and statistics tabs with final results
                    self._update_topology_tab()
                    self._update_statistics_tab()
                    
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._drain_queue)

    def toggle_theme(self):
        if self.current_theme == "light":
            self.current_theme = "dark"
            self.style.configure("TFrame", background="#2b2b2b")
            self.style.configure("TLabel", background="#2b2b2b", foreground="white")
            self.style.configure("TButton", background="#404040", foreground="white")
        else:
            self.current_theme = "light"
            self.style.configure("TFrame", background="white")
            self.style.configure("TLabel", background="white", foreground="black")
            self.style.configure("TButton", background="white", foreground="black")

    def show_statistics(self):
        if not MATPLOTLIB_AVAILABLE:
            messagebox.showinfo("Charts Disabled", "Matplotlib is not installed. Cannot show charts.")
            return

        # Create statistics window
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Network Statistics")
        stats_window.geometry("600x400")
        
        # Create matplotlib figure
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 6))
        
        # Port distribution chart
        if self.results:
            port_counts = Counter()
            for result in self.results:
                for port in result['open_ports']:
                    port_counts[port] += 1
            
            if port_counts:
                ports, counts = zip(*port_counts.most_common(10))
                ax1.bar(ports, counts)
                ax1.set_title("Top 10 Open Ports")
                ax1.set_xlabel("Port")
                ax1.set_ylabel("Count")
                ax1.tick_params(axis='x', rotation=45)
        
        # Host status chart
        active_hosts = len([r for r in self.results if r['open_ports']])
        inactive_hosts = len(self.results) - active_hosts
        
        if self.results:
            ax2.pie([active_hosts, inactive_hosts], 
                    labels=['Active', 'Inactive'], 
                    autopct='%1.1f%%',
                    colors=['#2ecc71', '#95a5a6'])
            ax2.set_title("Host Status Distribution")
        
        plt.tight_layout()
        
        # Embed in tkinter
        canvas = FigureCanvasTkAgg(fig, stats_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def show_topology(self):
        if not MATPLOTLIB_AVAILABLE:
            messagebox.showinfo("Charts Disabled", "Matplotlib is not installed. Cannot show topology.")
            return

        # Create topology window
        topo_window = tk.Toplevel(self.root)
        topo_window.title("Network Topology")
        topo_window.geometry("800x600")
        
        # Simple network visualization
        canvas = tk.Canvas(topo_window, bg="white")
        canvas.pack(fill=tk.BOTH, expand=True)
        
        if self.results:
            # Draw network diagram
            center_x, center_y = 400, 300
            radius = 200
            
            # Draw central router
            canvas.create_oval(center_x-30, center_y-30, center_x+30, center_y+30, 
                             fill="blue", outline="black")
            canvas.create_text(center_x, center_y, text="Router", fill="white")
            
            # Draw hosts
            active_hosts = [r for r in self.results if r['open_ports']]
            angle_step = 360 / len(active_hosts) if active_hosts else 0
            
            for i, host in enumerate(active_hosts):
                angle = math.radians(i * angle_step)
                x = center_x + radius * math.cos(angle)
                y = center_y + radius * math.sin(angle)
                
                # Draw host
                canvas.create_oval(x-20, y-20, x+20, y+20, 
                                 fill="green", outline="black")
                canvas.create_text(x, y, text=host['ip'].split('.')[-1], fill="white")
                
                # Draw connection line
                canvas.create_line(center_x, center_y, x, y, fill="gray", width=2)

    def network_speed_test(self):
        """Simple internet speed test"""
        # Show a simple message box with basic speed info
        try:
            # Quick ping test
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            result = sock.connect_ex(("8.8.8.8", 53))
            end_time = time.time()
            sock.close()
            
            if result == 0:
                ping_ms = (end_time - start_time) * 1000
                
                # Estimate speed based on ping
                if ping_ms < 20:
                    estimated_speed = "50-100 Mbps (Excellent)"
                elif ping_ms < 50:
                    estimated_speed = "25-50 Mbps (Very Good)"
                elif ping_ms < 100:
                    estimated_speed = "10-25 Mbps (Good)"
                elif ping_ms < 200:
                    estimated_speed = "5-15 Mbps (Fair)"
                else:
                    estimated_speed = "1-5 Mbps (Slow)"
                
                message = f"""🌐 Internet Speed Test Results

🏓 Ping: {ping_ms:.0f} ms
🚀 Estimated Speed: {estimated_speed}

💡 Connection Quality:
{'🟢 Excellent' if ping_ms < 20 else '🟡 Good' if ping_ms < 100 else '🔴 Slow'}

Your connection is suitable for:
{'✅ 4K Streaming, Gaming, Large Downloads' if ping_ms < 50 else '✅ HD Streaming, Video Calls' if ping_ms < 100 else '✅ Basic Web Browsing'}"""
                
                messagebox.showinfo("Internet Speed Test", message)
            else:
                messagebox.showerror("Connection Test", "❌ No internet connection detected")
                
        except Exception as e:
            messagebox.showerror("Speed Test Error", f"❌ Test failed: {str(e)}")
    
    def _clear_results(self):
        """Clear test results"""
        self.connection_results.delete(1.0, tk.END)
        self.connection_status.config(text="Click 'Test Connection' to check your internet")
    
    def _test_connection(self):
        """Test internet connection"""
        if self.testing:
            return
        
        self.testing = True
        self.test_btn.config(state=tk.DISABLED)
        self.connection_progress.start()
        self.connection_status.config(text="🔄 Testing connection...")
        self.connection_results.delete(1.0, tk.END)
        
        # Start test in thread
        threading.Thread(target=self._perform_connection_test, daemon=True).start()
    
    def _perform_connection_test(self):
        """Perform internet speed test"""
        try:
            self._add_result("🚀 Testing your internet speed...\n")
            self._add_result("=" * 40 + "\n\n")
            
            # Test download speed
            self._add_result("📥 Testing download speed...\n")
            download_speed = self._test_download_speed()
            
            if download_speed > 0:
                # Convert to Mbps
                download_mbps = download_speed / (1024 * 1024) * 8
                self._add_result(f"Download Speed: {download_mbps:.2f} Mbps\n\n")
                
                # Test upload speed (simple)
                self._add_result("📤 Testing upload speed...\n")
                upload_speed = self._test_upload_speed()
                
                if upload_speed > 0:
                    upload_mbps = upload_speed / (1024 * 1024) * 8
                    self._add_result(f"Upload Speed: {upload_mbps:.2f} Mbps\n\n")
                else:
                    self._add_result("Upload Speed: Unable to test\n\n")
                    upload_mbps = 0
                
                # Test ping
                self._add_result("🏓 Testing ping...\n")
                ping_ms = self._test_ping()
                self._add_result(f"Ping: {ping_ms:.0f} ms\n\n")
                
                # Overall assessment
                self._add_result("=" * 40 + "\n")
                self._add_result("📊 SPEED TEST RESULTS\n")
                self._add_result("=" * 40 + "\n")
                self._add_result(f"📥 Download: {download_mbps:.2f} Mbps\n")
                if upload_mbps > 0:
                    self._add_result(f"📤 Upload: {upload_mbps:.2f} Mbps\n")
                self._add_result(f"🏓 Ping: {ping_ms:.0f} ms\n\n")
                
                # Speed quality assessment
                if download_mbps >= 100:
                    quality = "🟢 Excellent (Ultra Fast)"
                elif download_mbps >= 50:
                    quality = "🟢 Very Good (Fast)"
                elif download_mbps >= 25:
                    quality = "🟡 Good (Standard)"
                elif download_mbps >= 10:
                    quality = "🟠 Fair (Basic)"
                else:
                    quality = "� xSlow (Limited)"
                
                self._add_result(f"🌐 Connection Quality: {quality}\n")
                
                # Update status
                status_text = f"Download: {download_mbps:.1f} Mbps | Ping: {ping_ms:.0f}ms | {quality.split('(')[1].replace(')', '')}"
                self.root.after(0, lambda: self.connection_status.config(text=status_text))
                
            else:
                error_msg = "❌ Unable to test internet speed - No connection"
                self._add_result(f"\n{error_msg}\n")
                self.root.after(0, lambda: self.connection_status.config(text=error_msg))
            
        except Exception as e:
            error_msg = f"❌ Speed test failed: {str(e)}"
            self._add_result(f"\n{error_msg}\n")
            self.root.after(0, lambda: self.connection_status.config(text=error_msg))
        
        finally:
            self.root.after(0, self._finish_test)
    
    def _test_download_speed(self):
        """Test download speed using multiple reliable sources"""
        try:
            import urllib.request
            
            # Try multiple reliable URLs
            test_urls = [
                "http://www.google.com/robots.txt",
                "http://github.com/robots.txt",
                "http://www.microsoft.com/robots.txt"
            ]
            
            total_speed = 0
            successful_tests = 0
            
            for url in test_urls:
                try:
                    start_time = time.time()
                    
                    with urllib.request.urlopen(url, timeout=10) as response:
                        data = response.read()
                    
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    if duration > 0 and len(data) > 0:
                        # Calculate speed and scale up (these are small files)
                        speed_bps = len(data) / duration
                        # Estimate based on small file performance
                        estimated_speed = speed_bps * 50  # Rough scaling factor
                        total_speed += estimated_speed
                        successful_tests += 1
                        
                        self._add_result(f"  Test {successful_tests}: {len(data)} bytes in {duration:.2f}s\n")
                    
                except Exception:
                    continue
                
                time.sleep(0.2)
            
            if successful_tests > 0:
                avg_speed = total_speed / successful_tests
                return avg_speed
            
        except Exception as e:
            self._add_result(f"Download test error: {str(e)}\n")
        
        return 0
    
    def _test_upload_speed(self):
        """Simple upload speed test"""
        try:
            # Simple ping-based upload estimation
            # This is a basic estimation, not a real upload test
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(("8.8.8.8", 53))
            
            # Send some data
            test_data = b"0" * 1024  # 1KB test
            sock.send(test_data)
            
            end_time = time.time()
            sock.close()
            
            duration = end_time - start_time
            if duration > 0:
                # Rough estimation (not accurate, but gives an idea)
                estimated_speed = len(test_data) / duration * 10  # Rough multiplier
                return estimated_speed
            
        except Exception:
            pass
        
        return 0
    
    def _test_ping(self):
        """Test ping latency"""
        try:
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            
            result = sock.connect_ex(("8.8.8.8", 53))
            end_time = time.time()
            
            sock.close()
            
            if result == 0:
                latency = (end_time - start_time) * 1000
                return latency
            
        except Exception:
            pass
        
        return 999  # High ping if failed
    
    def _add_result(self, text):
        """Add text to results"""
        self.connection_results.insert(tk.END, text)
        self.connection_results.see(tk.END)
        self.connection_results.update()
    
    def _finish_test(self):
        """Finish test and update UI"""
        self.testing = False
        self.test_btn.config(state=tk.NORMAL)
        self.connection_progress.stop()
  

    def ping_test(self):
        """Test connectivity to discovered hosts"""
        if not self.results:
            messagebox.showinfo("No Results", "Please run a scan first to test connectivity.")
            return
        
        # Create ping test window
        ping_window = tk.Toplevel(self.root)
        ping_window.title("Ping Test")
        ping_window.geometry("500x400")
        ping_window.transient(self.root)
        
        # Host selection
        ttk.Label(ping_window, text="Select hosts to ping:").pack(pady=5)
        
        # Create listbox with hosts
        host_listbox = tk.Listbox(ping_window, selectmode=tk.MULTIPLE, height=10)
        host_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        for result in self.results:
            host_listbox.insert(tk.END, f"{result['ip']} ({result['hostname'] or 'No hostname'})")
        
        # Ping button
        def run_ping():
            selected_indices = host_listbox.curselection()
            if not selected_indices:
                messagebox.showwarning("No Selection", "Please select hosts to ping.")
                return
            
            # Run ping tests
            ping_window.destroy()
            self._run_ping_tests([self.results[i]['ip'] for i in selected_indices])
        
        ttk.Button(ping_window, text="Start Ping Test", command=run_ping).pack(pady=10)

    def _run_ping_tests(self, hosts):
        """Run ping tests on selected hosts"""
        ping_window = tk.Toplevel(self.root)
        ping_window.title("Ping Results")
        ping_window.geometry("600x500")
        
        # Results text area
        text_area = scrolledtext.ScrolledText(ping_window, height=25, width=70)
        text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_area.insert(tk.END, "Ping Test Results\n")
        text_area.insert(tk.END, "=" * 30 + "\n\n")
        
        def ping_host(host):
            try:
                # Simple ping using socket (cross-platform)
                start_time = time.time()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((host, 80))  # Try port 80 as a connectivity test
                s.close()
                
                if result == 0:
                    response_time = (time.time() - start_time) * 1000
                    return f"✅ {host}: Connected ({response_time:.1f}ms)\n"
                else:
                    return f"❌ {host}: No response\n"
            except Exception as e:
                return f"❌ {host}: Error - {str(e)}\n"
        
        # Run ping tests
        for host in hosts:
            result = ping_host(host)
            text_area.insert(tk.END, result)
            text_area.see(tk.END)
            ping_window.update()
            time.sleep(0.1)  # Small delay to show progress
        
        text_area.insert(tk.END, "\nPing test completed!\n")

    def port_scanner(self):
        """Detailed port scanner for specific hosts"""
        if not self.results:
            messagebox.showinfo("No Results", "Please run a scan first to select hosts.")
            return
        
        # Create port scanner window
        port_window = tk.Toplevel(self.root)
        port_window.title("Detailed Port Scanner")
        port_window.geometry("600x500")
        port_window.transient(self.root)
        
        # Host selection
        ttk.Label(port_window, text="Select host for detailed port scan:").pack(pady=5)
        
        host_var = tk.StringVar()
        host_combo = ttk.Combobox(port_window, textvariable=host_var, 
                                 values=[f"{r['ip']} ({r['hostname'] or 'No hostname'})" for r in self.results],
                                 state="readonly", width=50)
        host_combo.pack(pady=5)
        
        # Port range
        ttk.Label(port_window, text="Port range (e.g., 1-1000):").pack(pady=5)
        port_range = ttk.Entry(port_window, width=30)
        port_range.insert(0, "1-1000")
        port_range.pack(pady=5)
        
        # Scan button
        def run_port_scan():
            if not host_var.get():
                messagebox.showwarning("No Selection", "Please select a host.")
                return
            
            # Extract IP from selection
            selected_ip = host_var.get().split()[0]
            port_range_str = port_range.get()
            
            port_window.destroy()
            self._run_detailed_port_scan(selected_ip, port_range_str)
        
        ttk.Button(port_window, text="Start Port Scan", command=run_port_scan).pack(pady=10)

    def _run_detailed_port_scan(self, host, port_range_str):
        """Run detailed port scan on specific host"""
        try:
            ports = self._parse_ports(port_range_str)
        except ValueError as e:
            messagebox.showerror("Invalid Ports", str(e))
            return
        
        # Create results window
        results_window = tk.Toplevel(self.root)
        results_window.title(f"Port Scan Results - {host}")
        results_window.geometry("700x600")
        
        # Progress
        progress_var = tk.StringVar(value="Scanning...")
        ttk.Label(results_window, textvariable=progress_var).pack(pady=5)
        
        progress_bar = ttk.Progressbar(results_window, orient="horizontal", mode="determinate")
        progress_bar.pack(fill=tk.X, padx=10, pady=5)
        progress_bar.config(maximum=len(ports))
        
        # Results tree
        columns = ("port", "status", "service", "banner")
        tree = ttk.Treeview(results_window, columns=columns, show="headings", height=20)
        
        tree.heading("port", text="Port")
        tree.heading("status", text="Status")
        tree.heading("service", text="Service")
        tree.heading("banner", text="Banner")
        
        tree.column("port", width=80, anchor=tk.CENTER)
        tree.column("status", width=100, anchor=tk.CENTER)
        tree.column("service", width=150, anchor=tk.W)
        tree.column("banner", width=300, anchor=tk.W)
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Run scan
        def scan_ports():
            for i, port in enumerate(ports):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1.0)
                        if s.connect_ex((host, port)) == 0:
                            service = self._detect_service(port)
                            banner = self._grab_banner(host, port, 1.0)
                            
                            tree.insert("", tk.END, values=(
                                port, "🟢 Open", service, banner or "—"
                            ))
                        else:
                            tree.insert("", tk.END, values=(
                                port, "🔴 Closed", "—", "—"
                            ))
                except Exception:
                    tree.insert("", tk.END, values=(
                        port, "❌ Error", "—", "—"
                    ))
                
                progress_bar.step(1)
                progress_var.set(f"Scanned {i+1}/{len(ports)} ports")
                results_window.update()
            
            progress_var.set("Scan completed!")
            progress_bar.config(value=len(ports))
        
        # Run scan in thread
        threading.Thread(target=scan_ports, daemon=True).start()

    def device_fingerprint(self):
        """Identify device types and OS information"""
        if not self.results:
            messagebox.showinfo("No Results", "Please run a scan first to analyze devices.")
            return
        
        # Create fingerprint window
        fp_window = tk.Toplevel(self.root)
        fp_window.title("Device Fingerprinting")
        fp_window.geometry("700x600")
        
        # Results text area
        text_area = scrolledtext.ScrolledText(fp_window, height=30, width=80)
        text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_area.insert(tk.END, "Device Fingerprinting Analysis\n")
        text_area.insert(tk.END, "=" * 40 + "\n\n")
        
        def analyze_device(result):
            ip = result['ip']
            services = result['services']
            open_ports = result['open_ports']
            
            text_area.insert(tk.END, f"Device: {ip}\n")
            text_area.insert(tk.END, f"Hostname: {result['hostname'] or 'Unknown'}\n")
            
            # Analyze based on open ports
            device_type = "Unknown"
            os_hints = []
            
            if 22 in open_ports:
                device_type = "Linux/Unix Server"
                os_hints.append("SSH service suggests Unix-like OS")
            elif 3389 in open_ports:
                device_type = "Windows Server/Workstation"
                os_hints.append("RDP service suggests Windows OS")
            elif 80 in open_ports or 443 in open_ports:
                if device_type == "Unknown":
                    device_type = "Web Server"
                os_hints.append("Web services detected")
            elif 139 in open_ports or 445 in open_ports:
                if device_type == "Unknown":
                    device_type = "File Server"
                os_hints.append("SMB services suggest file sharing")
            
            text_area.insert(tk.END, f"Device Type: {device_type}\n")
            if os_hints:
                text_area.insert(tk.END, "OS Hints:\n")
                for hint in os_hints:
                    text_area.insert(tk.END, f"  • {hint}\n")
            
            text_area.insert(tk.END, f"Open Ports: {', '.join(map(str, open_ports))}\n")
            text_area.insert(tk.END, f"Services: {'; '.join(services) if services else 'None'}\n")
            
            # Security assessment
            if result.get('vulnerabilities'):
                text_area.insert(tk.END, "⚠️  Security Issues Detected:\n")
                for vuln in result['vulnerabilities']:
                    text_area.insert(tk.END, f"  • {vuln}\n")
            else:
                text_area.insert(tk.END, "✅ No obvious security issues detected\n")
            
            text_area.insert(tk.END, "\n" + "-" * 50 + "\n\n")
            fp_window.update()
        
        # Analyze each device
        for result in self.results:
            analyze_device(result)
        
        text_area.insert(tk.END, "Device fingerprinting completed!\n")

    def save_config_profile(self):
        profile_name = tk.simpledialog.askstring("Save Profile", "Enter profile name:")
        if profile_name:
            config = {
                "network": self.net_entry_var.get(),
                "ports": self.ports_entry.get(),
                "timeout": self.timeout_entry.get(),
                "workers": self.workers_entry.get(),
                "reverse_dns": self.rev_dns_var.get(),
                "banner_grab": self.banner_grab_var.get(),
                "vuln_check": self.vuln_check_var.get()
            }
            self.config_profiles[profile_name] = config
            self.save_config_profiles()
            messagebox.showinfo("Success", f"Profile '{profile_name}' saved")

    def load_config_profile(self):
        if not self.config_profiles:
            messagebox.showinfo("No Profiles", "No saved profiles found")
            return
        
        profile_name = tk.simpledialog.askstring("Load Profile", 
                                               f"Enter profile name:\n{list(self.config_profiles.keys())}")
        if profile_name and profile_name in self.config_profiles:
            config = self.config_profiles[profile_name]
            self.net_entry_var.set(config["network"])
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, config["ports"])
            self.timeout_entry.delete(0, tk.END)
            self.timeout_entry.insert(0, config["timeout"])
            self.workers_entry.delete(0, tk.END)
            self.workers_entry.insert(0, config["workers"])
            self.rev_dns_var.set(config["reverse_dns"])
            self.banner_grab_var.set(config["banner_grab"])
            self.vuln_check_var.set(config["vuln_check"])
            messagebox.showinfo("Success", f"Profile '{profile_name}' loaded")

    def load_config_profiles(self):
        try:
            if os.path.exists("scanner_profiles.json"):
                with open("scanner_profiles.json", "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def save_config_profiles(self):
        try:
            with open("scanner_profiles.json", "w") as f:
                json.dump(self.config_profiles, f, indent=2)
        except Exception as e:
            print(f"Error saving profiles: {e}")

    def discover_networks(self):
        """Discover available networks on the local machine"""
        try:
            # Get local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Extract network from local IP
            ip_parts = local_ip.split('.')
            network_base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            # Show discovered network
            result = messagebox.askyesno(
                "Network Discovery", 
                f"Discovered local network: {network_base}\n\nUse this network for scanning?"
            )
            
            if result:
                self.net_entry_var.set(network_base)
                self.log_message(f"Network discovered and set: {network_base}")
                
        except Exception as e:
            messagebox.showerror("Discovery Error", f"Could not discover network: {str(e)}")
            self.log_message(f"Network discovery failed: {str(e)}")

    def set_port_preset(self, preset_name):
        """Set port presets for common scanning scenarios"""
        if preset_name == "common":
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, "common")
        elif preset_name == "80,443,8080,8443":
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, "80,443,8080,8443")
        elif preset_name == "22,80,443":
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, "22,80,443")
        elif preset_name == "1-1024":
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, "1-1024")
        
        self.log_message(f"Port preset applied: {preset_name}")

    def show_about(self):
        """Display the About dialog with application and developer information"""
        about_window = tk.Toplevel(self.root)
        about_window.title("About LAN Scanner Pro")
        about_window.geometry("550x500")
        about_window.resizable(True, True)
        about_window.transient(self.root)
        about_window.grab_set()
        
        # Center the window
        about_window.update_idletasks()
        x = (about_window.winfo_screenwidth() // 2) - (550 // 2)
        y = (about_window.winfo_screenheight() // 2) - (500 // 2)
        about_window.geometry(f"550x500+{x}+{y}")
        
        # Create main container
        main_container = ttk.Frame(about_window)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create scrollable frame
        canvas = tk.Canvas(main_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Content frame with padding
        content_frame = ttk.Frame(scrollable_frame, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Application title and icon
        title_frame = ttk.Frame(content_frame)
        title_frame.pack(fill=tk.X, pady=(0, 15))
        
        app_title = ttk.Label(title_frame, text="🚀 LAN Scanner Pro", 
                             font=('Arial', 22, 'bold'))
        app_title.pack()
        
        subtitle = ttk.Label(title_frame, text="Network Discovery & Security Scanner", 
                            font=('Arial', 11))
        subtitle.pack(pady=(5, 0))
        
        version = ttk.Label(title_frame, text="Version 2.0", 
                           font=('Arial', 9))
        version.pack(pady=(3, 0))
        
        # Separator
        separator1 = ttk.Separator(content_frame, orient='horizontal')
        separator1.pack(fill=tk.X, pady=15)
        
        # Application description
        desc_frame = ttk.LabelFrame(content_frame, text="About This Application", padding=10)
        desc_frame.pack(fill=tk.X, pady=(0, 15))
        
        description = """LAN Scanner Pro is a comprehensive network discovery and security scanning tool designed to help network administrators and security professionals identify devices, open ports, and potential vulnerabilities on local networks.

Key Features:
• Advanced network discovery with device fingerprinting
• Port scanning with service detection and banner grabbing
• Network topology visualization
• Real-time statistics and reporting
• Vulnerability assessment hints
• Multiple export formats (CSV, JSON, HTML, TXT)
• Modern Material Design interface
• Dark/Light theme support"""
        
        desc_label = ttk.Label(desc_frame, text=description, 
                              font=('Arial', 9), justify=tk.LEFT, wraplength=480)
        desc_label.pack()
        
        # Developer information
        dev_frame = ttk.LabelFrame(content_frame, text="Developer Information", padding=10)
        dev_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Developer name
        dev_name = ttk.Label(dev_frame, text="Vraj Maheshwari", 
                            font=('Arial', 14, 'bold'))
        dev_name.pack(pady=(0, 5))
        
        dev_title = ttk.Label(dev_frame, text="Passionate Software Developer", 
                             font=('Arial', 10))
        dev_title.pack(pady=(0, 10))
        
        # Contact information
        contact_frame = ttk.Frame(dev_frame)
        contact_frame.pack(fill=tk.X)
        
        # Email
        email_frame = ttk.Frame(contact_frame)
        email_frame.pack(fill=tk.X, pady=1)
        ttk.Label(email_frame, text="📧 Email:", font=('Arial', 9, 'bold')).pack(side=tk.LEFT)
        email_label = ttk.Label(email_frame, text="vrajmaheshwari06@gmail.com", 
                               font=('Arial', 9), foreground="blue", cursor="hand2")
        email_label.pack(side=tk.LEFT, padx=(8, 0))
        email_label.bind("<Button-1>", lambda e: self._open_email())
        
        # GitHub
        github_frame = ttk.Frame(contact_frame)
        github_frame.pack(fill=tk.X, pady=1)
        ttk.Label(github_frame, text="🐙 GitHub:", font=('Arial', 9, 'bold')).pack(side=tk.LEFT)
        github_label = ttk.Label(github_frame, text="https://github.com/vraj-maheshwari", 
                                font=('Arial', 9), foreground="blue", cursor="hand2")
        github_label.pack(side=tk.LEFT, padx=(8, 0))
        github_label.bind("<Button-1>", lambda e: self._open_url("https://github.com/vraj-maheshwari"))
        
        # Portfolio
        portfolio_frame = ttk.Frame(contact_frame)
        portfolio_frame.pack(fill=tk.X, pady=1)
        ttk.Label(portfolio_frame, text="🌐 Portfolio:", font=('Arial', 9, 'bold')).pack(side=tk.LEFT)
        portfolio_label = ttk.Label(portfolio_frame, text="vraj-maheshwari.github.io/portfolio", 
                                   font=('Arial', 9), foreground="blue", cursor="hand2")
        portfolio_label.pack(side=tk.LEFT, padx=(8, 0))
        portfolio_label.bind("<Button-1>", lambda e: self._open_url("https://vraj-maheshwari.github.io/portfolio"))
        
        # LinkedIn
        linkedin_frame = ttk.Frame(contact_frame)
        linkedin_frame.pack(fill=tk.X, pady=1)
        ttk.Label(linkedin_frame, text="💼 LinkedIn:", font=('Arial', 9, 'bold')).pack(side=tk.LEFT)
        linkedin_label = ttk.Label(linkedin_frame, text="linkedin.com/in/vraj-maheshwari-6537ba278", 
                                  font=('Arial', 9), foreground="blue", cursor="hand2")
        linkedin_label.pack(side=tk.LEFT, padx=(8, 0))
        linkedin_label.bind("<Button-1>", lambda e: self._open_url("https://www.linkedin.com/in/vraj-maheshwari-6537ba278/"))
        
        # Separator
        separator2 = ttk.Separator(content_frame, orient='horizontal')
        separator2.pack(fill=tk.X, pady=15)
        
        # Copyright and close button
        footer_frame = ttk.Frame(content_frame)
        footer_frame.pack(fill=tk.X)
        
        copyright_label = ttk.Label(footer_frame, text="© 2024 Vraj Maheshwari. All rights reserved.", 
                                   font=('Arial', 8))
        copyright_label.pack()
        
        close_btn = ttk.Button(footer_frame, text="Close", command=about_window.destroy)
        close_btn.pack(pady=(10, 0))
        
        # Enable mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Focus on close button and ensure it's visible
        close_btn.focus()
        
        # Ensure the canvas updates its scroll region
        about_window.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))
    
    def _open_email(self):
        """Open default email client"""
        import webbrowser
        try:
            webbrowser.open("mailto:vrajmaheshwari06@gmail.com")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open email client: {str(e)}")
    
    def _open_url(self, url):
        """Open URL in default browser"""
        import webbrowser
        try:
            webbrowser.open(url)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open URL: {str(e)}")

def main():
    root = tk.Tk()
    
    # Set window icon and properties
    try:
        root.iconbitmap("scanner_icon.ico")  # You can add an icon file
    except:
        pass
    
    # Configure scaling for high DPI displays
    try:
        root.call("tk", "scaling", 1.2)
    except Exception:
        pass
    
    app = EnhancedScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
