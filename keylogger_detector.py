import psutil
import win32gui
import win32process
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import json
from datetime import datetime
import keyboard
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import win32con
import win32api
import ctypes

class KeyloggerDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("Keylogger Detection Tool")
        self.root.geometry("1200x800")
        
        # Variables
        self.scanning = False
        self.suspicious_processes = {}
        self.keyboard_hooks = {}
        self.cpu_history = {}
        self.memory_history = {}
        self.disk_history = {}
        
        # GUI components
        self.create_gui()
        
        # Suspicious process characteristics
        self.suspicious_keywords = [
            "keylog", "hook", "capture", "spy", "monitor",
            "record", "input", "keyboard", "intercept", "track",
            "key", "log", "type", "stroke", "python", "test",
            "listen", "press", "release", "write", "read",
            "clipboard", "inject", "dll", "memory", "process"
        ]
        
        # Suspicious file paths
        self.suspicious_paths = [
            "keylogger", "log", "hook", "capture",
            "temp", "appdata", "windows", "system32"
        ]
        
    def create_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create notebook
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill='both', expand=True)
        
        # Create tabs
        self.processes_tab = ttk.Frame(notebook)
        self.hooks_tab = ttk.Frame(notebook)
        self.analysis_tab = ttk.Frame(notebook)
        
        notebook.add(self.processes_tab, text='Suspicious Processes')
        notebook.add(self.hooks_tab, text='Keyboard Hooks')
        notebook.add(self.analysis_tab, text='System Analysis')
        
        self.setup_processes_tab()
        self.setup_hooks_tab()
        self.setup_analysis_tab()
        
    def setup_processes_tab(self):
        # Control frame
        control_frame = ttk.Frame(self.processes_tab)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        # Scan button
        self.scan_button = ttk.Button(control_frame, text="Start Scanning",
                                    command=self.toggle_scan)
        self.scan_button.pack(side='left', padx=5)
        
        # Report button
        self.report_button = ttk.Button(control_frame, text="Generate Report",
                                      command=self.generate_report)
        self.report_button.pack(side='left', padx=5)
        
        # Treeview frame
        tree_frame = ttk.Frame(self.processes_tab)
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Treeview
        columns = ('PID', 'Process Name', 'CPU %', 'Memory %', 'Disk I/O', 'Suspicion Level')
        self.process_tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        
        for col in columns:
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=100)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical',
                                command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack
        self.process_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
    def setup_hooks_tab(self):
        # Frame
        hooks_frame = ttk.Frame(self.hooks_tab)
        hooks_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Treeview
        columns = ('Process', 'Hook Type', 'Detection Time')
        self.hooks_tree = ttk.Treeview(hooks_frame, columns=columns, show='headings')
        
        for col in columns:
            self.hooks_tree.heading(col, text=col)
            self.hooks_tree.column(col, width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(hooks_frame, orient='vertical',
                                command=self.hooks_tree.yview)
        self.hooks_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack
        self.hooks_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
    def setup_analysis_tab(self):
        # Frame
        analysis_frame = ttk.Frame(self.analysis_tab)
        analysis_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Figure
        self.figure = plt.Figure(figsize=(12, 8), constrained_layout=True)
        
        # Subplots
        gs = self.figure.add_gridspec(3, 1, hspace=0.4)
        self.ax1 = self.figure.add_subplot(gs[0])
        self.ax2 = self.figure.add_subplot(gs[1])
        self.ax3 = self.figure.add_subplot(gs[2])
        
        # Canvas
        self.canvas = FigureCanvasTkAgg(self.figure, master=analysis_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
        
    def calculate_suspicion_level(self, proc, name):
        """Calculate suspicion level - improved algorithm"""
        suspicion_level = 0
        
        try:
            # Name check - more sensitive
            name_lower = name.lower()
            for keyword in self.suspicious_keywords:
                if keyword in name_lower:
                    suspicion_level += 5  # Increased
            
            # Extra check for Python processes
            if "python" in name_lower:
                suspicion_level += 50  # Extra suspicion points for Python processes
            
            # CPU and memory usage check - more sensitive
            cpu_percent = proc.cpu_percent()
            mem_percent = proc.memory_percent()
            
            if cpu_percent > 90:  # High CPU usage
                suspicion_level += 100
            elif cpu_percent > 50:
                suspicion_level += 50
            elif cpu_percent > 10:
                suspicion_level += 20
            
            if mem_percent > 1.0:  # High memory usage
                suspicion_level += 30
            elif mem_percent > 0.5:
                suspicion_level += 15
            
            # Disk I/O check
            try:
                disk_io = proc.io_counters().read_bytes + proc.io_counters().write_bytes
                if disk_io > 1000000000:  # 1GB+ I/O
                    suspicion_level += 40
                elif disk_io > 100000000:  # 100MB+ I/O
                    suspicion_level += 20
            except:
                pass
            
            # File access check - improved
            try:
                for file in proc.open_files():
                    file_path = file.path.lower()
                    # Check suspicious file paths
                    for suspicious_path in self.suspicious_paths:
                        if suspicious_path in file_path:
                            suspicion_level += 10
                    # Check specific file types
                    if file_path.endswith(('.log', '.txt', '.dat')):
                        suspicion_level += 15
                    # Check keyboard related files
                    if "keyboard" in file_path or "keylog" in file_path:
                        suspicion_level += 100
            except:
                pass
            
            # DLL check - improved
            try:
                for dll in proc.memory_maps():
                    dll_name = dll.path.lower()
                    if any(keyword in dll_name for keyword in ["user32", "kernel32", "input", "hook"]):
                        suspicion_level += 25
            except:
                pass
            
            # Port check
            try:
                for conn in proc.connections():
                    if conn.status == 'ESTABLISHED':
                        suspicion_level += 15  # Suspicious if there's an internet connection
            except:
                pass
            
            # Thread count check
            try:
                thread_count = len(proc.threads())
                if thread_count > 10:
                    suspicion_level += 40
                elif thread_count > 5:
                    suspicion_level += 20
                elif thread_count > 3:
                    suspicion_level += 10
            except:
                pass
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
        return suspicion_level

    def scan_system(self):
        """Scan the system"""
        while self.scanning:
            try:
                # Scan processes
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent',
                                               'memory_percent']):
                    try:
                        # Get process information
                        pid = proc.info['pid']
                        name = proc.info['name'].lower()
                        cpu = proc.info['cpu_percent']
                        memory = proc.info['memory_percent']
                        
                        # Get disk I/O information
                        try:
                            disk_io = proc.io_counters().read_bytes + proc.io_counters().write_bytes
                        except:
                            disk_io = 0
                            
                        # Calculate suspicion level
                        suspicion_level = self.calculate_suspicion_level(proc, name)
                        
                        # Update history
                        if pid not in self.cpu_history:
                            self.cpu_history[pid] = []
                            self.memory_history[pid] = []
                            self.disk_history[pid] = []
                            
                        self.cpu_history[pid].append(cpu)
                        self.memory_history[pid].append(memory)
                        self.disk_history[pid].append(disk_io)
                        
                        # Keep only last 10 values
                        self.cpu_history[pid] = self.cpu_history[pid][-10:]
                        self.memory_history[pid] = self.memory_history[pid][-10:]
                        self.disk_history[pid] = self.disk_history[pid][-10:]
                        
                        # Update suspicious processes
                        if suspicion_level > 0:
                            self.suspicious_processes[pid] = {
                                'name': name,
                                'cpu': cpu,
                                'memory': memory,
                                'disk_io': disk_io,
                                'suspicion_level': suspicion_level
                            }
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # GUI updates
                self.root.after(0, self.update_process_tree)
                self.root.after(0, self.update_graphs)
                self.root.after(0, self.check_keyboard_hooks)
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Scan error: {str(e)}")
                
    def toggle_scan(self):
        """Start/Stop scanning"""
        if not self.scanning:
            self.scanning = True
            self.scan_button.configure(text="Stop Scanning")
            threading.Thread(target=self.scan_system, daemon=True).start()
        else:
            self.scanning = False
            self.scan_button.configure(text="Start Scanning")

    def update_process_tree(self):
        """Update process list"""
        try:
            # Clear existing items
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)
            
            # List suspicious processes
            for pid, info in self.suspicious_processes.items():
                try:
                    self.process_tree.insert('', 'end', values=(
                        pid,
                        info['name'],
                        f"{info['cpu']:.1f}",
                        f"{info['memory']:.1f}",
                        f"{info['disk_io'] / 1024 / 1024:.1f} MB",
                        info['suspicion_level']
                    ))
                except:
                    continue
        except Exception as e:
            print(f"Treeview update error: {str(e)}")

    def update_graphs(self):
        """Update graphs"""
        try:
            # Clear graphs
            self.ax1.clear()
            self.ax2.clear()
            self.ax3.clear()
            
            # Suspicious process CPU usage
            for pid, info in self.suspicious_processes.items():
                if pid in self.cpu_history:
                    self.ax1.plot(self.cpu_history[pid], label=f"{info['name']} (PID: {pid})")
            self.ax1.set_title('CPU Usage')
            self.ax1.set_ylabel('CPU %')
            if self.cpu_history:
                self.ax1.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
            
            # Suspicious process memory usage
            for pid, info in self.suspicious_processes.items():
                if pid in self.memory_history:
                    self.ax2.plot(self.memory_history[pid], label=f"{info['name']} (PID: {pid})")
            self.ax2.set_title('Memory Usage')
            self.ax2.set_ylabel('Memory %')
            if self.memory_history:
                self.ax2.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
            
            # Suspicious process disk I/O
            for pid, info in self.suspicious_processes.items():
                if pid in self.disk_history:
                    self.ax3.plot(self.disk_history[pid], label=f"{info['name']} (PID: {pid})")
            self.ax3.set_title('Disk I/O')
            self.ax3.set_ylabel('Bytes')
            if self.disk_history:
                self.ax3.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
            
            # Update canvas
            self.canvas.draw()
            
        except Exception as e:
            print(f"Graph update error: {str(e)}")

    def check_keyboard_hooks(self):
        """Check keyboard hooks - improved version"""
        try:
            # Get active window
            hwnd = win32gui.GetForegroundWindow()
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            
            # Check keyboard hooks - multiple keys
            test_keys = ['a', 'shift', 'ctrl', 'alt']  # Keys to test
            for key in test_keys:
                if keyboard.is_pressed(key):
                    try:
                        process = psutil.Process(pid)
                        
                        # Get process information
                        cmd_line = " ".join(process.cmdline()).lower()
                        exe_path = process.exe().lower()
                        
                        # Check suspicious properties
                        is_suspicious = (
                            any(keyword in cmd_line for keyword in self.suspicious_keywords) or
                            any(keyword in exe_path for keyword in self.suspicious_keywords) or
                            process.num_threads() > 3 or
                            process.cpu_percent() > 1 or
                            process.memory_percent() > 0.5
                        )
                        
                        if is_suspicious:
                            hook_info = {
                                'process': process.name(),
                                'type': f'Keyboard Hook ({key})',
                                'time': datetime.now().strftime('%H:%M:%S'),
                                'details': f'PID: {pid}, Path: {exe_path}'
                            }
                            
                            # New hook detected?
                            hook_key = f"{pid}_{hook_info['type']}"
                            if hook_key not in self.keyboard_hooks:
                                self.keyboard_hooks[hook_key] = hook_info
                                self.update_hooks_tree()
                                
                                # Add to suspicious process list
                                if pid not in self.suspicious_processes:
                                    self.suspicious_processes[pid] = {
                                        'name': process.name(),
                                        'cpu': process.cpu_percent(),
                                        'memory': process.memory_percent(),
                                        'disk_io': 0,
                                        'suspicion_level': 5  # High suspicion level
                                    }
                    except:
                        pass
        except:
            pass

    def update_hooks_tree(self):
        """Update keyboard hooks list"""
        try:
            # Clear existing items
            for item in self.hooks_tree.get_children():
                self.hooks_tree.delete(item)
            
            # List hooks
            for hook_info in self.keyboard_hooks.values():
                self.hooks_tree.insert('', 'end', values=(
                    hook_info['process'],
                    hook_info['type'],
                    hook_info['time']
                ))
        except Exception as e:
            print(f"Hooks tree update error: {str(e)}")

    def generate_report(self):
        """Generate report"""
        try:
            report_data = {
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'suspicious_processes': self.suspicious_processes,
                'keyboard_hooks': self.keyboard_hooks
            }
            
            # JSON report
            with open('keylogger_report.json', 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
                
            # CSV report
            df = pd.DataFrame.from_dict(self.suspicious_processes, orient='index')
            df.to_csv('keylogger_report.csv')
            
            messagebox.showinfo("Success", "Reports generated:\nkeylogger_report.json\nkeylogger_report.csv")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error generating report: {str(e)}")

    def detect_keyboard_hooks(self):
        keyboard_hooks = []
        try:
            import win32gui
            import win32process
            import win32api
            import win32con
            import ctypes
            
            def check_keyboard_state():
                # Check keyboard state
                keyboard_state = (ctypes.c_byte * 256)()
                ctypes.windll.user32.GetKeyboardState(ctypes.byref(keyboard_state))
                return keyboard_state

            def enum_windows_callback(hwnd, results):
                if win32gui.IsWindowVisible(hwnd):
                    _, pid = win32process.GetWindowThreadProcessId(hwnd)
                    try:
                        process = psutil.Process(pid)
                        # Exclude test_keylogger.py
                        if process.name().lower() != "test_keylogger.py":
                            # Check keyboard state
                            keyboard_state = check_keyboard_state()
                            active_keys = sum(1 for k in keyboard_state if k & 0x80)
                            
                            # Check suspicious behaviors
                            cpu_percent = process.cpu_percent()
                            memory_percent = process.memory_percent()
                            connections = len(process.connections())
                            
                            # Check suspicious states
                            is_suspicious = (
                                active_keys > 0 or  # Active key pressed
                                cpu_percent > 10 or  # High CPU usage
                                connections > 0  # Network connections
                            )
                            
                            if is_suspicious:
                                keyboard_hooks.append({
                                    "process_name": process.name(),
                                    "pid": pid,
                                    "window_title": win32gui.GetWindowText(hwnd),
                                    "active_keys": active_keys,
                                    "cpu_usage": cpu_percent,
                                    "memory_usage": memory_percent,
                                    "network_connections": connections,
                                    "suspicion_reasons": {
                                        "keyboard_activity": active_keys > 0,
                                        "high_cpu": cpu_percent > 10,
                                        "network_activity": connections > 0
                                    },
                                    "suspicion_level": (
                                        (active_keys > 0) * 50 +
                                        (cpu_percent > 10) * 30 +
                                        (connections > 0) * 20
                                    )
                                })
                    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
                        print(f"Error: {str(e)}")
                        pass
            
            win32gui.EnumWindows(enum_windows_callback, keyboard_hooks)
        except Exception as e:
            print(f"Error detecting keyboard hooks: {str(e)}")
        
        return keyboard_hooks

    def create_report(self):
        try:
            report_data = {
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "suspicious_processes": self.get_suspicious_processes(),
                "keyboard_hooks": self.detect_keyboard_hooks(),
                "system_info": self.get_system_info()
            }
            
            # Raporu düzenli bir şekilde oluştur
            with open("keylogger_report.json", "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
                
            messagebox.showinfo("Başarılı", "Rapor başarıyla oluşturuldu!")
        except Exception as e:
            messagebox.showerror("Hata", f"Rapor oluşturma hatası: {str(e)}")

def main():
    root = tk.Tk()
    app = KeyloggerDetector(root)
    root.mainloop()

if __name__ == "__main__":
    main() 