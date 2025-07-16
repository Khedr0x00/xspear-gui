import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import subprocess
import threading
import queue
import os
import sys
import re
import shlex # For robust command splitting

class XspearGUI:
    def __init__(self, master):
        self.master = master
        master.title("XSpear GUI")
        master.geometry("1200x900") # Increased window size
        master.resizable(True, True)
        master.grid_rowconfigure(0, weight=1) # Allow notebook to expand vertically
        master.grid_rowconfigure(1, weight=0) # Generated command frame
        master.grid_rowconfigure(2, weight=0) # Buttons frame
        master.grid_rowconfigure(3, weight=0) # Status bar
        master.grid_rowconfigure(4, weight=1) # Output frame to expand vertically
        master.grid_columnconfigure(0, weight=1) # Allow main column to expand horizontally

        self.xspear_process = None
        self.output_queue = queue.Queue()
        self.search_start_index = "1.0" # For incremental search

        # Configure style for ttk widgets
        self.style = ttk.Style()
        self.style.theme_use('clam') # 'clam', 'alt', 'default', 'classic'

        # --- Notebook (Tabs) ---
        self.notebook = ttk.Notebook(master)
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # --- Target Tab ---
        self.target_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.target_frame, text="Target")
        self._create_target_tab(self.target_frame)

        # --- Scan Options Tab ---
        self.scan_options_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.scan_options_frame, text="Scan Options")
        self._create_scan_options_tab(self.scan_options_frame)

        # --- Payload Options Tab ---
        self.payload_options_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.payload_options_frame, text="Payloads")
        self._create_payload_options_tab(self.payload_options_frame)

        # --- HTTP Options Tab ---
        self.http_options_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.http_options_frame, text="HTTP Options")
        self._create_http_options_tab(self.http_options_frame)

        # --- Output Tab ---
        self.output_options_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.output_options_frame, text="Output")
        self._create_output_options_tab(self.output_options_frame)

        # --- Advanced Tab ---
        self.advanced_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.advanced_frame, text="Advanced")
        self._create_advanced_tab(self.advanced_frame)

        # --- Generated Command ---
        self.command_frame = ttk.LabelFrame(master, text="Generated XSpear Command", padding="10 10 10 10")
        self.command_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.command_frame.grid_columnconfigure(0, weight=1)
        self.command_text = scrolledtext.ScrolledText(self.command_frame, height=3, width=80, font=("Consolas", 10), state=tk.DISABLED)
        self.command_text.grid(row=0, column=0, sticky="nsew")
        
        self.command_buttons_frame = ttk.Frame(self.command_frame)
        self.command_buttons_frame.grid(row=0, column=1, sticky="ne", padx=(10,0))
        self.copy_command_button = ttk.Button(self.command_buttons_frame, text="Copy Command", command=self.copy_command)
        self.copy_command_button.pack(pady=2)
        self.generate_command_button = ttk.Button(self.command_buttons_frame, text="Generate Command", command=self.generate_command)
        self.generate_command_button.pack(pady=2)

        # --- Buttons Frame ---
        self.button_frame = ttk.Frame(master, padding="10 0 10 5")
        self.button_frame.grid(row=2, column=0, sticky="ew")

        self.run_button = ttk.Button(self.button_frame, text="Run XSpear", command=self.run_xspear)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(self.button_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.save_output_button = ttk.Button(self.button_frame, text="Save Output", command=self.save_output)
        self.save_output_button.pack(side=tk.LEFT, padx=5)

        # --- Status Bar ---
        self.status_bar = ttk.Label(master, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=3, column=0, sticky="ew")

        # --- Output Frame ---
        self.output_frame = ttk.LabelFrame(master, text="XSpear Output", padding="10 10 10 10")
        self.output_frame.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.output_frame.grid_rowconfigure(1, weight=1) # Make the output_text expand vertically
        self.output_frame.grid_columnconfigure(0, weight=1) # Make the search_frame and output_text expand horizontally

        # Search functionality for output
        self.search_frame = ttk.Frame(self.output_frame)
        self.search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        self.search_frame.grid_columnconfigure(1, weight=1) # Make search entry expand
        ttk.Label(self.search_frame, text="Search:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.search_entry = ttk.Entry(self.search_frame, width=50)
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        self.search_entry.bind("<Return>", self.search_output) # Bind Enter key
        ttk.Button(self.search_frame, text="Search", command=self.search_output).grid(row=0, column=2, sticky="e", padx=(0, 5))
        ttk.Button(self.search_frame, text="Clear Search", command=self.clear_search_highlight).grid(row=0, column=3, sticky="e")

        self.output_text = scrolledtext.ScrolledText(self.output_frame, wrap=tk.WORD, bg="black", fg="white", font=("Consolas", 10), height=30)
        self.output_text.grid(row=1, column=0, sticky="nsew")
        self.output_text.config(state=tk.DISABLED) # Make it read-only

        # Configure tag for highlighting search results
        self.output_text.tag_configure("highlight", background="yellow", foreground="black")

        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.master.after(100, self.process_queue) # Start checking the queue
        self.generate_command() # Generate initial command on startup

    def _create_input_field(self, parent_frame, label_text, row, entry_name, col=0, width=40, is_checkbox=False, var_name=None, help_text=None, options=None, is_dropdown=False):
        if is_checkbox:
            var = tk.BooleanVar()
            setattr(self, var_name, var)
            chk = ttk.Checkbutton(parent_frame, text=label_text, variable=var, command=self.generate_command)
            chk.grid(row=row, column=col, sticky="w", pady=2)
            if help_text:
                help_button = ttk.Button(parent_frame, text="?", width=2, command=lambda t=help_text: self._show_help_popup(t))
                help_button.grid(row=row, column=col + 1, sticky="w", padx=(5, 0))
            return chk
        elif is_dropdown and options:
            label = ttk.Label(parent_frame, text=label_text)
            label.grid(row=row, column=col, sticky="w", pady=2, padx=(0, 5))
            var = tk.StringVar()
            setattr(self, var_name, var)
            dropdown = ttk.Combobox(parent_frame, textvariable=var, values=options, state="readonly", width=width)
            dropdown.grid(row=row, column=col+1, sticky="ew", pady=2)
            dropdown.set(options[0]) # Set default value
            dropdown.bind("<<ComboboxSelected>>", lambda event: self.generate_command())
            if help_text:
                help_button = ttk.Button(parent_frame, text="?", width=2, command=lambda t=help_text: self._show_help_popup(t))
                help_button.grid(row=row, column=col + 2, sticky="w", padx=(5, 0))
            return dropdown
        else:
            label = ttk.Label(parent_frame, text=label_text)
            label.grid(row=row, column=col, sticky="w", pady=2, padx=(0, 5))
            if entry_name and ("headers_entry" in entry_name or "data_entry" in entry_name or "additional_args_entry" in entry_name): # Use ScrolledText for larger inputs
                entry = scrolledtext.ScrolledText(parent_frame, height=4, width=width, font=("Consolas", 10))
            else:
                entry = ttk.Entry(parent_frame, width=width)
            
            entry.grid(row=row, column=col+1, sticky="ew", pady=2)
            setattr(self, entry_name, entry)
            entry.bind("<KeyRelease>", lambda event: self.generate_command()) # Update command on key release
            if help_text:
                help_button = ttk.Button(parent_frame, text="?", width=2, command=lambda t=help_text: self._show_help_popup(t))
                help_button.grid(row=row, column=col + 2, sticky="w", padx=(5, 0))
            return entry

    def _show_help_popup(self, help_text):
        popup = tk.Toplevel(self.master)
        popup.title("Help")
        popup.transient(self.master) # Make it appear on top of the main window
        popup.grab_set() # Disable interaction with the main window

        # Calculate position to center it relative to the main window
        main_x = self.master.winfo_x()
        main_y = self.master.winfo_y()
        main_width = self.master.winfo_width()
        main_height = self.master.winfo_height()

        popup_width = 500
        popup_height = 300
        popup_x = main_x + (main_width // 2) - (popup_width // 2)
        popup_y = main_y + (main_height // 2) - (popup_height // 2)
        popup.geometry(f"{popup_width}x{popup_height}+{popup_x}+{popup_y}")
        popup.resizable(False, False)

        text_widget = scrolledtext.ScrolledText(popup, wrap=tk.WORD, font=("Consolas", 10), width=60, height=15)
        text_widget.pack(expand=True, fill="both", padx=10, pady=10)
        text_widget.insert(tk.END, help_text)
        text_widget.config(state=tk.DISABLED)

        close_button = ttk.Button(popup, text="Close", command=popup.destroy)
        close_button.pack(pady=5)

    def _create_target_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "Target URL (-u):", row, "url_entry", width=60,
                                 help_text="Target URL to scan for XSS. Example: 'http://example.com/search?q=test'")
        row += 1
        self._create_input_field(parent_frame, "Target List File (-l):", row, "list_file_entry", width=60,
                                 help_text="File containing a list of URLs to scan (one per line).")
        row += 1
        self._create_input_field(parent_frame, "POST Data (-d):", row, "data_entry", width=60,
                                 help_text="POST data to send with the request. Example: 'param1=value1&param2=value2'")
        row += 1
        self._create_input_field(parent_frame, "Headers (-H):", row, "headers_entry", width=60,
                                 help_text="Custom HTTP headers. Format: 'Header-Name: Value'. Use one per line.")
        row += 1
        self._create_input_field(parent_frame, "Cookies (-c):", row, "cookie_entry", width=60,
                                 help_text="Custom HTTP cookies. Format: 'name=value; name2=value2'.")
        row += 1
        self._create_input_field(parent_frame, "Proxy (-x):", row, "proxy_entry", width=60,
                                 help_text="HTTP/S proxy to use. Example: http://127.0.0.1:8080")
        row += 1
        self._create_input_field(parent_frame, "Request File (--request):", row, "request_file_entry", width=60,
                                 help_text="File containing the full HTTP request to use as a template.")

    def _create_scan_options_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "Scan Mode (-m):", row, "scan_mode_entry", width=20, is_dropdown=True, var_name="scan_mode_var",
                                 options=["", "normal", "blind", "dom", "all"],
                                 help_text="Specify scan mode. 'normal' (default), 'blind', 'dom', 'all'.")
        self.scan_mode_var.set("normal") # Default
        row += 1
        self._create_input_field(parent_frame, "Concurrency (-t):", row, "concurrency_entry", width=10,
                                 help_text="Number of concurrent requests (default: 10).")
        row += 1
        self._create_input_field(parent_frame, "Delay (--delay):", row, "delay_entry", width=10,
                                 help_text="Delay between requests in seconds. Example: 0.5")
        row += 1
        self._create_input_field(parent_frame, "Timeout (--timeout):", row, "timeout_entry", width=10,
                                 help_text="Timeout for each request in seconds (default: 10).")
        row += 1
        self._create_input_field(parent_frame, "Level (--level):", row, "level_entry", width=10,
                                 help_text="Level of tests to perform (1-5, default: 1). Higher levels include more tests.")
        row += 1
        self._create_input_field(parent_frame, "Risk (--risk):", row, "risk_entry", width=10,
                                 help_text="Risk of tests to perform (1-3, default: 1). Higher risks include more aggressive tests.")
        row += 1
        self.skip_waf_check_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Skip WAF Check (--skip-waf):", row, None, is_checkbox=True, var_name="skip_waf_check_var",
                                 help_text="Skip WAF detection and bypass tests.")
        row += 1
        self.no_dom_check_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "No DOM Check (--no-dom):", row, None, is_checkbox=True, var_name="no_dom_check_var",
                                 help_text="Disable DOM XSS checks.")

    def _create_payload_options_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "Custom Payload (-p):", row, "payload_entry", width=60,
                                 help_text="Custom XSS payload to use. Example: '<script>alert(1)</script>'")
        row += 1
        self._create_input_field(parent_frame, "Payload File (-pf):", row, "payload_file_entry", width=60,
                                 help_text="Path to a file containing custom XSS payloads (one per line).")
        row += 1
        self._create_input_field(parent_frame, "Encode Payload (--encode):", row, "encode_payload_entry", width=20, is_dropdown=True, var_name="encode_payload_var",
                                 options=["", "html", "url", "base64", "js", "all"],
                                 help_text="Encode payloads with specified method(s). Comma-separated for multiple.")
        row += 1
        self._create_input_field(parent_frame, "Blind XSS Callback (--blind-callback):", row, "blind_callback_entry", width=60,
                                 help_text="URL for blind XSS callback (e.g., your interactsh server).")
        row += 1
        self._create_input_field(parent_frame, "Skip Payload Encoding (--skip-encoding):", row, "skip_encoding_entry", width=60,
                                 help_text="Skip encoding for specific payloads. Comma-separated.")

    def _create_http_options_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "HTTP Method (--method):", row, "method_entry", width=20, is_dropdown=True, var_name="method_var",
                                 options=["", "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"],
                                 help_text="HTTP method to use for requests. Overrides method from raw file.")
        row += 1
        self._create_input_field(parent_frame, "User-Agent (--user-agent):", row, "user_agent_entry", width=60,
                                 help_text="Custom User-Agent header.")
        row += 1
        self.random_agent_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Random User-Agent (--random-agent):", row, None, is_checkbox=True, var_name="random_agent_var",
                                 help_text="Use a random User-Agent for each request.")
        row += 1
        self.ignore_ssl_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Ignore SSL (--ignore-ssl):", row, None, is_checkbox=True, var_name="ignore_ssl_var",
                                 help_text="Ignore SSL certificate errors.")
        row += 1
        self.follow_redirects_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Follow Redirects (--follow-redirects):", row, None, is_checkbox=True, var_name="follow_redirects_var",
                                 help_text="Follow HTTP redirects.")
        row += 1
        self._create_input_field(parent_frame, "Referer (--referer):", row, "referer_entry", width=60,
                                 help_text="Set a custom Referer header.")
        row += 1
        self._create_input_field(parent_frame, "Auth Header (--auth):", row, "auth_entry", width=60,
                                 help_text="Set an Authorization header. Example: 'Bearer TOKEN' or 'Basic BASE64_CREDS'")

    def _create_output_options_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "Output File (-o):", row, "output_file_entry", width=60,
                                 help_text="Save results to a file.")
        row += 1
        self._create_input_field(parent_frame, "Output Format (--format):", row, "output_format_entry", width=20, is_dropdown=True, var_name="output_format_var",
                                 options=["", "json", "html", "csv", "text"],
                                 help_text="Output format (json, html, csv, text).")
        row += 1
        self.verbose_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Verbose (-v):", row, None, is_checkbox=True, var_name="verbose_var",
                                 help_text="Show verbose output.")
        row += 1
        self.silent_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Silent (-s):", row, None, is_checkbox=True, var_name="silent_var",
                                 help_text="Suppress all output except errors.")
        row += 1
        self.no_color_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "No Color (--no-color):", row, None, is_checkbox=True, var_name="no_color_var",
                                 help_text="Disable colored output.")
        row += 1
        self.debug_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Debug (--debug):", row, None, is_checkbox=True, var_name="debug_var",
                                 help_text="Enable debug mode.")

    def _create_advanced_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "Custom Parameter (--param):", row, "custom_param_entry", width=60,
                                 help_text="Specify a custom parameter name for XSS testing. Example: 'query'")
        row += 1
        self._create_input_field(parent_frame, "Skip Parameters (--skip-param):", row, "skip_param_entry", width=60,
                                 help_text="Skip testing specific parameters. Comma-separated. Example: 'id,name'")
        row += 1
        self._create_input_field(parent_frame, "Custom Headers File (--headers-file):", row, "headers_file_entry", width=60,
                                 help_text="File containing custom HTTP headers (one per line).")
        row += 1
        self._create_input_field(parent_frame, "Custom Cookies File (--cookies-file):", row, "cookies_file_entry", width=60,
                                 help_text="File containing custom HTTP cookies (one per line).")
        row += 1
        self._create_input_field(parent_frame, "Additional Arguments:", row, "additional_args_entry", width=60,
                                 help_text="Any other XSpear arguments not covered by the GUI.")

    def generate_command(self):
        command_parts = ["xspear"]

        # Helper to add arguments if value is not empty
        def add_arg(arg_name, entry_widget, is_text_area=False):
            if is_text_area:
                value = entry_widget.get("1.0", tk.END).strip()
            else:
                value = entry_widget.get().strip()
            if value:
                command_parts.append(arg_name)
                command_parts.append(shlex.quote(value)) # Quote values to handle spaces

        # Helper to add checkbox arguments
        def add_checkbox_arg(arg_name, var_widget):
            if var_widget.get():
                command_parts.append(arg_name)

        # Helper to add dropdown arguments
        def add_dropdown_arg(arg_name, var_widget):
            value = var_widget.get().strip()
            if value:
                command_parts.append(arg_name)
                command_parts.append(shlex.quote(value))

        # Target Tab
        add_arg("-u", self.url_entry)
        add_arg("-l", self.list_file_entry)
        add_arg("-d", self.data_entry, is_text_area=True)
        headers = self.headers_entry.get("1.0", tk.END).strip()
        if headers:
            for header_line in headers.split('\n'):
                header_line = header_line.strip()
                if header_line:
                    command_parts.append("-H")
                    command_parts.append(shlex.quote(header_line))
        add_arg("-c", self.cookie_entry)
        add_arg("-x", self.proxy_entry)
        add_arg("--request", self.request_file_entry)

        # Scan Options Tab
        add_dropdown_arg("-m", self.scan_mode_var)
        add_arg("-t", self.concurrency_entry)
        add_arg("--delay", self.delay_entry)
        add_arg("--timeout", self.timeout_entry)
        add_arg("--level", self.level_entry)
        add_arg("--risk", self.risk_entry)
        add_checkbox_arg("--skip-waf", self.skip_waf_check_var)
        add_checkbox_arg("--no-dom", self.no_dom_check_var)

        # Payload Options Tab
        add_arg("-p", self.payload_entry)
        add_arg("-pf", self.payload_file_entry)
        add_dropdown_arg("--encode", self.encode_payload_var)
        add_arg("--blind-callback", self.blind_callback_entry)
        add_arg("--skip-encoding", self.skip_encoding_entry)

        # HTTP Options Tab
        add_dropdown_arg("--method", self.method_var)
        add_arg("--user-agent", self.user_agent_entry)
        add_checkbox_arg("--random-agent", self.random_agent_var)
        add_checkbox_arg("--ignore-ssl", self.ignore_ssl_var)
        add_checkbox_arg("--follow-redirects", self.follow_redirects_var)
        add_arg("--referer", self.referer_entry)
        add_arg("--auth", self.auth_entry)

        # Output Tab
        add_arg("-o", self.output_file_entry)
        add_dropdown_arg("--format", self.output_format_var)
        add_checkbox_arg("-v", self.verbose_var)
        add_checkbox_arg("-s", self.silent_var)
        add_checkbox_arg("--no-color", self.no_color_var)
        add_checkbox_arg("--debug", self.debug_var)

        # Advanced Tab
        add_arg("--param", self.custom_param_entry)
        add_arg("--skip-param", self.skip_param_entry)
        add_arg("--headers-file", self.headers_file_entry)
        add_arg("--cookies-file", self.cookies_file_entry)
        
        # Additional Arguments
        additional_args = self.additional_args_entry.get("1.0", tk.END).strip()
        if additional_args:
            try:
                split_args = shlex.split(additional_args)
                command_parts.extend(split_args)
            except ValueError:
                messagebox.showwarning("Command Generation Error", "Could not parse additional arguments. Please check quotes.")
                command_parts.append(additional_args) # Fallback

        generated_cmd = " ".join(command_parts)
        self.command_text.config(state=tk.NORMAL)
        self.command_text.delete(1.0, tk.END)
        self.command_text.insert(tk.END, generated_cmd)
        self.command_text.config(state=tk.DISABLED)

    def copy_command(self):
        command_to_copy = self.command_text.get("1.0", tk.END).strip()
        self.master.clipboard_clear()
        self.master.clipboard_append(command_to_copy)
        messagebox.showinfo("Copy Command", "Command copied to clipboard!")

    def run_xspear(self):
        if self.xspear_process and self.xspear_process.poll() is None:
            messagebox.showwarning("XSpear Running", "XSpear is already running. Please wait for it to finish or close the application.")
            return

        self.clear_output()
        self.status_bar.config(text="XSpear is running...")
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, "Starting XSpear...\n")
        self.output_text.config(state=tk.DISABLED)

        # Generate the command just before running to ensure it's up-to-date
        self.generate_command()
        command_str = self.command_text.get("1.0", tk.END).strip()
        
        # Use shlex.split to correctly handle quoted arguments for subprocess
        try:
            command = shlex.split(command_str)
        except ValueError as e:
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, f"Error parsing command: {e}\n")
            self.output_text.config(state=tk.DISABLED)
            self.status_bar.config(text="Error")
            return

        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, f"Executing command: {command_str}\n\n")
        self.output_text.config(state=tk.DISABLED)

        # Run xspear in a separate thread
        self.xspear_thread = threading.Thread(target=self._run_xspear_thread, args=(command,))
        self.xspear_thread.daemon = True
        self.xspear_thread.start()

    def _run_xspear_thread(self, command):
        try:
            # Check if xspear is available in PATH
            import shutil
            if shutil.which(command[0]) is None:
                self.output_queue.put(f"Error: '{command[0]}' not found in system PATH. Please ensure xspear is installed and accessible.\n")
                self.output_queue.put("STATUS: Error\n")
                return

            self.xspear_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1, # Line-buffered
                universal_newlines=True
            )

            # Use a separate thread for reading stdout/stderr to avoid blocking
            def read_output(pipe, output_queue):
                for line in iter(pipe.readline, ''):
                    output_queue.put(line)
                pipe.close()

            stdout_thread = threading.Thread(target=read_output, args=(self.xspear_process.stdout, self.output_queue))
            stderr_thread = threading.Thread(target=read_output, args=(self.xspear_process.stderr, self.output_queue))
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()

            # Wait for xspear process to finish
            self.xspear_process.wait()
            return_code = self.xspear_process.returncode
            self.output_queue.put(f"\nXSpear finished with exit code: {return_code}\n")
            self.output_queue.put(f"STATUS: {'Completed' if return_code == 0 else 'Failed'}\n")

        except FileNotFoundError:
            self.output_queue.put("Error: xspear command not found. Make sure xspear is installed and in your system's PATH.\n")
            self.output_queue.put("STATUS: Error\n")
        except Exception as e:
            self.output_queue.put(f"An error occurred: {e}\n")
            self.output_queue.put("STATUS: Error\n")
        finally:
            self.master.after(0, lambda: setattr(self, 'xspear_process', None)) # Clear process on main thread
            self.master.after(0, lambda: self.status_bar.config(text="Ready")) # Update status bar on main thread

    def process_queue(self):
        while not self.output_queue.empty():
            try:
                line = self.output_queue.get_nowait()
                self.output_text.config(state=tk.NORMAL)
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END) # Scroll to the end
                self.output_text.config(state=tk.DISABLED)
            except queue.Empty:
                pass
        
        if self.xspear_process and self.xspear_process.poll() is None:
            self.status_bar.config(text="XSpear is running...")
        else:
            self.status_bar.config(text="Ready")

        self.master.after(100, self.process_queue)

    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.status_bar.config(text="Ready")
        self.clear_search_highlight() # Clear highlights when output is cleared

    def save_output(self):
        output_content = self.output_text.get("1.0", tk.END)
        if not output_content.strip():
            messagebox.showinfo("Save Output", "No output to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(output_content)
                messagebox.showinfo("Save Output", f"Output saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save file: {e}")

    def search_output(self, event=None):
        search_term = self.search_entry.get().strip()
        self.clear_search_highlight() # Clear previous highlights

        if not search_term:
            self.search_start_index = "1.0" # Reset search start
            return

        self.output_text.config(state=tk.NORMAL)
        
        # Start search from the beginning if it's a new search or no more matches from current position
        if self.search_start_index == "1.0" or not self.output_text.search(search_term, self.search_start_index, tk.END, nocase=1):
            self.search_start_index = "1.0"

        idx = self.output_text.search(search_term, self.search_start_index, tk.END, nocase=1)
        if idx:
            end_idx = f"{idx}+{len(search_term)}c"
            self.output_text.tag_add("highlight", idx, end_idx)
            self.output_text.see(idx) # Scroll to the found text
            self.search_start_index = end_idx # Set start for next search
        else:
            messagebox.showinfo("Search", f"No more occurrences of '{search_term}' found.")
            self.search_start_index = "1.0" # Reset for next search attempt

        self.output_text.config(state=tk.DISABLED)

    def clear_search_highlight(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.tag_remove("highlight", "1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.search_start_index = "1.0" # Reset search start index

    def on_closing(self):
        if self.xspear_process and self.xspear_process.poll() is None:
            if messagebox.askokcancel("Quit", "XSpear is still running. Do you want to terminate it and quit?"):
                self.xspear_process.terminate()
                self.master.destroy()
        else:
            self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = XspearGUI(root)
    root.mainloop()
