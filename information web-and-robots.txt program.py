import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
import socket
import time
import threading

# --- Color Configuration ---
background_color = "#f5f5dc"  # Beige
frame_color = "#e8e8e8"        # Light Gray
button_color = "#4682b4"        # Steel Blue
button_text_color = "white"
label_color = "#2f4f4f"        # Dark Slate Gray
output_bg_color = "#f0fff0"    # Honeydew
output_fg_color = "black"
title_color = "#8b4513"        # Saddle Brown

def get_hostname_from_ip(ip_address):
    """Tries to get the hostname from the IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return ip_address
    except Exception as e:
        return ip_address

def get_ip_address(url_or_ip):
    """Gets the IP address from a URL or validates an IP address."""
    try:
        socket.inet_aton(url_or_ip)  # Check if input is a valid IP address
        return url_or_ip
    except socket.error:
        try:
            hostname = url_or_ip.split("//")[-1].split("/")[0]
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except socket.gaierror:
            return "Could not resolve IP address for this URL/IP."
        except Exception as e:
            return f"An error occurred: {e}"

def get_website_info(url_or_ip, output_text):
    """Gets website information based on URL or IP and displays it in the GUI."""
    output_text.config(state=tk.NORMAL, bg=output_bg_color, fg=output_fg_color)
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Processing: {url_or_ip}\n", "process")
    output_text.config(state=tk.DISABLED)

    ip_address = get_ip_address(url_or_ip)
    if "Could not resolve IP address" in ip_address or "An error occurred" in ip_address:
        output_text.config(state=tk.NORMAL)
        output_text.insert(tk.END, ip_address + "\n", "error")
        output_text.config(state=tk.DISABLED)
        return

    target_url = url_or_ip if url_or_ip.startswith("http://") or url_or_ip.startswith("https://") else f"http://{get_hostname_from_ip(ip_address)}"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}

    try:
        start_time = time.time()
        response = requests.get(target_url, stream=True, timeout=10, allow_redirects=True, headers=headers)
        end_time = time.time()
        response.raise_for_status()

        info = {}
        info["IP Address"] = ip_address
        info["Hostname (Possible)"] = get_hostname_from_ip(ip_address)
        info["URL"] = response.url
        info["Status Code"] = response.status_code
        info["Server"] = response.headers.get("Server")
        info["Date"] = response.headers.get("Date")
        info["Content-Type"] = response.headers.get("Content-Type")
        info["Encoding"] = response.encoding
        info["Response Time (seconds)"] = f"{end_time - start_time:.4f}"
        info["Content Size (bytes)"] = response.headers.get("Content-Length")
        info["Cookies"] = response.cookies.get_dict()
        info["Redirect History"] = [r.url for r in response.history]

        security_headers = {}
        security_headers["Strict-Transport-Security"] = response.headers.get("Strict-Transport-Security")
        security_headers["Content-Security-Policy"] = response.headers.get("Content-Security-Policy")
        security_headers["X-Frame-Options"] = response.headers.get("X-Frame-Options")
        security_headers["X-Content-Type-Options"] = response.headers.get("X-Content-Type-Options")
        security_headers["Referrer-Policy"] = response.headers.get("Referrer-Policy")
        security_headers["Permissions-Policy"] = response.headers.get("Permissions-Policy")
        info["Security Headers"] = security_headers

        output_text.config(state=tk.NORMAL)
        output_text.insert(tk.END, f"Information for: {response.url}\n", "title_info")
        for key, value in info.items():
            output_text.insert(tk.END, f"{key}: ", "label_info")
            if key == "Security Headers":
                output_text.insert(tk.END, "\n", "value_info")
                for header, header_value in value.items():
                    output_text.insert(tk.END, f"  {header}: ", "header_label")
                    output_text.insert(tk.END, f"{header_value if header_value else 'None'}\n", "header_value")
            elif key == "Cookies":
                output_text.insert(tk.END, "\n", "value_info")
                for cookie, cookie_value in value.items():
                    output_text.insert(tk.END, f"  {cookie}: ", "cookie_label")
                    output_text.insert(tk.END, f"{cookie_value}\n", "cookie_value")
            elif key == "Redirect History":
                if value:
                    output_text.insert(tk.END, "\n", "value_info")
                    for url in value:
                        output_text.insert(tk.END, f"  {url}\n", "redirect_url")
                else:
                    output_text.insert(tk.END, "No redirects\n", "no_redirect")
            else:
                output_text.insert(tk.END, f"{value}\n", "value_info")
        output_text.config(state=tk.DISABLED)

    except requests.exceptions.RequestException as e:
        output_text.config(state=tk.NORMAL)
        output_text.insert(tk.END, f"Error retrieving information from {target_url} ({ip_address}): {e}\n", "error")
        output_text.config(state=tk.DISABLED)

def fetch_robots_txt(url, output_text):
    """Fetches and displays the content of robots.txt from the given URL."""
    output_text.config(state=tk.NORMAL, bg=output_bg_color, fg=output_fg_color)
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Checking robots.txt for: {url}\n", "process")
    output_text.config(state=tk.DISABLED)

    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        robots_url = url.rstrip('/') + "/robots.txt"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        response = requests.get(robots_url, timeout=10, headers=headers)
        response.raise_for_status()  # Will raise HTTPError for bad responses (4xx or 5xx)

        if response.status_code == 200:
            output_text.config(state=tk.NORMAL)
            output_text.insert(tk.END, f"Content of robots.txt from: {robots_url}\n", "title_info")
            output_text.insert(tk.END, response.text, "robots_content")
            output_text.config(state=tk.DISABLED)
        else:
            output_text.config(state=tk.NORMAL)
            output_text.insert(tk.END, f"robots.txt not found (Status Code: {response.status_code}) at: {robots_url}\n", "error")
            output_text.config(state=tk.DISABLED)

    except requests.exceptions.RequestException as e:
        output_text.config(state=tk.NORMAL)
        output_text.insert(tk.END, f"An error occurred while fetching robots.txt from {url}: {e}\n", "error")
        output_text.config(state=tk.DISABLED)

def start_action():
    """Starts the action based on the user's selection."""
    target = entry.get()
    selected_option = tool_var.get()
    if target:
        if selected_option == "Website Info":
            threading.Thread(target=get_website_info, args=(target, output_text)).start()
        elif selected_option == "Robots.txt Checker":
            threading.Thread(target=fetch_robots_txt, args=(target, output_text)).start()
        else:
            messagebox.showerror("Error", "Please select an action type.")
    else:
        messagebox.showerror("Error", "Please enter a URL or IP Address.")

# --- GUI Configuration ---
root = tk.Tk()
root.title("Website/IP Tools")
root.geometry("1000x750")  # Slightly taller
root.config(bg=background_color)

style = ttk.Style()
style.theme_use('clam')
style.configure("TLabelFrame", background=frame_color, foreground=title_color, font=('TkDefaultFont', 12, 'bold'))
style.configure("TLabel", background=frame_color, foreground=label_color)
style.configure("TButton", background=button_color, foreground=button_text_color, font=('TkDefaultFont', 10, 'bold'), padding=5)
style.map("TButton", background=[('active', '#5e94c1')], foreground=[('active', button_text_color)])
style.configure("TEntry", background="white", foreground="black", font=('TkDefaultFont', 10))
style.configure("TCombobox", background="white", foreground="black", font=('TkDefaultFont', 10))
style.configure("Clear.TButton", background="#d32f2f", foreground="white", font=('TkDefaultFont', 10, 'bold'))
style.map("Clear.TButton", background=[('active', '#f44336')], foreground=[('active', 'white')])

# --- Tool Selection Frame ---
tool_frame = ttk.LabelFrame(root, text="Select Tool")
tool_frame.pack(padx=20, pady=10, fill="x")

tool_label = ttk.Label(tool_frame, text="Select:", font=('TkDefaultFont', 10))
tool_label.pack(pady=5, padx=10, side="left")

tools = ["Website Info", "Robots.txt Checker"]
tool_var = tk.StringVar(root)
tool_var.set(tools[0])  # Set default value
tool_combobox = ttk.Combobox(tool_frame, textvariable=tool_var, values=tools, state="readonly", width=20)
tool_combobox.pack(pady=5, padx=10, side="left")

# Input Frame
input_frame = ttk.LabelFrame(root, text="Target Input")
input_frame.pack(padx=20, pady=10, fill="x")
input_label = ttk.Label(input_frame, text="URL or IP:", font=('TkDefaultFont', 10))
input_label.pack(pady=5, padx=10, side="left")
entry = ttk.Entry(input_frame, width=80)
entry.pack(pady=5, padx=10, side="left", fill="x", expand=True)
action_button = ttk.Button(input_frame, text="Start", command=start_action)
action_button.pack(pady=5, padx=10, side="right")

# Explanation Frame (Concise)
explanation_frame = ttk.LabelFrame(root, text="Guide")
explanation_frame.pack(padx=20, pady=10, fill="x")
explanation_text = tk.StringVar()
explanation_text.set("""
Select the tool you want to use from the list above.
For 'Website Info': Enter the complete URL (e.g., https://example.com) or IP address (e.g., 192.168.1.1) and click 'Start' to view website information.
For 'Robots.txt Checker': Enter the website URL (e.g., https://example.com) and click 'Start' to check the robots.txt file.
Use 'Clear Results' to remove previous output.
""")
explanation_label = ttk.Label(explanation_frame, textvariable=explanation_text, wraplength=950, justify="left")
explanation_label.pack(padx=15, pady=10, fill="x")

# Output Frame
output_frame = ttk.LabelFrame(root, text="Results")
output_frame.pack(padx=20, pady=10, fill="both", expand=True)
output_text = scrolledtext.ScrolledText(output_frame, height=25, width=100, state=tk.DISABLED, font=('Courier New', 11), bg=output_bg_color, fg=output_fg_color)
output_text.pack(padx=15, pady=15, fill="both", expand=True)

# Output Text Tags for Coloring (Include robots_content)
output_text.tag_config("process", foreground="#0000CD")
output_text.tag_config("error", foreground="#FF4500", font=('Courier New', 11, 'bold'))
output_text.tag_config("title_info", foreground=title_color, font=('Courier New', 12, 'bold'))
output_text.tag_config("label_info", foreground="#191970", font=('Courier New', 11, 'bold'))
output_text.tag_config("value_info", foreground="black")
output_text.tag_config("header_label", foreground="#800080", font=('Courier New', 11, 'italic'))
output_text.tag_config("header_value", foreground="black")
output_text.tag_config("cookie_label", foreground="#228B22", font=('Courier New', 11, 'italic'))
output_text.tag_config("cookie_value", foreground="black")
output_text.tag_config("redirect_url", foreground="#DAA520")
output_text.tag_config("no_redirect", foreground="gray")
output_text.tag_config("robots_content", foreground="black")

# Clear Output Button
clear_button = ttk.Button(output_frame, text="Clear Results", command=lambda: output_text.config(state=tk.NORMAL) or output_text.delete(1.0, tk.END) or output_text.config(state=tk.DISABLED), style="Clear.TButton")
clear_button.pack(pady=10, padx=15, fill="x")

root.mainloop()