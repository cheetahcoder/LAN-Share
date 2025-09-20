import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import socket
import threading
import os
import sys
import platform
import time
import math
import webbrowser
import shutil
import tempfile
import subprocess
import hashlib
from queue import Queue
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf, IPVersion
import tkinterdnd2 as tkdnd

HOST = '0.0.0.0'
TCP_PORT = 65432
BUFFER_SIZE = 8192
SERVICE_TYPE = "_ftapp._tcp.local."
TRANSFER_REQUEST = "TRANSFER_REQUEST"
ACCEPT_TRANSFER = "ACCEPT_TRANSFER"
DECLINE_TRANSFER = "DECLINE_TRANSFER"
NEXT_FILE = "NEXT_FILE"
OK_TO_SEND = "OK_TO_SEND"
SENDING_HASH = "SENDING_HASH"
HASH_OK = "HASH_OK"
HASH_FAIL = "HASH_FAIL"
CANCEL_SESSION = "CANCEL_SESSION"
MULTI_FILE_END = "MULTI_FILE_END"

available_hosts = {}
selected_paths = []
transfer_cancel_event = threading.Event()

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('1.1.1.1', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP
    
def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(BUFFER_SIZE), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, OSError):
        return None

class ZeroconfListener:
    def remove_service(self, zeroconf, type, name):
        simple_name = name.replace(f".{SERVICE_TYPE}", "")
        if simple_name in available_hosts:
            del available_hosts[simple_name]
            update_combobox_safe()

    def update_service(self, zeroconf, type, name):
        pass

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            try:
                ip_address = socket.inet_ntoa(info.addresses[0])
                if ip_address != get_local_ip():
                    simple_name = name.replace(f".{SERVICE_TYPE}", "")
                    available_hosts[simple_name] = ip_address
                    update_combobox_safe()
            except (IndexError, OSError):
                pass

def start_zeroconf_service():
    try:
        info = ServiceInfo(
            SERVICE_TYPE, f"{socket.gethostname()}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(get_local_ip())], port=TCP_PORT,
            properties={'app': 'FileTransferApp'},
        )
        zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        zeroconf.register_service(info)
        while True: time.sleep(10)
    except Exception as e:
        print(f"Error starting Zeroconf service: {e}")

def start_zeroconf_browser():
    zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
    listener = ZeroconfListener()
    ServiceBrowser(zeroconf, SERVICE_TYPE, listener)

def update_combobox_safe():
    def update_gui():
        if not available_hosts:
            ip_combobox.set("No available devices found")
            ip_combobox['values'] = []
        else:
            sorted_names = sorted(available_hosts.keys())
            current_selection = ip_combobox.get()
            ip_combobox['values'] = sorted_names
            if current_selection not in sorted_names and "devices" not in current_selection:
                ip_combobox.set(sorted_names[0])
            elif "devices" in current_selection and sorted_names:
                ip_combobox.set(sorted_names[0])
        update_status_safe(f"{len(available_hosts)} device(s) found.")
    root.after(0, update_gui)

def apply_keepalive_settings(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if platform.system() == "Linux":
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        except (AttributeError, OSError):
            pass

def start_tcp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((HOST, TCP_PORT))
        server_socket.listen(5)
    except Exception as e:
        update_status_safe(f"Error: Port {TCP_PORT} is already in use.")
        return
    while True:
        try:
            conn, addr = server_socket.accept()
            apply_keepalive_settings(conn)
            threading.Thread(target=handle_tcp_connection, args=(conn,), daemon=True).start()
        except Exception:
            pass
            
def handle_tcp_connection(conn):
    try:
        initial_data = conn.recv(BUFFER_SIZE).decode().split("::")
        
        if initial_data[0] == TRANSFER_REQUEST:
            total_files = int(initial_data[1])
            total_size = int(initial_data[2])
            sender_hostname = initial_data[3]

            if not messagebox.askyesno("Incoming Transfer", f"'{sender_hostname}' wants to send you {total_files} file(s) ({format_size(total_size)}).\n\nDo you accept?"):
                conn.sendall(DECLINE_TRANSFER.encode())
                update_status_safe("Transfer declined.")
                return
            
            conn.sendall(ACCEPT_TRANSFER.encode())

            base_save_dir = ask_directory_native(f"Select a folder to save the incoming {total_files} file(s)")
            if not base_save_dir:
                conn.sendall(CANCEL_SESSION.encode())
                update_status_safe("Transfer cancelled by user.")
                return

            if not check_disk_space_and_permissions(base_save_dir, total_size):
                conn.sendall(CANCEL_SESSION.encode())
                return
            
            toggle_ui_state('transfer')
            update_overall_progress_safe(0, f"File 0/{total_files}")
            conn.sendall(OK_TO_SEND.encode())
            
            files_received = 0
            while files_received < total_files:
                if transfer_cancel_event.is_set():
                    conn.sendall(CANCEL_SESSION.encode())
                    raise InterruptedError("Transfer cancelled by receiver.")

                file_header_str = conn.recv(BUFFER_SIZE).decode()
                if not file_header_str or file_header_str == MULTI_FILE_END:
                    break
                
                _, rel_path, file_size_str = file_header_str.split("::")
                file_size = int(file_size_str)
                
                full_save_path = os.path.join(base_save_dir, rel_path)
                os.makedirs(os.path.dirname(full_save_path), exist_ok=True)
                
                conn.sendall(OK_TO_SEND.encode())
                
                receive_single_file(conn, full_save_path, file_size)

                hash_header = conn.recv(BUFFER_SIZE).decode().split("::")
                if hash_header[0] == SENDING_HASH:
                    remote_hash = hash_header[1]
                    update_status_safe(f"Verifying {os.path.basename(full_save_path)}...")
                    local_hash = calculate_sha256(full_save_path)
                    if local_hash == remote_hash:
                        conn.sendall(HASH_OK.encode())
                    else:
                        conn.sendall(HASH_FAIL.encode())
                        os.remove(full_save_path)
                        raise ValueError(f"Checksum mismatch for {os.path.basename(full_save_path)}")
                else:
                    raise ValueError("Protocol error: Expected hash.")
                
                files_received += 1
                update_overall_progress_safe((files_received / total_files) * 100, f"File {files_received}/{total_files}")
                
            update_status_safe("All files received and verified successfully!")
            messagebox.showinfo("Success", "All files transferred successfully!")
            update_show_in_folder_button_safe(base_save_dir)
            
    except InterruptedError as e:
        update_status_safe(str(e))
        update_progress_style_safe("danger.Horizontal.TProgressbar", "overall")
    except Exception as e:
        update_status_safe(f"Transfer Error: {e}")
        update_progress_style_safe("danger.Horizontal.TProgressbar", "overall")
    finally:
        conn.close()
        toggle_ui_state('idle')
        root.after(3000, lambda: reset_progress_bars())

def receive_single_file(conn, save_path, filesize):
    update_current_file_label_safe(f"Receiving: {os.path.basename(save_path)}")
    update_progress_style_safe("blue.Horizontal.TProgressbar", "current")
    start_time = time.time()
    bytes_received = 0
    with open(save_path, 'wb') as f:
        while bytes_received < filesize:
            if transfer_cancel_event.is_set():
                raise InterruptedError("Transfer cancelled by receiver.")
            remaining = filesize - bytes_received
            data = conn.recv(min(BUFFER_SIZE, remaining))
            if not data: break
            f.write(data)
            bytes_received += len(data)
            progress = (bytes_received / filesize) * 100 if filesize > 0 else 100
            
            elapsed_time = time.time() - start_time
            if elapsed_time > 0.5:
                speed = bytes_received / elapsed_time
                update_speed_and_eta_safe(speed, bytes_received, filesize)

            update_progress_safe(progress, bytes_received, filesize, "current")

    if transfer_cancel_event.is_set():
        os.remove(save_path)
        raise InterruptedError("Transfer cancelled by receiver.")
    update_progress_style_safe("success.Horizontal.TProgressbar", "current")

def prepare_and_send():
    if not selected_paths:
        messagebox.showerror("Error", "Please select file(s) or a folder first.")
        return
    
    target_name = ip_combobox.get()
    target_ip = available_hosts.get(target_name)
    if not target_ip:
        messagebox.showerror("Error", "Please select a valid target device.")
        return
    
    threading.Thread(target=send_manager_thread, args=(selected_paths, target_ip, target_name), daemon=True).start()

def send_manager_thread(paths, target_ip, target_name):
    toggle_ui_state('transfer')
    file_list = []
    
    update_status_safe("Preparing file list...")
    for path in paths:
        if os.path.isfile(path):
            file_list.append((path, os.path.basename(path)))
        elif os.path.isdir(path):
            base_dir_for_relpath = os.path.dirname(path)
            for dirpath, _, filenames in os.walk(path):
                for filename in filenames:
                    full_path = os.path.join(dirpath, filename)
                    relative_path = os.path.relpath(full_path, base_dir_for_relpath)
                    file_list.append((full_path, relative_path))

    normalized_file_list = []
    for full_path, rel_path in file_list:
        normalized_file_list.append((full_path, rel_path.replace(os.path.sep, '/')))
    
    file_list = normalized_file_list
    total_files = len(file_list)
    if total_files == 0:
        messagebox.showwarning("Empty Selection", "The selected folder or files are empty.")
        toggle_ui_state('idle')
        return

    total_size = sum(os.path.getsize(f[0]) for f in file_list)
    sender_hostname = socket.gethostname()

    client_socket = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            apply_keepalive_settings(client_socket)
            client_socket.connect((target_ip, TCP_PORT))
            
            client_socket.sendall(f"{TRANSFER_REQUEST}::{total_files}::{total_size}::{sender_hostname}".encode())
            
            response = client_socket.recv(BUFFER_SIZE).decode()
            if response == DECLINE_TRANSFER:
                messagebox.showinfo("Declined", f"'{target_name}' declined the transfer request.")
                toggle_ui_state('idle')
                return
            elif response != ACCEPT_TRANSFER:
                raise ConnectionAbortedError("Receiver did not accept the transfer.")

            response = client_socket.recv(BUFFER_SIZE).decode()
            if response != OK_TO_SEND:
                raise ConnectionAbortedError("Receiver cancelled after accepting.")

            update_overall_progress_safe(0, f"File 0/{total_files}")
            
            files_sent = 0
            for full_path, rel_path in file_list:
                if transfer_cancel_event.is_set():
                    try: client_socket.sendall(CANCEL_SESSION.encode())
                    except: pass
                    raise InterruptedError("Transfer cancelled by sender.")
                
                file_size = os.path.getsize(full_path)
                
                client_socket.sendall(f"{NEXT_FILE}::{rel_path}::{file_size}".encode())
                response = client_socket.recv(BUFFER_SIZE).decode()
                if response != OK_TO_SEND:
                    raise ConnectionAbortedError(f"Receiver rejected file: {rel_path}")

                send_single_file(client_socket, full_path)
                
                file_hash = calculate_sha256(full_path)
                client_socket.sendall(f"{SENDING_HASH}::{file_hash}".encode())
                
                hash_response = client_socket.recv(BUFFER_SIZE).decode()
                if hash_response != HASH_OK:
                    raise ValueError(f"Checksum mismatch for {os.path.basename(full_path)}")

                files_sent += 1
                update_overall_progress_safe((files_sent/total_files)*100, f"File {files_sent}/{total_files}")

            client_socket.sendall(MULTI_FILE_END.encode())
            update_status_safe("All files sent and verified successfully.")
            update_progress_style_safe("success.Horizontal.TProgressbar", "overall")
            messagebox.showinfo("Success", "All files sent successfully!")

    except InterruptedError as e:
        update_status_safe(str(e))
        update_progress_style_safe("danger.Horizontal.TProgressbar", "overall")
    except Exception as e:
        update_status_safe(f"Sending Error: {e}")
        update_progress_style_safe("danger.Horizontal.TProgressbar", "overall")
    finally:
        if client_socket: client_socket.close()
        toggle_ui_state('idle')
        root.after(3000, lambda: reset_progress_bars())

def send_single_file(sock, filepath):
    filesize = os.path.getsize(filepath)
    update_current_file_label_safe(f"Sending: {os.path.basename(filepath)}")
    update_progress_style_safe("blue.Horizontal.TProgressbar", "current")
    bytes_sent = 0
    start_time = time.time()
    with open(filepath, 'rb') as f:
        while True:
            if transfer_cancel_event.is_set():
                raise InterruptedError("Transfer cancelled by sender.")
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read: break
            sock.sendall(bytes_read)
            bytes_sent += len(bytes_read)
            progress = (bytes_sent / filesize) * 100 if filesize > 0 else 100
            
            elapsed_time = time.time() - start_time
            if elapsed_time > 0.5:
                speed = bytes_sent / elapsed_time
                update_speed_and_eta_safe(speed, bytes_sent, filesize)
            
            update_progress_safe(progress, bytes_sent, filesize, "current")

    if transfer_cancel_event.is_set():
        raise InterruptedError("Transfer cancelled by sender.")
    update_progress_style_safe("success.Horizontal.TProgressbar", "current")

def ask_open_filenames_native():
    if platform.system() == 'Linux' and shutil.which('zenity'):
        try:
            command = ['zenity', '--file-selection', '--multiple', '--title=Select File(s)']
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().split('|')
            else:
                return []
        except FileNotFoundError:
            return filedialog.askopenfilenames()
    return filedialog.askopenfilenames()

def ask_directory_native(title="Select Folder"):
    if platform.system() == 'Linux' and shutil.which('zenity'):
        try:
            command = ['zenity', '--file-selection', '--directory', f'--title={title}']
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return ""
        except FileNotFoundError:
            return filedialog.askdirectory(title=title)
    return filedialog.askdirectory(title=title)

def ask_save_as_filename_native(initial_filename=""):
    if platform.system() == 'Linux' and shutil.which('zenity'):
        try:
            command = ['zenity', '--file-selection', '--save', '--confirm-overwrite', f'--filename={initial_filename}']
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return ""
        except FileNotFoundError:
            return filedialog.asksaveasfilename(initialfile=initial_filename)
    return filedialog.asksaveasfilename(initialfile=initial_filename)

def process_selected_paths(paths):
    global selected_paths
    if not paths:
        return

    selected_paths = list(paths)
    if len(selected_paths) == 1:
        path = selected_paths[0]
        if os.path.isdir(path):
            filepath_label.config(text=f"Folder: {os.path.basename(path)}")
            total_size = sum(os.path.getsize(os.path.join(dirpath, filename)) for dirpath, _, filenames in os.walk(path) for filename in filenames)
            file_size_label.config(text=format_size(total_size))
        else:
            filepath_label.config(text=os.path.basename(path))
            update_file_size_label(path)
    else:
        filepath_label.config(text=f"{len(selected_paths)} items selected")
        total_size = 0
        for p in selected_paths:
            if os.path.isfile(p):
                total_size += os.path.getsize(p)
            elif os.path.isdir(p):
                 total_size += sum(os.path.getsize(os.path.join(dirpath, filename)) for dirpath, _, filenames in os.walk(p) for filename in filenames)
        file_size_label.config(text=format_size(total_size))

def handle_drop(event):
    paths = root.tk.splitlist(event.data)
    if paths:
        process_selected_paths(paths)

def select_files():
    paths = ask_open_filenames_native()
    if paths and paths[0]:
        process_selected_paths(paths)

def select_folder():
    path = ask_directory_native(title="Select Folder to Send")
    if path:
        process_selected_paths([path])

def cancel_transfer():
    transfer_cancel_event.set()

def open_github(event=None):
    webbrowser.open_new("https://github.com/cheetahcoder")

def open_file_location(path):
    try:
        if platform.system() == "Windows":
            subprocess.Popen(f'explorer /select,"{os.path.normpath(path)}"')
        elif platform.system() == "Darwin":
            subprocess.Popen(['open', '-R', path])
        else:
            open_path = path if os.path.isdir(path) else os.path.dirname(path)
            subprocess.Popen(['xdg-open', open_path])
    except Exception as e:
        messagebox.showerror("Error", f"Could not open file location:\n{e}")

def check_disk_space_and_permissions(directory, required_space):
    if not os.path.isdir(directory):
        directory = os.path.dirname(directory)
    
    try:
        total, used, free = shutil.disk_usage(directory)
        if free < required_space:
            messagebox.showerror("Insufficient Disk Space", f"Not enough space on the destination drive.\n\nRequired: {format_size(required_space)}\nAvailable: {format_size(free)}")
            return False
    except FileNotFoundError:
        messagebox.showerror("Error", f"The destination directory does not exist:\n{directory}")
        return False

    if not os.access(directory, os.W_OK):
        messagebox.showerror("Permission Error", f"Cannot write to the selected directory:\n{directory}\n\nPlease choose a different folder, like 'Downloads' or 'Desktop'.")
        return False
    
    return True

def format_size(size_bytes):
    if size_bytes == 0: return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    try:
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_name[i]}"
    except (ValueError, IndexError):
        return "0 B"

def format_speed(speed_bps):
    if speed_bps < 1024: return f"{speed_bps:.2f} B/s"
    elif speed_bps < 1024 * 1024: return f"{speed_bps / 1024:.2f} KB/s"
    else: return f"{speed_bps / (1024*1024):.2f} MB/s"
def format_time(seconds):
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds//60)}m {int(seconds%60)}s"
    else:
        return f"{int(seconds//3600)}h {int((seconds%3600)//60)}m"
def update_file_size_label(path):
    try:
        size = os.path.getsize(path)
        file_size_label.config(text=format_size(size))
    except OSError:
        file_size_label.config(text="Unknown Size")

def toggle_ui_state(state):
    def do_toggle():
        if state == 'transfer':
            send_button.config(state=tk.DISABLED)
            cancel_button.config(state=tk.NORMAL)
            select_files_button.config(state=tk.DISABLED)
            select_folder_button.config(state=tk.DISABLED)
            ip_combobox.config(state=tk.DISABLED)
            transfer_cancel_event.clear()
        else:
            send_button.config(state=tk.NORMAL)
            cancel_button.config(state=tk.DISABLED)
            select_files_button.config(state=tk.NORMAL)
            select_folder_button.config(state=tk.NORMAL)
            ip_combobox.config(state=tk.NORMAL)
            transfer_cancel_event.clear()
    root.after(0, do_toggle)

def update_status_safe(message):
    root.after(0, status_label.config, {'text': message})
def update_progress_safe(percentage, bytes_so_far, total_bytes, bar="current"):
    target_bar = current_progress_bar if bar == "current" else overall_progress_bar
    target_label = current_progress_label if bar == "current" else overall_progress_label
    
    label_text = f"{format_size(bytes_so_far)} / {format_size(total_bytes)} ({int(percentage)}%)" if total_bytes > 0 else "0%"
    
    root.after(0, target_bar.config, {'value': percentage})
    root.after(0, target_label.config, {'text': label_text})
def update_overall_progress_safe(percentage, text):
    root.after(0, overall_progress_bar.config, {'value': percentage})
    root.after(0, overall_progress_label.config, {'text': f"Overall: {text}"})
def update_current_file_label_safe(text):
    root.after(0, current_file_label.config, {'text': text})
def update_speed_and_eta_safe(speed_bps, bytes_so_far, total_bytes):
    formatted_speed = format_speed(speed_bps)
    remaining_bytes = total_bytes - bytes_so_far
    eta = "..."
    if speed_bps > 0:
        eta_seconds = remaining_bytes / speed_bps
        eta = format_time(eta_seconds)
    
    root.after(0, speed_label.config, {'text': formatted_speed})
    root.after(0, eta_label.config, {'text': f"ETA: {eta}"})
def update_progress_style_safe(style_name, bar="current"):
    target_bar = current_progress_bar if bar == "current" else overall_progress_bar
    root.after(0, target_bar.config, {'style': style_name})
def update_show_in_folder_button_safe(path):
    def update():
        show_in_folder_button.config(state=tk.NORMAL, command=lambda: open_file_location(path))
    root.after(0, update)
def reset_progress_bars():
    update_progress_safe(0, 0, 0, "current")
    update_overall_progress_safe(0, "0/0")
    update_speed_and_eta_safe(0, 0, 0)
    update_current_file_label_safe("No file in progress.")
    update_progress_style_safe("blue.Horizontal.TProgressbar", "current")
    update_progress_style_safe("blue.Horizontal.TProgressbar", "overall")
    root.after(0, show_in_folder_button.config, {'state': tk.DISABLED})

root = tkdnd.Tk()
root.title("File Transfer App")
root.geometry("600x480")
root.minsize(550, 480)

root.drop_target_register(tkdnd.DND_FILES)
root.dnd_bind('<<Drop>>', handle_drop)

try:
    icon_path = resource_path('icon.png')
    icon = tk.PhotoImage(file=icon_path)
    root.iconphoto(True, icon)
except Exception as e:
    print(f"Icon file not found: {e}")

style = ttk.Style(root)
style.configure("TFrame", background="#f0f0f0")
style.configure("TLabel", background="#f0f0f0")
style.configure("TLabelframe", background="#f0f0f0")
style.configure("TLabelframe.Label", background="#f0f0f0")
style.configure("blue.Horizontal.TProgressbar", background='#0078D7')
style.configure("success.Horizontal.TProgressbar", background='#28A745')
style.configure("danger.Horizontal.TProgressbar", background='#DC3545')

main_frame = ttk.Frame(root, padding="10 10 10 10")
main_frame.pack(fill=tk.BOTH, expand=True)

top_frame = ttk.Frame(main_frame)
top_frame.pack(fill=tk.X, pady=(0, 10))
top_frame.columnconfigure(1, weight=1)

ttk.Label(top_frame, text="Content:").grid(row=0, column=0, padx=(0, 5), sticky="w")
filepath_label = ttk.Label(top_frame, text="Drag & drop files/folders here", anchor='w', relief="sunken", padding=5)
filepath_label.grid(row=0, column=1, columnspan=2, sticky="ew")
file_size_label = ttk.Label(top_frame, text="", width=12, anchor='w')
file_size_label.grid(row=0, column=3, padx=5, sticky="w")

button_frame = ttk.Frame(top_frame)
button_frame.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(5,0))
button_frame.columnconfigure(0, weight=1)
button_frame.columnconfigure(1, weight=1)
select_files_button = ttk.Button(button_frame, text="Select File(s)", command=select_files)
select_files_button.grid(row=0, column=0, sticky="ew", padx=(0, 2))
select_folder_button = ttk.Button(button_frame, text="Select Folder", command=select_folder)
select_folder_button.grid(row=0, column=1, sticky="ew", padx=(2, 0))

ttk.Label(top_frame, text="Target:").grid(row=2, column=0, padx=(0, 5), pady=(10, 0), sticky="w")
ip_combobox = ttk.Combobox(top_frame, state="readonly")
ip_combobox.grid(row=2, column=1, columnspan=3, pady=(10, 0), sticky="ew")
ip_combobox.set("Searching for devices...")

progress_frame = ttk.LabelFrame(main_frame, text="Transfer Progress", padding=10)
progress_frame.pack(fill=tk.X, pady=10)
progress_frame.columnconfigure(0, weight=1)

overall_frame = ttk.Frame(progress_frame)
overall_frame.grid(row=0, column=0, sticky="ew")
overall_frame.columnconfigure(0, weight=1)
overall_progress_bar = ttk.Progressbar(overall_frame, orient="horizontal", style="blue.Horizontal.TProgressbar")
overall_progress_bar.grid(row=0, column=0, sticky="ew")
overall_progress_label = ttk.Label(overall_frame, text="Overall: 0/0", width=15, anchor="e")
overall_progress_label.grid(row=0, column=1, padx=5)

current_frame = ttk.Frame(progress_frame)
current_frame.grid(row=1, column=0, sticky="ew", pady=(5,0))
current_frame.columnconfigure(0, weight=1)
current_file_label = ttk.Label(current_frame, text="No file in progress", anchor="w")
current_file_label.grid(row=0, column=0, columnspan=2, sticky="ew")
current_progress_bar = ttk.Progressbar(current_frame, orient="horizontal", style="blue.Horizontal.TProgressbar")
current_progress_bar.grid(row=1, column=0, sticky="ew", pady=(2,0))
current_progress_label = ttk.Label(current_frame, text="0 B / 0 B (0%)", width=24, anchor="e")
current_progress_label.grid(row=1, column=1, padx=5, pady=(2,0))

control_frame = ttk.Frame(main_frame)
control_frame.pack(fill=tk.X)
speed_label = ttk.Label(control_frame, text="0.00 KB/s", width=12)
speed_label.pack(side=tk.LEFT, pady=5)
eta_label = ttk.Label(control_frame, text="ETA: ...", width=12)
eta_label.pack(side=tk.LEFT, padx=5, pady=5)
right_buttons_frame = ttk.Frame(control_frame)
right_buttons_frame.pack(side=tk.RIGHT, pady=5)
show_in_folder_button = ttk.Button(right_buttons_frame, text="Show in Folder", state=tk.DISABLED)
show_in_folder_button.pack(side=tk.LEFT, padx=(0, 5))
cancel_button = ttk.Button(right_buttons_frame, text="Cancel", command=cancel_transfer, state=tk.DISABLED)
cancel_button.pack(side=tk.LEFT)

send_button = ttk.Button(main_frame, text="Send Content", command=prepare_and_send, style="Accent.TButton")
send_button.pack(pady=(10, 5), fill=tk.X, ipady=5)
style.configure("Accent.TButton", font=("Helvetica", 10, "bold"))

info_frame = ttk.Frame(root, padding=5, relief="sunken")
info_frame.pack(side=tk.BOTTOM, fill=tk.X)
info_frame.columnconfigure(1, weight=1)
local_ip_info = f"Your IP: {get_local_ip()}"
ip_label = ttk.Label(info_frame, text=local_ip_info, foreground="blue")
ip_label.grid(row=0, column=0, sticky="w")
status_label = ttk.Label(info_frame, text="", anchor=tk.CENTER)
status_label.grid(row=0, column=1, sticky="ew")
github_label = ttk.Label(info_frame, text="View on GitHub", foreground="blue", cursor="hand2")
github_label.grid(row=0, column=2, sticky="e")
github_label.bind("<Button-1>", open_github)

threading.Thread(target=start_tcp_server, daemon=True).start()
threading.Thread(target=start_zeroconf_service, daemon=True).start()
threading.Thread(target=start_zeroconf_browser, daemon=True).start()

root.mainloop()

