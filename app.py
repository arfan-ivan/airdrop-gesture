import cv2
import mediapipe as mp
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import socket
import os
import json
import time
import struct
from pathlib import Path
import uuid
import hashlib
from datetime import datetime
import logging


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OptimizedGestureAirDrop:
    def __init__(self):
        self.device_id = str(uuid.uuid4())[:8]
        self.device_name = f"GestureAirDrop_{self.device_id}"
        
        self.mp_hands = mp.solutions.hands
        self.hands = self.mp_hands.Hands(
            static_image_mode=False,
            max_num_hands=1,
            min_detection_confidence=0.7,
            min_tracking_confidence=0.5
        )
        self.mp_draw = mp.solutions.drawing_utils
        
        self.discovery_port = 8889
        self.transfer_port = 8888
        self.broadcast_interval = 3  
        
        self.selected_file = None
        self.is_running = False
        self.camera_active = False
        self.connected_devices = {}  # {device_id: {name, ip, last_seen}}
        self.gesture_state = "none"
        self.last_gesture_time = 0
        self.gesture_stability_time = 1.5  
        
        
        self.cap = None
        self.camera_thread = None
        
        self.received_folder = Path("received_files")
        self.received_folder.mkdir(exist_ok=True)
        
      
        self.setup_ui()
      
        self.start_all_services()
    
    def setup_ui(self):
        self.root = tk.Tk()
        self.root.title(f"Gesture AirDrop - {self.device_name}")
        self.root.geometry("900x700")
        self.root.configure(bg='#1a1a1a')
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        main_canvas = tk.Canvas(self.root, bg='#1a1a1a')
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=main_canvas.yview)
        scrollable_frame = tk.Frame(main_canvas, bg='#1a1a1a')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=scrollbar.set)
        
        main_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        content_frame = tk.Frame(scrollable_frame, bg='#1a1a1a')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        title_label = tk.Label(
            content_frame,
            text="🤚 Gesture AirDrop",
            font=('Arial', 28, 'bold'),
            fg='#00d4ff',
            bg='#1a1a1a'
        )
        title_label.pack(pady=(0, 30))

        device_info_frame = tk.Frame(content_frame, bg='#2d2d2d', relief=tk.RAISED, bd=2)
        device_info_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(
            device_info_frame,
            text=f"Device: {self.device_name}",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#2d2d2d',
            pady=10
        ).pack()
        
        status_frame = tk.Frame(content_frame, bg='#2d2d2d', relief=tk.RAISED, bd=2)
        status_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.status_label = tk.Label(
            status_frame,
            text="🔄 Initializing services...",
            font=('Arial', 12),
            fg='#ffaa00',
            bg='#2d2d2d',
            pady=15
        )
        self.status_label.pack()
        
        camera_frame = tk.LabelFrame(
            content_frame,
            text="Camera Control",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#1a1a1a'
        )
        camera_frame.pack(fill=tk.X, pady=(0, 20))
        
        camera_control_frame = tk.Frame(camera_frame, bg='#1a1a1a')
        camera_control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.camera_btn = tk.Button(
            camera_control_frame,
            text="📷 Start Camera",
            command=self.toggle_camera,
            font=('Arial', 12, 'bold'),
            bg='#27ae60',
            fg='white',
            relief=tk.FLAT,
            padx=20,
            pady=10
        )
        self.camera_btn.pack(side=tk.LEFT)
        
        self.camera_status_label = tk.Label(
            camera_control_frame,
            text="Camera: OFF",
            font=('Arial', 11),
            fg='#ff6b6b',
            bg='#1a1a1a'
        )
        self.camera_status_label.pack(side=tk.LEFT, padx=(20, 0))
        
        devices_frame = tk.LabelFrame(
            content_frame,
            text="Connected Devices",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#1a1a1a'
        )
        devices_frame.pack(fill=tk.X, pady=(0, 20))

        devices_list_frame = tk.Frame(devices_frame, bg='#1a1a1a')
        devices_list_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.devices_listbox = tk.Listbox(
            devices_list_frame,
            font=('Arial', 10),
            bg='#2d2d2d',
            fg='#ffffff',
            height=5,
            selectbackground='#4a4a4a'
        )
        devices_scrollbar = ttk.Scrollbar(devices_list_frame, orient="vertical")
        self.devices_listbox.config(yscrollcommand=devices_scrollbar.set)
        devices_scrollbar.config(command=self.devices_listbox.yview)
        
        self.devices_listbox.pack(side="left", fill="both", expand=True)
        devices_scrollbar.pack(side="right", fill="y")
        
        file_frame = tk.LabelFrame(
            content_frame,
            text="File Selection",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#1a1a1a'
        )
        file_frame.pack(fill=tk.X, pady=(0, 20))
        
        file_control_frame = tk.Frame(file_frame, bg='#1a1a1a')
        file_control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(
            file_control_frame,
            text="📁 Select File",
            command=self.select_file,
            font=('Arial', 12),
            bg='#3498db',
            fg='white',
            relief=tk.FLAT,
            padx=20,
            pady=8
        ).pack(side=tk.LEFT)
        
        self.file_label = tk.Label(
            file_control_frame,
            text="No file selected",
            font=('Arial', 10),
            fg='#aaaaaa',
            bg='#1a1a1a'
        )
        self.file_label.pack(side=tk.LEFT, padx=(20, 0))
        
        gesture_frame = tk.LabelFrame(
            content_frame,
            text="Gesture Status",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#1a1a1a'
        )
        gesture_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.gesture_label = tk.Label(
            gesture_frame,
            text="👋 Start camera to detect gestures",
            font=('Arial', 16, 'bold'),
            fg='#ffaa00',
            bg='#1a1a1a',
            pady=20
        )
        self.gesture_label.pack()
        
        instructions_frame = tk.LabelFrame(
            content_frame,
            text="Instructions",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#1a1a1a'
        )
        instructions_frame.pack(fill=tk.X, pady=(0, 20))
        
        instructions_text = """
📋 HOW TO USE:
1. Start the camera on both devices
2. Select a file you want to send
3. SENDER: Make a FIST 👊 to initiate file transfer
4. RECEIVER: Show OPEN HAND ✋ to accept the file
5. Files will be saved in 'received_files' folder

💡 TIPS:
• Keep gestures stable for 1.5 seconds
• Ensure good lighting for better detection
• Both devices must be on the same network
        """
        
        tk.Label(
            instructions_frame,
            text=instructions_text,
            font=('Arial', 10),
            fg='#cccccc',
            bg='#1a1a1a',
            justify=tk.LEFT
        ).pack(padx=10, pady=10)
        
        log_frame = tk.LabelFrame(
            content_frame,
            text="Activity Log",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#1a1a1a'
        )
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        log_text_frame = tk.Frame(log_frame, bg='#1a1a1a')
        log_text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_text = tk.Text(
            log_text_frame,
            font=('Courier', 9),
            bg='#0d1117',
            fg='#c9d1d9',
            height=8,
            wrap=tk.WORD
        )
        log_scrollbar = ttk.Scrollbar(log_text_frame, orient="vertical")
        self.log_text.config(yscrollcommand=log_scrollbar.set)
        log_scrollbar.config(command=self.log_text.yview)
        
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scrollbar.pack(side="right", fill="y")
    
    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        logger.info(message)
    
    def start_all_services(self):
        """Start all background services"""
        self.is_running = True
        
        discovery_thread = threading.Thread(target=self.discovery_service, daemon=True)
        discovery_thread.start()
        
        transfer_thread = threading.Thread(target=self.transfer_server, daemon=True)
        transfer_thread.start()
        
        cleanup_thread = threading.Thread(target=self.device_cleanup, daemon=True)
        cleanup_thread.start()
        
        self.log_message("🚀 All services started")
        self.update_status("✅ Services running - Ready to discover devices")
    
    def discovery_service(self):
        """Handle device discovery via UDP broadcast"""
        server_thread = threading.Thread(target=self.discovery_server, daemon=True)
        server_thread.start()
        
        while self.is_running:
            try:
                self.broadcast_presence()
                time.sleep(self.broadcast_interval)
            except Exception as e:
                logger.error(f"Discovery broadcast error: {e}")
                time.sleep(5)
    
    def discovery_server(self):
        """Listen for discovery messages"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', self.discovery_port))
            sock.settimeout(1)
            
            self.log_message(f"🔍 Discovery server listening on port {self.discovery_port}")
            
            while self.is_running:
                try:
                    data, addr = sock.recvfrom(1024)
                    message = json.loads(data.decode())
                    
                    if message['type'] == 'discovery' and message['device_id'] != self.device_id:
                        # Respond to discovery
                        response = {
                            'type': 'discovery_response',
                            'device_id': self.device_id,
                            'device_name': self.device_name,
                            'transfer_port': self.transfer_port
                        }
                        sock.sendto(json.dumps(response).encode(), addr)
                        
                        self.add_discovered_device(message, addr[0])
                        
                    elif message['type'] == 'discovery_response' and message['device_id'] != self.device_id:
                        self.add_discovered_device(message, addr[0])
                        
                    elif message['type'] == 'gesture_signal':
                        self.handle_gesture_signal(message, addr[0])
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Discovery server error: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to start discovery server: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
    
    def broadcast_presence(self):
        """Broadcast presence to discover other devices"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(2)
            
            message = {
                'type': 'discovery',
                'device_id': self.device_id,
                'device_name': self.device_name,
                'transfer_port': self.transfer_port,
                'timestamp': time.time()
            }
            
            sock.sendto(json.dumps(message).encode(), ('<broadcast>', self.discovery_port))
            sock.close()
            
        except Exception as e:
            logger.error(f"Broadcast error: {e}")
    
    def add_discovered_device(self, message, ip):
        """Add discovered device to the list"""
        device_id = message['device_id']
        device_name = message['device_name']
        
        if device_id not in self.connected_devices:
            self.log_message(f"🔗 New device discovered: {device_name} ({ip})")
        
        self.connected_devices[device_id] = {
            'name': device_name,
            'ip': ip,
            'last_seen': time.time(),
            'transfer_port': message.get('transfer_port', self.transfer_port)
        }
        
        self.update_device_list()
    
    def device_cleanup(self):
        """Remove devices that haven't been seen for a while"""
        while self.is_running:
            try:
                current_time = time.time()
                devices_to_remove = []
                
                for device_id, info in self.connected_devices.items():
                    if current_time - info['last_seen'] > 30:
                        devices_to_remove.append(device_id)
                
                for device_id in devices_to_remove:
                    device_name = self.connected_devices[device_id]['name']
                    del self.connected_devices[device_id]
                    self.log_message(f"❌ Device disconnected: {device_name}")
                
                if devices_to_remove:
                    self.update_device_list()
                
                time.sleep(10)  
                
            except Exception as e:
                logger.error(f"Device cleanup error: {e}")
                time.sleep(10)
    
    def transfer_server(self):
        """Handle incoming file transfers"""
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('', self.transfer_port))
            server_sock.listen(5)
            server_sock.settimeout(1)
            
            self.log_message(f"📁 Transfer server listening on port {self.transfer_port}")
            
            while self.is_running:
                try:
                    conn, addr = server_sock.accept()
                    transfer_thread = threading.Thread(
                        target=self.handle_file_transfer,
                        args=(conn, addr),
                        daemon=True
                    )
                    transfer_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Transfer server accept error: {e}")
                    
        except Exception as e:
            logger.error(f"Transfer server error: {e}")
        finally:
            try:
                server_sock.close()
            except:
                pass
    
    def handle_file_transfer(self, conn, addr):
        """Handle incoming file transfer"""
        try:
            metadata_size = struct.unpack('!I', conn.recv(4))[0]
            metadata_data = b''
            while len(metadata_data) < metadata_size:
                chunk = conn.recv(min(4096, metadata_size - len(metadata_data)))
                if not chunk:
                    break
                metadata_data += chunk
            
            metadata = json.loads(metadata_data.decode())
            filename = metadata['filename']
            filesize = metadata['filesize']
            sender = metadata.get('sender', 'Unknown')
            
            self.log_message(f"📥 Receiving file: {filename} ({filesize} bytes) from {sender}")
            
            received_path = self.received_folder / filename
            received_bytes = 0
            
            with open(received_path, 'wb') as f:
                while received_bytes < filesize:
                    chunk_size = min(8192, filesize - received_bytes)
                    chunk = conn.recv(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    received_bytes += len(chunk)
            
            if received_bytes == filesize:
                self.log_message(f"✅ File received successfully: {filename}")
                self.update_status(f"✅ File received: {filename}")
                
                self.root.after(0, lambda: messagebox.showinfo(
                    "File Received", 
                    f"File '{filename}' received successfully!\nSaved to: {received_path}"
                ))
            else:
                self.log_message(f"❌ File transfer incomplete: {filename}")
                
        except Exception as e:
            self.log_message(f"❌ File transfer error: {e}")
        finally:
            conn.close()
    
    def toggle_camera(self):
        """Toggle camera on/off"""
        if not self.camera_active:
            self.start_camera()
        else:
            self.stop_camera()
    
    def start_camera(self):
        """Start camera and gesture detection"""
        try:
            self.cap = cv2.VideoCapture(0)
            if not self.cap.isOpened():
                raise Exception("Cannot open camera")
            
            self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            self.cap.set(cv2.CAP_PROP_FPS, 30)
            
            self.camera_active = True
            self.camera_thread = threading.Thread(target=self.camera_loop, daemon=True)
            self.camera_thread.start()
            
            self.camera_btn.config(text="📷 Stop Camera", bg='#e74c3c')
            self.camera_status_label.config(text="Camera: ON", fg='#27ae60')
            self.log_message("📷 Camera started successfully")
            
        except Exception as e:
            self.log_message(f"❌ Failed to start camera: {e}")
            messagebox.showerror("Camera Error", f"Failed to start camera: {e}")
    
    def stop_camera(self):
        """Stop camera"""
        self.camera_active = False
        
        if self.cap:
            self.cap.release()
            self.cap = None
        
        cv2.destroyAllWindows()
        
        self.camera_btn.config(text="📷 Start Camera", bg='#27ae60')
        self.camera_status_label.config(text="Camera: OFF", fg='#ff6b6b')
        self.gesture_label.config(
            text="👋 Start camera to detect gestures",
            fg='#ffaa00'
        )
        self.log_message("📷 Camera stopped")
    
    def camera_loop(self):
        """Main camera loop"""
        while self.camera_active and self.cap:
            try:
                ret, frame = self.cap.read()
                if not ret:
                    self.log_message("❌ Failed to read from camera")
                    break
                
                frame = cv2.flip(frame, 1)
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                
                results = self.hands.process(rgb_frame)
                
                current_gesture = "none"
                if results.multi_hand_landmarks:
                    for hand_landmarks in results.multi_hand_landmarks:
                        self.mp_draw.draw_landmarks(
                            frame, hand_landmarks, self.mp_hands.HAND_CONNECTIONS
                        )
                        
                        current_gesture = self.detect_gesture(hand_landmarks.landmark)
                
                self.update_gesture_state(current_gesture)
                
                self.add_camera_overlay(frame, current_gesture)
                
                cv2.imshow('Gesture AirDrop - Camera (Press Q to close)', frame)
                
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
                    
            except Exception as e:
                self.log_message(f"❌ Camera loop error: {e}")
                break
        
        self.stop_camera()
    
    def add_camera_overlay(self, frame, gesture):
        """Add overlay information to camera frame"""
        height, width = frame.shape[:2]
        
        gesture_text = f"Gesture: {gesture.upper()}"
        cv2.putText(frame, gesture_text, (10, 30), 
                   cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
        
        device_count = len(self.connected_devices)
        device_text = f"Connected Devices: {device_count}"
        cv2.putText(frame, device_text, (10, 70), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 0), 2)
        
        file_text = "File: " + (os.path.basename(self.selected_file) if self.selected_file else "None")
        cv2.putText(frame, file_text, (10, height - 20), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 0, 255), 2)
    
    def detect_gesture(self, landmarks):
        """Detect fist or open hand gesture"""
        if not landmarks:
            return "none"
        
        finger_tips = [4, 8, 12, 16, 20]  
        finger_pips = [3, 6, 10, 14, 18]  
        
        extended_fingers = 0
        
        if landmarks[4].x > landmarks[3].x: 
            extended_fingers += 1
        
        for i in range(1, 5):
            if landmarks[finger_tips[i]].y < landmarks[finger_pips[i]].y:
                extended_fingers += 1

        if extended_fingers <= 1:
            return "fist"
        elif extended_fingers >= 4:
            return "open"
        else:
            return "partial"
    
    def update_gesture_state(self, current_gesture):
        """Update gesture state with stability check"""
        current_time = time.time()
        
        if current_gesture != self.gesture_state:
            if current_time - self.last_gesture_time > self.gesture_stability_time:
                old_gesture = self.gesture_state
                self.gesture_state = current_gesture
                self.last_gesture_time = current_time
                
                self.root.after(0, lambda: self.update_gesture_display(current_gesture))
                
                if old_gesture != current_gesture:
                    self.handle_gesture_change(current_gesture)
        else:
            self.last_gesture_time = current_time
    
    def handle_gesture_change(self, gesture):
        """Handle gesture state changes"""
        if gesture == "fist" and self.selected_file and self.connected_devices:
            self.log_message("✊ Fist detected - Initiating file transfer...")
            self.broadcast_gesture_signal("fist_ready")
            
        elif gesture == "open" and self.connected_devices:
            self.log_message("✋ Open hand detected - Ready to receive...")
            self.broadcast_gesture_signal("open_ready")
    
    def broadcast_gesture_signal(self, signal):
        """Broadcast gesture signal to all connected devices"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            message = {
                'type': 'gesture_signal',
                'device_id': self.device_id,
                'device_name': self.device_name,
                'signal': signal,
                'has_file': self.selected_file is not None,
                'timestamp': time.time()
            }
            
            sock.sendto(json.dumps(message).encode(), ('<broadcast>', self.discovery_port))
            sock.close()
            
        except Exception as e:
            self.log_message(f"❌ Failed to broadcast gesture signal: {e}")
    
    def handle_gesture_signal(self, message, sender_ip):
        """Handle gesture signals from other devices"""
        signal = message['signal']
        sender_name = message['device_name']
        has_file = message.get('has_file', False)
        
        if signal == "fist_ready" and has_file:
            self.log_message(f"👊 {sender_name} wants to send a file")
            
            if self.gesture_state == "open":
                self.log_message(f"✋ Auto-accepting file from {sender_name}")
                self.request_file_transfer(sender_ip, message['device_id'])
                
        elif signal == "open_ready":
            self.log_message(f"✋ {sender_name} is ready to receive files")
            
            if self.gesture_state == "fist" and self.selected_file:
                self.log_message(f"👊 Sending file to {sender_name}")
                self.send_file_to_device(sender_ip, message['device_id'])
    
    def request_file_transfer(self, sender_ip, sender_device_id):
        """Request file transfer from sender"""
        pass
    
    def send_file_to_device(self, target_ip, target_device_id):
        """Send file to target device"""
        if not self.selected_file or not os.path.exists(self.selected_file):
            self.log_message("❌ No valid file selected")
            return
        
        try:
            device_info = None
            for device_id, info in self.connected_devices.items():
                if device_id == target_device_id:
                    device_info = info
                    break
            
            if not device_info:
                self.log_message("❌ Device not found")
                return
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  
            
            transfer_port = device_info.get('transfer_port', self.transfer_port)
            sock.connect((target_ip, transfer_port))
            
            filename = os.path.basename(self.selected_file)
            filesize = os.path.getsize(self.selected_file)
            
            metadata = {
                'filename': filename,
                'filesize': filesize,
                'sender': self.device_name,
                'checksum': self.calculate_file_checksum(self.selected_file)
            }
            
            metadata_json = json.dumps(metadata).encode()

            sock.send(struct.pack('!I', len(metadata_json)))
            sock.send(metadata_json)
            
            self.log_message(f"📤 Sending {filename} ({filesize} bytes)...")
            
            with open(self.selected_file, 'rb') as f:
                sent_bytes = 0
                while sent_bytes < filesize:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sock.send(chunk)
                    sent_bytes += len(chunk)
                    
                    progress = (sent_bytes / filesize) * 100
                    if sent_bytes % (filesize // 10 + 1) < 8192: 
                        self.root.after(0, lambda p=progress: self.update_status(f"📤 Sending... {p:.1f}%"))
            
            sock.close()
            self.log_message(f"✅ File sent successfully: {filename}")
            self.update_status(f"✅ File sent: {filename}")
            
        except Exception as e:
            self.log_message(f"❌ Failed to send file: {e}")
            self.update_status(f"❌ Send failed: {str(e)}")
    
    def calculate_file_checksum(self, filepath):
        """Calculate MD5 checksum of file"""
        try:
            hash_md5 = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return None
    
    def select_file(self):
        """Select file for transfer"""
        filename = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=[
                ("All files", "*.*"),
                ("Images", "*.jpg *.jpeg *.png *.gif *.bmp *.tiff"),
                ("Videos", "*.mp4 *.avi *.mov *.mkv *.wmv *.flv"),
                ("Documents", "*.pdf *.doc *.docx *.txt *.rtf *.xlsx *.pptx"),
                ("Audio", "*.mp3 *.wav *.flac *.aac *.ogg"),
                ("Archives", "*.zip *.rar *.7z *.tar *.gz")
            ]
        )
        
        if filename:
            self.selected_file = filename
            file_name = os.path.basename(filename)
            file_size = os.path.getsize(filename) / (1024 * 1024)  # MB
            
            size_text = f"{file_size:.2f} MB" if file_size < 1024 else f"{file_size/1024:.2f} GB"
            self.file_label.config(
                text=f"{file_name} ({size_text})",
                fg='#27ae60'
            )
            self.log_message(f"📁 File selected: {file_name} ({size_text})")
    
    def update_status(self, message):
        """Update status label"""
        def update():
            self.status_label.config(text=message)
            if not any(x in message.lower() for x in ['error', 'failed', '❌']):
                self.root.after(5000, lambda: self.status_label.config(text="✅ Ready"))
        
        if threading.current_thread() != threading.main_thread():
            self.root.after(0, update)
        else:
            update()
    
    def update_gesture_display(self, gesture):
        """Update gesture display"""
        gesture_info = {
            "fist": ("✊ FIST - Ready to send!", '#e74c3c'),
            "open": ("✋ OPEN - Ready to receive!", '#27ae60'),
            "partial": ("👍 PARTIAL - Adjust hand position", '#f39c12'),
            "none": ("👋 Show your hand to camera", '#ffaa00')
        }
        
        text, color = gesture_info.get(gesture, ("❓ Unknown gesture", '#666666'))
        self.gesture_label.config(text=text, fg=color)
    
    def update_device_list(self):
        """Update device list display"""
        def update():
            self.devices_listbox.delete(0, tk.END)
            
            if not self.connected_devices:
                self.devices_listbox.insert(tk.END, "No devices found...")
                self.update_status("🔍 Searching for devices...")
            else:
                for device_id, info in self.connected_devices.items():
                    device_text = f"{info['name']} - {info['ip']}"
                    self.devices_listbox.insert(tk.END, device_text)
                
                count = len(self.connected_devices)
                self.update_status(f"🔗 Connected to {count} device{'s' if count != 1 else ''}")
        
        if threading.current_thread() != threading.main_thread():
            self.root.after(0, update)
        else:
            update()
    
    def on_closing(self):
        """Handle window closing"""
        self.log_message("🔄 Shutting down...")
        self.is_running = False
        
        if self.camera_active:
            self.stop_camera()
        
        time.sleep(1)
        
        self.root.destroy()
    
    def run(self):
        """Run the application"""
        try:
            self.log_message("🚀 Gesture AirDrop started successfully!")
            self.log_message("💡 Click 'Start Camera' to begin gesture detection")
            self.root.mainloop()
        except Exception as e:
            logger.error(f"Application error: {e}")
        finally:
            self.is_running = False

def check_dependencies():
    """Check if required packages are installed"""
    required_packages = {
        'cv2': 'opencv-python',
        'mediapipe': 'mediapipe'
    }
    
    missing_packages = []
    
    for package, pip_name in required_packages.items():
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(pip_name)
    
    if missing_packages:
        print("❌ Missing required packages!")
        print("📦 Please install the following packages:")
        print(f"   pip install {' '.join(missing_packages)}")
        print("\n💡 For better performance, also install:")
        print("   pip install opencv-contrib-python")
        return False
    
    return True

def main():
    """Main function"""
    print("🤚 Gesture AirDrop - Optimized Version")
    print("=" * 50)
    
    if not check_dependencies():
        input("Press Enter to exit...")
        return
    
    print("📷 Checking camera availability...")
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("⚠️  Warning: Camera not detected or in use by another application")
        print("   You can still run the app, but gesture detection won't work")
        print("   until you start the camera manually.")
    else:
        print("✅ Camera is available")
        cap.release()
    
    print("🚀 Starting Gesture AirDrop...")
    print("💡 The app will automatically discover other devices running the same script")
    print()
    
    try:
        app = OptimizedGestureAirDrop()
        app.run()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()