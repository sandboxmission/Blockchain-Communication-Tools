import customtkinter as ctk
import requests
from datetime import datetime
import time
import threading
from lzstring import LZString
import json
import base64
import os

# CustomTkinter Setup
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Cache constants
CACHE_FILE = "blockchain_scanner_cache.json"
CACHE_SAVE_INTERVAL = 10  # Save cache every 10 messages

# Network configurations with responsive parameters
NETWORKS = {
    "sepolia": {
        "name": "Ethereum Sepolia",
        "rpc_url": "https://ethereum-sepolia-rpc.publicnode.com",
        "explorer": "https://sepolia.etherscan.io",
        "max_requests_per_minute": 60,
        "batch_size": 10,
        "batch_delay": 1.0
    },
    "mainnet": {
        "name": "Ethereum Mainnet", 
        "rpc_url": "https://ethereum-rpc.publicnode.com",
        "explorer": "https://etherscan.io",
        "max_requests_per_minute": 120,
        "batch_size": 25,
        "batch_delay": 0.3,
        "max_scan_blocks": 1000
    }
}

MIN_SLEEP = 0.5
EINTRV = 60

# Global variables per network
network_states = {
    "sepolia": {
        "last_block_seen": None,
        "rpc_request_count": 0,
        "realtime_start_time": None,
        "last_request_time": 0,
        "requests_this_minute": []
    },
    "mainnet": {
        "last_block_seen": None, 
        "rpc_request_count": 0,
        "realtime_start_time": None,
        "last_request_time": 0,
        "requests_this_minute": []
    }
}

def rpc_post(method, params, network="sepolia"):
    state = network_states[network]
    network_config = NETWORKS[network]
    rpc_url = network_config["rpc_url"]
    max_requests = network_config["max_requests_per_minute"]
    
    now = time.time()
    state["requests_this_minute"] = [req_time for req_time in state["requests_this_minute"] if now - req_time < 60]
    
    if len(state["requests_this_minute"]) >= max_requests:
        sleep_time = 60 - (now - state["requests_this_minute"][0])
        print(f"Rate limit reached for {network} ({max_requests}/min). Sleeping for {sleep_time:.1f} seconds...")
        time.sleep(sleep_time + 1)
        state["requests_this_minute"] = []
    
    time_since_last = now - state["last_request_time"]
    if time_since_last < MIN_SLEEP:
        time.sleep(MIN_SLEEP - time_since_last)
    
    start_time = time.time()
    try:
        response = requests.post(rpc_url, json={"jsonrpc":"2.0","method":method,"params":params,"id":1}, timeout=15)
        response.raise_for_status()
    except requests.exceptions.Timeout:
        print(f"RPC Timeout for {method} on {network}")
        return None
    except Exception as e:
        print(f"RPC Error ({method}) on {network}: {e}")
        return None
    
    state["last_request_time"] = time.time()
    state["requests_this_minute"].append(state["last_request_time"])
    
    if state["realtime_start_time"] is not None:
        state["rpc_request_count"] += 1
    
    min_sleep = MIN_SLEEP if network == "mainnet" else MIN_SLEEP * 2
    elapsed = time.time() - start_time
    if elapsed < min_sleep:
        time.sleep(min_sleep - elapsed)
    
    result = response.json()
    if "error" in result:
        print(f"RPC Error Response on {network}: {result['error']}")
        return None
    
    return result.get("result")

def latest_block_number(network="sepolia"):
    result = rpc_post("eth_blockNumber", [], network)
    return 0 if result is None else int(result, 16)

def find_start_block(target_timestamp, network="sepolia"):
    low = 0
    high = latest_block_number(network)
    while low < high:
        mid = (low + high) // 2
        block = rpc_post("eth_getBlockByNumber", [hex(mid), True], network)
        if not block:
            high = mid - 1
            continue
        ts = int(block["timestamp"], 16)
        if ts < target_timestamp:
            low = mid + 1
        else:
            high = mid
    return low

def safe_decode_bytes(raw_bytes):
    try:
        return raw_bytes.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        try:
            return raw_bytes.decode("latin-1"), "latin-1"
        except UnicodeDecodeError:
            try:
                return raw_bytes.decode("ascii", errors='ignore'), "ascii-filtered"
            except:
                return raw_bytes.hex(), "hex"

def detect_content_type(content):
    if not content:
        return "empty"
    
    content_lower = content.lower().strip()
    
    if any(tag in content_lower for tag in ['<html', '<!doctype html', '<head>', '<body>']):
        return "html"
    
    if (content_lower.startswith('{') and content_lower.endswith('}')) or \
       (content_lower.startswith('[') and content_lower.endswith(']')):
        return "json"
    
    if content_lower.startswith('<?xml') or (content_lower.startswith('<') and content_lower.endswith('>')):
        return "xml"
    
    if len(content) > 50 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in content.replace('\n', '').replace('\r', '').strip()):
        return "base64"
    
    return "text"

def process_eth_file_data(decoded_data, tx_hash, block_num):
    try:
        parts = decoded_data[len("ETH_FILE_DATA:"):].split(";")
        mime_type = "application/octet-stream"
        file_name = f"blockchain_data_{block_num}_{tx_hash[:8]}"
        base64_data = ""

        for part in parts:
            if part.startswith("type="):
                mime_type = part[5:]
            elif part.startswith("name="):
                file_name = part[5:]
            elif part.startswith("data="):
                base64_data = part[5:]

        if not base64_data:
            return None, "No data found in ETH_FILE_DATA"

        decompressed_content = LZString.decompressFromBase64(base64_data)

        if decompressed_content:
            try:
                if mime_type.startswith("text/") or mime_type == "text/html":
                    if not any(ext in file_name.lower() for ext in ['.txt', '.html', '.htm', '.css', '.js']):
                        if mime_type == "text/html":
                            file_name += ".html"
                        else:
                            file_name += ".txt"
                    
                    with open(file_name, "w", encoding="utf-8") as f:
                        f.write(decompressed_content)
                else:
                    if "." not in file_name:
                        file_name += ".bin"
                    
                    try:
                        content_bytes = decompressed_content.encode('utf-8')
                    except:
                        content_bytes = decompressed_content.encode('latin-1', errors='ignore')
                    
                    with open(file_name, "wb") as f:
                        f.write(content_bytes)
                
                saved = True
            except Exception as save_error:
                print(f"Save error: {save_error}")
                saved = False
                file_name = f"[Save failed: {str(save_error)}]"

            preview = decompressed_content[:300]
            if len(decompressed_content) > 300:
                preview += "..."
            
            return {
                "type": "eth_file_data",
                "file_name": file_name,
                "mime_type": mime_type,
                "size": len(decompressed_content),
                "preview": preview,
                "saved": saved,
                "content_type": detect_content_type(decompressed_content),
                "full_content": decompressed_content
            }, "success"
        else:
            return None, "LZString decompression failed"

    except Exception as e:
        return None, f"ETH_FILE_DATA processing error: {str(e)}"

def process_transaction_data(input_data, tx_hash, block_num):
    if not input_data or input_data == "0x":
        return None, "No data"
    
    try:
        raw_bytes = bytes.fromhex(input_data[2:])
        decoded_data, decode_method = safe_decode_bytes(raw_bytes)
        
        if not decoded_data:
            return None, "Decode failed"
        
        if decoded_data.startswith("ETH_FILE_DATA:"):
            return process_eth_file_data(decoded_data, tx_hash, block_num)
        
        content_type = detect_content_type(decoded_data)
        
        result = {
            "type": "flexible_data",
            "content_type": content_type,
            "decode_method": decode_method,
            "size": len(decoded_data),
            "raw_size": len(raw_bytes),
            "data": decoded_data
        }
        
        if content_type == "base64" and len(decoded_data) > 10:
            try:
                base64_decoded = base64.b64decode(decoded_data).decode('utf-8')
                result["base64_decoded"] = base64_decoded
                result["base64_content_type"] = detect_content_type(base64_decoded)
            except:
                pass
        
        try:
            lz_decompressed = LZString.decompressFromBase64(decoded_data)
            if lz_decompressed and lz_decompressed != decoded_data and len(lz_decompressed) > 10:
                result["lz_decompressed"] = lz_decompressed
                result["lz_content_type"] = detect_content_type(lz_decompressed)
        except:
            pass
        
        if content_type == "json":
            try:
                json_data = json.loads(decoded_data)
                result["json_parsed"] = json_data
            except:
                pass
        
        return result, "success"
        
    except Exception as e:
        return None, f"Processing error: {str(e)}"

def format_output(tx, block_num, processed_data, status):
    value_eth = int(tx.get("value", "0x0"), 16) / 10**18
    
    output = []
    output.append(f"🔗 Block: {block_num}")
    output.append(f"📤 From: {tx['from']}")
    output.append(f"📥 To: {tx.get('to', 'N/A')}")
    output.append(f"🏷️  Hash: {tx['hash']}")
    output.append(f"💰 Value: {value_eth:.6f} ETH")
    
    if status == "No data":
        output.append("📄 Message: <No transaction data>")
    elif status == "success" and processed_data:
        if processed_data["type"] == "eth_file_data":
            output.append(f"📄 [ETH_FILE] Name: {processed_data['file_name']}")
            output.append(f"📋 MIME: {processed_data['mime_type']}")
            output.append(f"📏 Size: {processed_data['size']} bytes")
            output.append(f"📝 Content Type: {processed_data['content_type']}")
            output.append(f"💾 Saved: {'✅ Yes' if processed_data['saved'] else '❌ No'}")
            output.append(f"👀 Preview: {processed_data['preview']}")
        
        elif processed_data["type"] == "flexible_data":
            output.append(f"📊 [DATA] Content Type: {processed_data['content_type']}")
            output.append(f"🔤 Decode: {processed_data['decode_method']}")
            output.append(f"📏 Size: {processed_data['size']} chars ({processed_data['raw_size']} bytes)")
            
            if "lz_decompressed" in processed_data:
                output.append(f"🗜️  [LZ-DECOMPRESSED] Type: {processed_data['lz_content_type']}")
                preview = processed_data["lz_decompressed"][:200]
                if len(processed_data["lz_decompressed"]) > 200:
                    preview += "..."
                output.append(f"📄 Decompressed Content: {preview}")
            
            elif "base64_decoded" in processed_data:
                output.append(f"🔓 [BASE64-DECODED] Type: {processed_data['base64_content_type']}")
                preview = processed_data["base64_decoded"][:200]
                if len(processed_data["base64_decoded"]) > 200:
                    preview += "..."
                output.append(f"📄 Decoded Content: {preview}")
            
            elif "json_parsed" in processed_data:
                output.append(f"📋 [JSON] Type: {type(processed_data['json_parsed'])}")
                json_str = str(processed_data['json_parsed'])[:200]
                if len(str(processed_data['json_parsed'])) > 200:
                    json_str += "..."
                output.append(f"📄 JSON Content: {json_str}")
            
            else:
                if processed_data["decode_method"] != "hex":
                    preview = processed_data["data"][:200]
                    if len(processed_data["data"]) > 200:
                        preview += "..."
                    output.append(f"📄 Content: {preview}")
                else:
                    output.append(f"📄 Content: <Binary data - {processed_data['raw_size']} bytes>")
    else:
        output.append(f"📄 Message: <{status}>")
    
    output.append("─" * 80)
    return "\n".join(output) + "\n"

class BlockchainScannerApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("🔗 Blockchain Communication Scanner")
        
        # Fixed window size for optimal display without scrolling
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Grid configuration for main window
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Statistics variables
        self.blocks_scanned = 0
        self.messages_found = 0
        self.rpc_calls_made = 0
        self.addresses_monitoring = 0
        
        # Real-time scan variables
        self.last_block_seen = {}
        self.realtime_active = False
        self.countdown = EINTRV
        self.active_networks = []
        
        # Message storage for filtering and details
        self.found_messages = []
        self.filtered_messages = []
        
        # Cache counter
        self.cache_counter = 0
        
        # Load cache on startup
        self.load_cache()
        
        # Setup UI
        self.setup_ui()
        
        # Adjust font sizes
        self.adjust_font_sizes()
        
        # Event handler for window resize
        self.root.bind("<Configure>", self.on_window_resize)
    
    def adjust_font_sizes(self):
        """Adjust font sizes based on window size"""
        width = self.root.winfo_width()
        
        if width < 1200:  # Small screens
            label_size = 10
            button_size = 12
            input_size = 11
        elif width < 1600:  # Medium screens
            label_size = 11
            button_size = 13
            input_size = 12
        else:  # Large screens
            label_size = 12
            button_size = 14
            input_size = 13
        
        # Adjust buttons
        if hasattr(self, 'scan_button'):
            self.scan_button.configure(font=ctk.CTkFont(size=button_size, weight="bold"))
        
        # Adjust input fields
        if hasattr(self, 'date_entry'):
            self.date_entry.configure(font=ctk.CTkFont(size=input_size))
        if hasattr(self, 'addr_textbox'):
            self.addr_textbox.configure(font=ctk.CTkFont(size=input_size))
    
    def on_window_resize(self, event):
        """React to window size changes"""
        # Only react to actual size changes
        if event.widget == self.root:
            self.adjust_font_sizes()
            
            # Adjust layout for very small windows
            if event.width < 1000:
                # Change two-column layout to single column
                if hasattr(self, 'content_frame'):
                    self.content_frame.grid_columnconfigure(0, weight=1)
                    self.content_frame.grid_columnconfigure(1, weight=0)
                    if hasattr(self, 'right_frame'):
                        self.right_frame.grid_forget()
                        self.right_frame.grid(row=1, column=0, sticky="nsew", padx=(2, 5), pady=5)
            else:
                # Restore standard two-column layout
                if hasattr(self, 'content_frame'):
                    self.content_frame.grid_columnconfigure(0, weight=1)
                    self.content_frame.grid_columnconfigure(1, weight=1)
                    if hasattr(self, 'right_frame'):
                        self.right_frame.grid_forget()
                        self.right_frame.grid(row=0, column=1, sticky="nsew", padx=(2, 5), pady=5)
    
    def setup_ui(self):
        # Main container with padding
        main_frame = ctk.CTkFrame(self.root)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # GRID CONFIGURATION: 55% for upper area, 45% for content area
        main_frame.grid_rowconfigure(0, weight=11)  # Upper area
        main_frame.grid_rowconfigure(1, weight=9)  # Content area
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Top frame for all upper elements
        top_frame = ctk.CTkFrame(main_frame)
        top_frame.grid(row=0, column=0, sticky="nsew")
        top_frame.grid_rowconfigure(0, weight=1)  # Control area
        top_frame.grid_columnconfigure(0, weight=1)
        
        # Control area
        control_frame = ctk.CTkFrame(top_frame)
        control_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        control_frame.grid_columnconfigure(0, weight=1)
        
        # Input fields in a frame (no scrolling)
        inputs_frame = ctk.CTkFrame(control_frame)
        inputs_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        inputs_frame.grid_columnconfigure(1, weight=1)
        
        # First row: Date and block inputs
        date_label = ctk.CTkLabel(inputs_frame, text="Start Date (YYYY-MM-DD):", font=ctk.CTkFont(weight="bold"))
        date_label.grid(row=0, column=0, sticky="w", padx=(10, 5), pady=(5, 5))
        
        self.date_entry = ctk.CTkEntry(inputs_frame, placeholder_text="2024-01-01", width=180)
        self.date_entry.grid(row=0, column=1, sticky="w", padx=(0, 10), pady=(5, 5))
        
        or_label = ctk.CTkLabel(inputs_frame, text="OR", font=ctk.CTkFont(weight="bold"))
        or_label.grid(row=0, column=2, sticky="", padx=(0, 0), pady=(5, 5))
        
        # Block inputs - side by side
        block_frame = ctk.CTkFrame(inputs_frame)
        block_frame.grid(row=0, column=3, sticky="w", padx=(10, 10), pady=(5, 5))

        sepolia_block_label = ctk.CTkLabel(block_frame, text="Sepolia:", font=ctk.CTkFont(size=10))
        sepolia_block_label.grid(row=0, column=0, padx=5, pady=(5, 0), sticky="w")

        self.sepolia_block_entry = ctk.CTkEntry(block_frame, placeholder_text="Latest", width=80)
        self.sepolia_block_entry.grid(row=1, column=0, padx=5, pady=(0, 5))

        mainnet_block_label = ctk.CTkLabel(block_frame, text="Mainnet:", font=ctk.CTkFont(size=10))
        mainnet_block_label.grid(row=0, column=1, padx=5, pady=(5, 0), sticky="w")

        self.mainnet_block_entry = ctk.CTkEntry(block_frame, placeholder_text="Latest", width=80)
        self.mainnet_block_entry.grid(row=1, column=1, padx=5, pady=(0, 5))

        # Second row: Network selection
        network_label = ctk.CTkLabel(inputs_frame, text="Networks:", font=ctk.CTkFont(weight="bold"))
        network_label.grid(row=1, column=0, sticky="w", padx=(10, 5), pady=(5, 0))
        
        network_frame = ctk.CTkFrame(inputs_frame)
        network_frame.grid(row=1, column=1, columnspan=3, sticky="w", padx=(0, 10), pady=(5, 0))
        
        self.sepolia_var = ctk.BooleanVar(value=True)
        self.mainnet_var = ctk.BooleanVar(value=True)
        
        sepolia_check = ctk.CTkCheckBox(network_frame, text="Ethereum Sepolia", variable=self.sepolia_var)
        sepolia_check.pack(side="left", padx=(10, 20), pady=5)
        
        mainnet_check = ctk.CTkCheckBox(network_frame, text="Ethereum Mainnet", variable=self.mainnet_var)
        mainnet_check.pack(side="left", padx=(0, 10), pady=5)
        
        # Third row: Address input
        addr_label = ctk.CTkLabel(inputs_frame, text="Addresses:", font=ctk.CTkFont(weight="bold"))
        addr_label.grid(row=2, column=0, sticky="nw", padx=(10, 5), pady=(5, 0))
        
        # Address input with fixed height
        self.addr_textbox = ctk.CTkTextbox(inputs_frame, height=80, width=400)
        self.addr_textbox.grid(row=2, column=1, columnspan=3, sticky="ew", padx=(0, 10), pady=(5, 5))
        
        # Add default addresses
        default_addresses = "0x000000000000000000000000000000000000dead\n0x0000000000000000000000000000000000000001\n0x0000000000000000000000000000000000000000\n0x1111111111111111111111111111111111111111\n0x4444444444444444444444444444444444444444"
        self.addr_textbox.insert("1.0", default_addresses)
        
        # Control buttons and statistics
        control_bottom_frame = ctk.CTkFrame(control_frame)
        control_bottom_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        
        # Scan button
        self.scan_button = ctk.CTkButton(
            control_bottom_frame,
            text="🔍 Start Scanning",
            command=self.start_scan,
            font=ctk.CTkFont(size=14, weight="bold"),
            height=35,
            width=160
        )
        self.scan_button.pack(side="left", padx=(10, 20), pady=10)
        
        # Statistics
        stats_frame = ctk.CTkFrame(control_bottom_frame)
        stats_frame.pack(side="right", padx=(20, 10), pady=10)
        
        self.stats_label = ctk.CTkLabel(
            stats_frame,
            text="📊 Ready • Addresses: 5 • Blocks: 0 • Messages: 0 • RPC: 0",
            font=ctk.CTkFont(size=11)
        )
        self.stats_label.pack(padx=15, pady=8)
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(top_frame)
        self.progress_bar.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 5))
        self.progress_bar.set(0)
        
        # Status
        self.status_label = ctk.CTkLabel(top_frame, text="🟢 Ready to scan", font=ctk.CTkFont(size=11))
        self.status_label.grid(row=2, column=0, sticky="w", padx=15, pady=(0, 10))
        
        # RESULTS AREA
        self.results_frame = ctk.CTkFrame(main_frame)
        self.results_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        
        # GRID CONFIGURATION for results_frame:
        # 0: Filter (fixed height)
        # 1: Content (two columns, gets remaining space)
        # 2: Log (fixed height)
        self.results_frame.grid_rowconfigure(0, weight=0)  # Filter
        self.results_frame.grid_rowconfigure(1, weight=4)  # Content
        self.results_frame.grid_rowconfigure(2, weight=1)  # Log
        self.results_frame.grid_columnconfigure(0, weight=1)
        self.results_frame.grid_columnconfigure(1, weight=1)
        
        # Filter controls
        filter_frame = ctk.CTkFrame(self.results_frame)
        filter_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=15, pady=(10, 5))
        
        filter_label = ctk.CTkLabel(filter_frame, text="🔍 Filter:", font=ctk.CTkFont(size=12, weight="bold"))
        filter_label.pack(side="left", padx=(10, 20))
        
        self.filter_var = ctk.StringVar(value="all")
        
        filter_all = ctk.CTkRadioButton(filter_frame, text="All", variable=self.filter_var, value="all", command=self.apply_filter)
        filter_all.pack(side="left", padx=(0, 10))
        
        filter_text = ctk.CTkRadioButton(filter_frame, text="Text", variable=self.filter_var, value="text", command=self.apply_filter)
        filter_text.pack(side="left", padx=(0, 10))
        
        filter_files = ctk.CTkRadioButton(filter_frame, text="Files", variable=self.filter_var, value="files", command=self.apply_filter)
        filter_files.pack(side="left", padx=(0, 10))
        
        filter_json = ctk.CTkRadioButton(filter_frame, text="JSON", variable=self.filter_var, value="json", command=self.apply_filter)
        filter_json.pack(side="left", padx=(0, 10))
        
        # Clear button
        clear_btn = ctk.CTkButton(filter_frame, text="🗑️ Clear", width=60, command=self.clear_messages)
        clear_btn.pack(side="right", padx=10)
        
        # Content area with two columns
        self.content_frame = ctk.CTkFrame(self.results_frame)
        self.content_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=15, pady=(0, 10))
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(1, weight=1)
        
        # Left side: Message list
        left_frame = ctk.CTkFrame(self.content_frame)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(5, 2), pady=5)
        left_frame.grid_rowconfigure(1, weight=1)
        
        list_header = ctk.CTkLabel(left_frame, text="📋 Found Messages", font=ctk.CTkFont(size=14, weight="bold"))
        list_header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        
        # Message list (clickable and scrollable)
        self.message_listbox = ctk.CTkScrollableFrame(left_frame)
        self.message_listbox.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        
        # Right side: Message details
        self.right_frame = ctk.CTkFrame(self.content_frame)
        self.right_frame.grid(row=0, column=1, sticky="nsew", padx=(2, 5), pady=5)
        self.right_frame.grid_rowconfigure(1, weight=1)
        
        detail_header = ctk.CTkLabel(self.right_frame, text="📄 Message Details", font=ctk.CTkFont(size=14, weight="bold"))
        detail_header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        
        self.detail_textbox = ctk.CTkTextbox(
            self.right_frame,
            font=ctk.CTkFont(family="JetBrains Mono", size=10),
            wrap="word"
        )
        self.detail_textbox.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        
        # Initialize detail view
        self.detail_textbox.insert("1.0", "👈 Click on a message to view details")
        
        # Log area
        log_frame = ctk.CTkFrame(self.results_frame)
        log_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=15, pady=(0, 10))
        
        log_header = ctk.CTkLabel(log_frame, text="📊 Scan Log", font=ctk.CTkFont(size=12, weight="bold"))
        log_header.pack(pady=(10, 5))
        
        # Text output with fixed height
        self.text_output = ctk.CTkTextbox(
            log_frame,
            font=ctk.CTkFont(family="JetBrains Mono", size=9),
            wrap="word",
            height=80
        )
        self.text_output.pack(fill="x", padx=10, pady=(0, 10))
        
        # Welcome message
        welcome_msg = "🔍 Scanner ready! Pre-loaded 5 addresses. Both networks selected."
        self.text_output.insert("1.0", welcome_msg)
    
    def load_cache(self):
        """Load messages from cache file"""
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                    self.found_messages = cached_data.get('messages', [])
                    self.blocks_scanned = cached_data.get('blocks_scanned', 0)
                    self.messages_found = cached_data.get('messages_found', 0)
                    self.rpc_calls_made = cached_data.get('rpc_calls_made', 0)
                    print(f"Cache loaded: {len(self.found_messages)} messages")
            except Exception as e:
                print(f"Error loading cache: {e}")
    
    def save_cache(self):
        """Save messages to cache file"""
        try:
            cache_data = {
                'messages': self.found_messages,
                'blocks_scanned': self.blocks_scanned,
                'messages_found': self.messages_found,
                'rpc_calls_made': self.rpc_calls_made
            }
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
            print(f"Cache saved: {len(self.found_messages)} messages")
        except Exception as e:
            print(f"Error saving cache: {e}")
    
    def parse_addresses(self, address_text):
        """Parse multiple addresses from text input"""
        addresses = []
        
        # Split by commas and newlines, clean whitespace
        for addr in address_text.replace('\n', ',').split(','):
            addr = addr.strip()
            if addr:
                # Validate address format
                if addr.startswith('0x') and len(addr) == 42:
                    addresses.append(addr.lower())
                else:
                    self.text_output.insert("end", f"⚠️  Invalid address format: {addr}\n")
        
        return addresses
    
    def store_message(self, tx, block_num, processed_data, status, matched_addr, network):
        """Store found message for filtering and detail view"""
        message_data = {
            "block": block_num,
            "network": network,
            "tx_hash": tx['hash'],
            "from": tx['from'],
            "to": tx.get('to', 'N/A'),
            "value": int(tx.get("value", "0x0"), 16) / 10**18,
            "matched_address": matched_addr,
            "processed_data": processed_data,
            "status": status,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "explorer_url": f"{NETWORKS[network]['explorer']}/tx/{tx['hash']}"
        }
        
        # Determine message type for filtering
        if status == "success" and processed_data:
            if processed_data["type"] == "eth_file_data":
                message_data["message_type"] = "files"
                message_data["preview"] = f"File: {processed_data.get('file_name', 'unknown')}"
                message_data["content"] = processed_data.get('preview', '')
            elif processed_data["type"] == "flexible_data":
                if processed_data.get("content_type") == "json" or "json_parsed" in processed_data:
                    message_data["message_type"] = "json"
                    message_data["preview"] = "JSON Data"
                    if "json_parsed" in processed_data:
                        message_data["content"] = str(processed_data["json_parsed"])[:100]
                    else:
                        message_data["content"] = processed_data.get("data", "")[:100]
                else:
                    message_data["message_type"] = "text"
                    if "lz_decompressed" in processed_data:
                        content = processed_data["lz_decompressed"]
                        message_data["preview"] = f"Compressed: {content[:30]}..."
                        message_data["content"] = content
                    elif "base64_decoded" in processed_data:
                        content = processed_data["base64_decoded"]
                        message_data["preview"] = f"Base64: {content[:30]}..."
                        message_data["content"] = content
                    else:
                        content = processed_data.get("data", "")
                        message_data["preview"] = content[:50]
                        message_data["content"] = content
        else:
            message_data["message_type"] = "other"
            message_data["preview"] = f"<{status}>"
            message_data["content"] = ""
        
        self.found_messages.append(message_data)
        self.messages_found += 1
        
        # Save cache regularly
        self.cache_counter += 1
        if self.cache_counter >= CACHE_SAVE_INTERVAL:
            self.save_cache()
            self.cache_counter = 0
        
        # Thread-safe update
        self.safe_ui_update(self.apply_filter)
    
    def apply_filter(self):
        """Apply current filter to message list"""
        filter_type = self.filter_var.get()
        
        if filter_type == "all":
            self.filtered_messages = self.found_messages.copy()
        else:
            self.filtered_messages = [msg for msg in self.found_messages if msg["message_type"] == filter_type]
        
        self.update_message_list()
    
    def update_message_list(self):
        """Update clickable message list"""
        # Delete existing elements
        for widget in self.message_listbox.winfo_children():
            widget.destroy()
        
        # Limit number of messages to display
        max_display = 100  # For better performance
        display_messages = self.filtered_messages[-max_display:]
        
        for i, msg in enumerate(display_messages):
            # Create clickable message element
            msg_frame = ctk.CTkFrame(self.message_listbox)
            msg_frame.pack(fill="x", padx=5, pady=2)
            
            # Message preview
            network_emoji = "🧪" if msg['network'] == "sepolia" else "🌐"
            preview_text = f"{network_emoji} {NETWORKS[msg['network']]['name']} • Block {msg['block']} • {msg['timestamp']}"
            preview_label = ctk.CTkLabel(
                msg_frame, 
                text=preview_text,
                font=ctk.CTkFont(size=9),
                anchor="w"
            )
            preview_label.pack(fill="x", padx=10, pady=(5, 0))
            
            content_text = f"{msg['matched_address'][-8:]} • {msg['preview'][:40]}"
            if len(msg['preview']) > 40:
                content_text += "..."
            
            content_label = ctk.CTkLabel(
                msg_frame,
                text=content_text,
                font=ctk.CTkFont(size=10, weight="bold"),
                anchor="w"
            )
            content_label.pack(fill="x", padx=10, pady=(0, 5))
            
            # Make clickable
            def make_click_handler(message_data):
                return lambda event: self.show_message_details(message_data)
            
            for widget in [msg_frame, preview_label, content_label]:
                widget.bind("<Button-1>", make_click_handler(msg))
                widget.configure(cursor="hand2")
    
    def show_message_details(self, msg_data):
        """Show detailed information for selected message"""
        network_emoji = "🧪" if msg_data['network'] == "sepolia" else "🌐"
        network_name = NETWORKS[msg_data['network']]['name']
        
        details = []
        details.append(f"{network_emoji} BLOCKCHAIN MESSAGE DETAILS")
        details.append("=" * 50)
        details.append(f"🌐 Network: {network_name}")
        details.append(f"⏰ Time: {msg_data['timestamp']}")
        details.append(f"🧊 Block: {msg_data['block']}")
        details.append(f"🏷️  Hash: {msg_data['tx_hash']}")
        details.append(f"🔗 Explorer: {msg_data['explorer_url']}")
        details.append(f"📤 From: {msg_data['from']}")
        details.append(f"📥 To: {msg_data['to']}")
        details.append(f"🎯 Matched: {msg_data['matched_address']}")
        details.append(f"💰 Value: {msg_data['value']:.6f} ETH")
        details.append(f"📋 Type: {msg_data['message_type'].upper()}")
        details.append("")
        
        if msg_data['status'] == "success" and msg_data['processed_data']:
            data = msg_data['processed_data']
            
            if data["type"] == "eth_file_data":
                details.append("📄 ETH_FILE_DATA DETAILS:")
                details.append(f"• File Name: {data.get('file_name', 'N/A')}")
                details.append(f"• MIME Type: {data.get('mime_type', 'N/A')}")
                details.append(f"• Size: {data.get('size', 0)} bytes")
                details.append(f"• Content Type: {data.get('content_type', 'N/A')}")
                details.append(f"• Saved to Disk: {'✅ Yes' if data.get('saved') else '❌ No'}")
                details.append("")
                details.append("📄 CONTENT PREVIEW:")
                details.append("-" * 30)
                details.append(data.get('preview', 'No preview available'))
                
            elif data["type"] == "flexible_data":
                details.append("📊 FLEXIBLE DATA DETAILS:")
                details.append(f"• Content Type: {data.get('content_type', 'N/A')}")
                details.append(f"• Decode Method: {data.get('decode_method', 'N/A')}")
                details.append(f"• Size: {data.get('size', 0)} chars ({data.get('raw_size', 0)} bytes)")
                details.append("")
                
                if "lz_decompressed" in data:
                    details.append("🗜️  LZ-DECOMPRESSED CONTENT:")
                    details.append("-" * 30)
                    details.append(data["lz_decompressed"])
                elif "base64_decoded" in data:
                    details.append("🔓 BASE64-DECODED CONTENT:")
                    details.append("-" * 30)
                    details.append(data["base64_decoded"])
                elif "json_parsed" in data:
                    details.append("📋 JSON CONTENT:")
                    details.append("-" * 30)
                    details.append(json.dumps(data["json_parsed"], indent=2))
                else:
                    details.append("📄 RAW CONTENT:")
                    details.append("-" * 30)
                    if data.get('decode_method') != 'hex':
                        details.append(data.get("data", "No data"))
                    else:
                        details.append(f"<Binary data - {data.get('raw_size', 0)} bytes>")
        else:
            details.append(f"❌ Processing Status: {msg_data['status']}")
        
        # Update detail textbox
        self.detail_textbox.delete("1.0", "end")
        self.detail_textbox.insert("1.0", "\n".join(details))
    
    def clear_messages(self):
        """Clear all found messages"""
        def clear_all():
            self.found_messages.clear()
            self.filtered_messages.clear()
            self.update_message_list()
            self.detail_textbox.delete("1.0", "end")
            self.detail_textbox.insert("1.0", "🗑️ Messages cleared. Start a new scan to find communications.")
            self.messages_found = 0
            self.save_cache()  # Save cache after clearing
        
        self.safe_ui_update(clear_all)
        self.safe_stats_update()
    
    def safe_ui_update(self, func, *args):
        """Thread-safe UI update"""
        try:
            self.root.after(0, func, *args)
        except Exception as e:
            print(f"UI Update Error: {e}")
    
    def safe_text_insert(self, text):
        """Thread-safe text insertion"""
        def insert_text():
            try:
                self.text_output.insert("end", text)
                self.text_output.see("end")
            except:
                pass
        self.safe_ui_update(insert_text)
    
    def safe_progress_update(self, progress):
        """Thread-safe progress bar update"""
        def update_progress():
            try:
                self.progress_bar.set(progress)
            except:
                pass
        self.safe_ui_update(update_progress)
    
    def safe_status_update(self, status_text):
        """Thread-safe status label update"""
        def update_status():
            try:
                self.status_label.configure(text=status_text)
            except:
                pass
        self.safe_ui_update(update_status)
    
    def safe_stats_update(self):
        """Thread-safe statistics update"""
        def update_stats():
            try:
                stats_text = f"📊 Scanning • Addresses: {self.addresses_monitoring} • Blocks: {self.blocks_scanned} • Messages: {self.messages_found} • RPC: {self.rpc_calls_made}"
                self.stats_label.configure(text=stats_text)
            except:
                pass
        self.safe_ui_update(update_stats)
    
    def safe_message_list_update(self):
        """Thread-safe message list update"""
        def update_list():
            try:
                self.update_message_list()
            except:
                pass
        self.safe_ui_update(update_list)
        
    def historical_scan(self, addresses, start_block, end_block, network):
        """Scan multiple addresses simultaneously on specific network"""
        # Convert all addresses to lowercase for comparison
        addresses = [addr.lower() for addr in addresses]
        current = start_block
        total_blocks = end_block - start_block + 1
        transactions_found = 0
        
        network_config = NETWORKS[network]
        network_name = network_config['name']
        batch_size = network_config['batch_size']
        batch_delay = network_config['batch_delay']
        max_requests = network_config['max_requests_per_minute']
        
        # Show realistic completion estimate
        estimated_minutes = total_blocks / batch_size * (batch_delay / 60) + (total_blocks / max_requests * 60)
        
        self.safe_text_insert(f"\n🔍 Scanning {network_name} blocks {start_block} to {end_block}\n")
        self.safe_text_insert(f"📋 Monitoring {len(addresses)} addresses\n")
        self.safe_text_insert(f"📊 Total blocks: {total_blocks} | Batch size: {batch_size} | Estimated time: {estimated_minutes:.1f} min\n")

        batch_count = 0
        address_stats = {addr: 0 for addr in addresses}
        last_progress_time = time.time()
        
        # Save start time for performance measurement
        network_states[network]["scan_start_time"] = time.time()
        
        while current <= end_block:
            # Less frequent status updates for Mainnet for performance improvement
            if batch_count % (batch_size // 2) == 0:
                state = network_states[network]
                remaining_requests = max_requests - len([r for r in state["requests_this_minute"] if time.time() - r < 60])
                
                # Show progress percentage correctly
                progress_pct = ((current - start_block) / total_blocks) * 100
                self.safe_text_insert(f"⚡ {network_name} Block {current}/{end_block} ({progress_pct:.1f}%) • Budget: {remaining_requests}/{max_requests}\n")
            
            block = rpc_post("eth_getBlockByNumber", [hex(current), True], network)
            if not block:
                self.safe_text_insert(f"❌ Failed to get block {current} on {network_name}\n")
                current += 1
                time.sleep(batch_delay * 3)  # Longer pause on errors
                continue
            
            self.blocks_scanned += 1
            self.rpc_calls_made += 1
            
            # Process all transactions in this block
            for tx in block.get("transactions", []):
                to_addr = tx.get("to")
                if to_addr and to_addr.lower() in addresses:
                    transactions_found += 1
                    
                    matched_addr = to_addr.lower()
                    address_stats[matched_addr] += 1
                    
                    processed_data, status = process_transaction_data(
                        tx.get("input", ""), tx['hash'], current
                    )
                    
                    # Store message for filtering and detail view
                    self.store_message(tx, current, processed_data, status, matched_addr, network)
                    
                    # Only log important finds to avoid spam
                    if status == "success":
                        network_emoji = "🧪" if network == "sepolia" else "🌐"
                        log_entry = f"✅ {network_emoji} Block {current}: {matched_addr[-8:]} • {status}\n"
                        self.safe_text_insert(log_entry)
            
            # Update progress bar more frequently, but UI less frequently
            if time.time() - last_progress_time > 2:  # Maximum every 2 seconds
                progress = ((current - start_block + 1) / total_blocks)
                self.safe_progress_update(progress)
                
                progress_pct = progress * 100
                
                # Calculate realistic performance metrics
                elapsed_time = time.time() - network_states[network].get("scan_start_time", time.time())
                blocks_completed = current - start_block + 1
                blocks_per_min = blocks_completed / (elapsed_time / 60) if elapsed_time > 0 else 0
                
                # Estimate completion time
                remaining_blocks = end_block - current
                eta_minutes = remaining_blocks / blocks_per_min if blocks_per_min > 0 else 0
                
                self.safe_status_update(f"🔍 {network_name} {progress_pct:.1f}% • {blocks_per_min:.1f} bl/min • ETA: {eta_minutes:.1f}min")
                self.safe_stats_update()
                last_progress_time = time.time()
            
            # Batch delay - shorter for Mainnet
            if current < end_block:
                time.sleep(batch_delay)
            
            current += 1
            batch_count += 1
        
        # Summary at the end
        total_time = time.time() - network_states[network].get("scan_start_time", time.time())
        avg_blocks_per_min = total_blocks / (total_time / 60) if total_time > 0 else 0
        
        self.safe_text_insert(f"\n✅ {network_name} scan completed! Found: {transactions_found} messages\n")
        self.safe_text_insert(f"📈 Performance: {avg_blocks_per_min:.1f} blocks/min, {total_time/60:.1f} minutes total\n")
        
        # Show summary per address
        if address_stats:
            self.safe_text_insert("📊 Messages per address:\n")
            for addr, count in address_stats.items():
                if count > 0:
                    self.safe_text_insert(f"   • {addr}: {count} messages\n")
        
        self.safe_progress_update(1.0)
        
        # Save cache after scan completion
        self.save_cache()
        
        return end_block
        
    def start_scan(self):
        # Check if we should stop real-time monitoring
        if self.realtime_active:
            self.realtime_active = False
            self.scan_button.configure(text="🔍 Start New Scan")
            self.status_label.configure(text="✅ Monitoring stopped")
            self.safe_text_insert("🛑 Real-time monitoring stopped by user.\n\n")
            # Save cache when stopping
            self.save_cache()
            return
            
        addr_text = self.addr_textbox.get("1.0", "end").strip()
        date_str = self.date_entry.get().strip()
        
        # Get block numbers for each network separately
        sepolia_block_str = self.sepolia_block_entry.get().strip()
        mainnet_block_str = self.mainnet_block_entry.get().strip()
        
        # Check network selection
        self.active_networks = []
        if self.sepolia_var.get():
            self.active_networks.append("sepolia")
        if self.mainnet_var.get():
            self.active_networks.append("mainnet")
            
        if not self.active_networks:
            self.safe_text_insert("❌ Please select at least one network.\n")
            return
        
        if not addr_text:
            self.safe_text_insert("❌ Please enter at least one Ethereum address.\n")
            return
        
        # Parse multiple addresses
        addresses = self.parse_addresses(addr_text)
        
        if not addresses:
            self.safe_text_insert("❌ No valid Ethereum addresses found.\n")
            return
        
        self.addresses_monitoring = len(addresses)
        
        # Reset statistics
        self.blocks_scanned = 0
        self.messages_found = 0
        self.rpc_calls_made = 0
        
        def run_multi_network_scan():
            self.scan_button.configure(state="disabled", text="⏳ Scanning...")
            self.status_label.configure(text="🔍 Starting multi-network scan...")
            self.root.update()
            
            try:
                # Get start blocks for each network
                start_blocks = {}
                
                # Check if user specified custom block numbers for each network
                use_custom_blocks = False
                if sepolia_block_str and "sepolia" in self.active_networks:
                    try:
                        start_blocks["sepolia"] = int(sepolia_block_str)
                        use_custom_blocks = True
                        self.safe_text_insert(f"📊 Sepolia: Using custom start block {start_blocks['sepolia']}\n")
                    except ValueError:
                        self.safe_text_insert(f"❌ Invalid Sepolia block number: {sepolia_block_str}\n")
                        return
                
                if mainnet_block_str and "mainnet" in self.active_networks:
                    try:
                        start_blocks["mainnet"] = int(mainnet_block_str)
                        use_custom_blocks = True
                        self.safe_text_insert(f"📊 Mainnet: Using custom start block {start_blocks['mainnet']}\n")
                    except ValueError:
                        self.safe_text_insert(f"❌ Invalid Mainnet block number: {mainnet_block_str}\n")
                        return
                
                # If no custom blocks specified, use date
                if not use_custom_blocks and date_str:
                    try:
                        target_date = datetime.strptime(date_str, "%Y-%m-%d")
                        target_timestamp = int(target_date.timestamp())
                        
                        for network in self.active_networks:
                            start_block = find_start_block(target_timestamp, network)
                            start_blocks[network] = start_block
                            self.safe_text_insert(f"📅 {NETWORKS[network]['name']}: Found start block {start_block} for date {date_str}\n")
                    except ValueError:
                        self.safe_text_insert(f"❌ Invalid date format: {date_str}. Use YYYY-MM-DD\n")
                        return
                
                # If neither custom blocks nor date specified, use current blocks
                if not start_blocks:
                    for network in self.active_networks:
                        latest = latest_block_number(network)
                        start_blocks[network] = latest
                        self.safe_text_insert(f"🔍 {NETWORKS[network]['name']}: Starting from latest block {latest}\n")
                
                # Get end blocks for each network
                end_blocks = {}
                for network in self.active_networks:
                    if network == "mainnet" and "max_scan_blocks" in NETWORKS[network]:
                        # Limit max scan blocks for Mainnet
                        max_blocks = NETWORKS[network]["max_scan_blocks"]
                        end_blocks[network] = min(start_blocks[network] + max_blocks, latest_block_number(network))
                    else:
                        end_blocks[network] = latest_block_number(network)
                
                # Start multi-network scan
                for network in self.active_networks:
                    start_block = start_blocks[network]
                    end_block = end_blocks[network]
                    
                    if start_block > end_block:
                        self.safe_text_insert(f"⚠️  {NETWORKS[network]['name']}: Start block {start_block} is after end block {end_block}. Skipping.\n")
                        continue
                    
                    # Perform historical scan
                    last_block = self.historical_scan(addresses, start_block, end_block, network)
                    
                    # Save last seen block for real-time monitoring
                    self.last_block_seen[network] = last_block
                
                # Start real-time monitoring after all scans complete
                self.safe_text_insert("\n🔄 Starting real-time monitoring...\n")
                self.realtime_active = True
                self.scan_button.configure(text="⏹️ Stop Monitoring")
                self.status_label.configure(text="🔄 Real-time monitoring active")
                
                # Start real-time monitoring in separate thread
                threading.Thread(target=self.realtime_monitoring, daemon=True).start()
                
            except Exception as e:
                self.safe_text_insert(f"❌ Scan error: {str(e)}\n")
                self.scan_button.configure(state="normal", text="🔍 Start Scanning")
                self.status_label.configure(text="❌ Scan failed")
        
        # Start scan in separate thread
        threading.Thread(target=run_multi_network_scan, daemon=True).start()
    
    def realtime_monitoring(self):
        """Real-time monitoring of blockchain for new transactions"""
        self.countdown = EINTRV
        
        while self.realtime_active:
            try:
                # Countdown for status display
                while self.countdown > 0 and self.realtime_active:
                    self.safe_status_update(f"🔄 Real-time monitoring • Next check in {self.countdown}s")
                    time.sleep(1)
                    self.countdown -= 1
                
                if not self.realtime_active:
                    break
                
                # Reload addresses if changed
                addr_text = self.addr_textbox.get("1.0", "end").strip()
                addresses = self.parse_addresses(addr_text)
                
                if not addresses:
                    self.safe_text_insert("⚠️  No valid addresses for monitoring. Pausing...\n")
                    time.sleep(10)
                    continue
                
                # Check each active network
                for network in self.active_networks:
                    latest_block = latest_block_number(network)
                    last_seen = self.last_block_seen.get(network, latest_block)
                    
                    if latest_block > last_seen:
                        self.safe_text_insert(f"\n🔄 {NETWORKS[network]['name']}: Checking blocks {last_seen+1} to {latest_block}\n")
                        
                        # Scan new blocks
                        for block_num in range(last_seen + 1, latest_block + 1):
                            block = rpc_post("eth_getBlockByNumber", [hex(block_num), True], network)
                            if not block:
                                self.safe_text_insert(f"❌ Failed to get block {block_num} on {NETWORKS[network]['name']}\n")
                                continue
                            
                            self.blocks_scanned += 1
                            self.rpc_calls_made += 1
                            
                            # Check transactions
                            for tx in block.get("transactions", []):
                                to_addr = tx.get("to")
                                if to_addr and to_addr.lower() in addresses:
                                    matched_addr = to_addr.lower()
                                    
                                    processed_data, status = process_transaction_data(
                                        tx.get("input", ""), tx['hash'], block_num
                                    )
                                    
                                    # Store message
                                    self.store_message(tx, block_num, processed_data, status, matched_addr, network)
                                    
                                    # Log find
                                    network_emoji = "🧪" if network == "sepolia" else "🌐"
                                    log_entry = f"🆕 {network_emoji} Block {block_num}: {matched_addr[-8:]} • {status}\n"
                                    self.safe_text_insert(log_entry)
                            
                            # Short pause between blocks
                            time.sleep(0.1)
                        
                        # Update last seen block
                        self.last_block_seen[network] = latest_block
                        self.safe_stats_update()
                
                # Reset countdown
                self.countdown = EINTRV
                
            except Exception as e:
                self.safe_text_insert(f"❌ Monitoring error: {str(e)}\n")
                time.sleep(5)
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = BlockchainScannerApp()
    app.run()