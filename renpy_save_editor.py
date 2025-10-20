#!/usr/bin/env python3
"""
Ren'Py Save Editor - Safe Bytecode Patching Version
Preserves save file integrity by patching values directly in pickle bytecode
"""

import sys
import os
import io
import zipfile
import base64
import struct
import pickle
import importlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from io import BytesIO


# ============================================================================
# Signature handling for Ren'Py compatibility
# ============================================================================

def _find_security_keys():
    """Best-effort search for Ren'Py signing keys file."""
    candidates = [
        os.path.expanduser('~/.renpy/tokens/security_keys.txt'),
        os.path.expanduser('~/Library/RenPy/tokens/security_keys.txt'),
        os.path.join(os.environ.get('APPDATA', ''), 'RenPy', 'tokens', 'security_keys.txt'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'RenPy', 'tokens', 'security_keys.txt'),
        os.path.expanduser('~/.local/share/renpy/tokens/security_keys.txt'),
        os.path.expanduser('~/.config/renpy/tokens/security_keys.txt'),
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return p
    return None


def _load_signing_keys(keys_path):
    """Parse signing keys from security_keys.txt. Returns list of DER bytes."""
    keys = []
    try:
        with open(keys_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if parts and parts[0] == 'signing-key' and len(parts) >= 2:
                    try:
                        der = base64.b64decode(parts[1])
                        keys.append(der)
                    except Exception:
                        pass
    except Exception:
        pass
    return keys


def _signatures_for_log(log_bytes):
    """Create Ren'Py-compatible signatures string for given log, or b'' if unavailable."""
    keys_path = _find_security_keys()
    if not keys_path:
        return b''
    keys = _load_signing_keys(keys_path)
    if not keys:
        return b''
    try:
        import ecdsa
    except Exception:
        return b''

    out_lines = []
    for der in keys:
        try:
            sk = ecdsa.SigningKey.from_der(der)
            vk = getattr(sk, 'verifying_key', None)
            if vk is None:
                continue
            sig = sk.sign(log_bytes)
            vk_der = vk.to_der()
            line = 'signature ' + base64.b64encode(vk_der).decode('ascii') + ' ' + base64.b64encode(sig).decode('ascii')
            out_lines.append(line)
        except Exception:
            continue
    if not out_lines:
        return b''
    return ('\n'.join(out_lines) + '\n').encode('utf-8')


# ============================================================================
# Pickle bytecode constants
# ============================================================================

BINUNICODE = 0x58
BININT1 = 0x4B
BININT2 = 0x4D
BININT = 0x4A
BINFLOAT = 0x47
NEWTRUE = 0x88
NEWFALSE = 0x89
LONG1 = 0x8A
LONG4 = 0x8B
BINSTRING = 0x54
SHORT_BINSTRING = 0x55


# ============================================================================
# Safe unpickler for reading save data
# ============================================================================

class _Proxy:
    def __init__(self, *a, **k):
        self._state = None
        self._list = []
    def __setstate__(self, state):
        setattr(self, '_state', state)
    def append(self, item):
        self._list.append(item)
    def extend(self, items):
        try:
            self._list.extend(items)
        except Exception:
            for it in items:
                self._list.append(it)
    def __iter__(self):
        return iter(self._list)
    def __len__(self):
        return len(self._list)


class _RevertableList(list):
    def __setstate__(self, state):
        try:
            if isinstance(state, (list, tuple)) and state:
                first = state[0]
                if isinstance(first, (list, tuple)):
                    self.extend(first)
        except Exception:
            pass


class _RevertableDict(dict):
    def __setstate__(self, state):
        try:
            if isinstance(state, dict):
                self.update(state)
            elif isinstance(state, (list, tuple)) and state and isinstance(state[0], dict):
                self.update(state[0])
        except Exception:
            pass


class _RevertableSet(set):
    def __setstate__(self, state):
        try:
            if isinstance(state, (list, tuple)) and state and isinstance(state[0], (list, tuple, set)):
                self.update(state[0])
        except Exception:
            pass


class _SimpleDefaultDict(dict):
    def __init__(self, *a, **k):
        self.default_factory = None
    def __setstate__(self, state):
        try:
            if isinstance(state, tuple) and len(state) == 2:
                self.default_factory = state[0]
                st = state[1]
                if isinstance(st, dict):
                    self.update(st)
        except Exception:
            pass


class _SimpleOrderedDict(dict):
    def __setstate__(self, state):
        try:
            if isinstance(state, dict):
                self.update(state)
            elif isinstance(state, list):
                for k, v in state:
                    self[k] = v
        except Exception:
            pass


_SPECIAL = {
    ('renpy.revertable', 'RevertableList'): _RevertableList,
    ('renpy.revertable', 'RevertableDict'): _RevertableDict,
    ('renpy.revertable', 'RevertableSet'): _RevertableSet,
    ('collections', 'defaultdict'): _SimpleDefaultDict,
    ('collections', 'OrderedDict'): _SimpleOrderedDict,
}


class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) in _SPECIAL:
            return _SPECIAL[(module, name)]
        if name in ('RevertableList', 'RevertableDict', 'RevertableSet'):
            mapping = {
                'RevertableList': _RevertableList,
                'RevertableDict': _RevertableDict,
                'RevertableSet': _RevertableSet,
            }
            return mapping[name]
        if module == 'builtins':
            return getattr(importlib.import_module(module), name)
        return type(name, (_Proxy,), {})


# ============================================================================
# Value parsing and encoding
# ============================================================================

def _parse_value_at(data: bytes, pos: int):
    """Parse a scalar value at the given position. Returns (value, end_pos, encoding_type) or None."""
    n = len(data)
    if pos >= n:
        return None
    op = data[pos]
    
    if op == BININT1 and pos + 2 <= n:
        return (data[pos + 1], pos + 2, 'BININT1')
    if op == BININT2 and pos + 3 <= n:
        return (struct.unpack('<H', data[pos + 1:pos + 3])[0], pos + 3, 'BININT2')
    if op == BININT and pos + 5 <= n:
        return (struct.unpack('<i', data[pos + 1:pos + 5])[0], pos + 5, 'BININT')
    if op == BINFLOAT and pos + 9 <= n:
        return (struct.unpack('>d', data[pos + 1:pos + 9])[0], pos + 9, 'BINFLOAT')
    if op == NEWTRUE:
        return (True, pos + 1, 'BOOL')
    if op == NEWFALSE:
        return (False, pos + 1, 'BOOL')
    if op == ord('I'):
        end = data.find(b'\n', pos)
        if end != -1:
            txt = data[pos + 1:end]
            try:
                return (int(txt.decode('ascii')), end + 1, 'INT')
            except Exception:
                return None
    if op == ord('F'):
        end = data.find(b'\n', pos)
        if end != -1:
            txt = data[pos + 1:end]
            try:
                return (float(txt.decode('ascii')), end + 1, 'FLOAT')
            except Exception:
                return None
    if op == LONG1 and pos + 2 <= n:
        ln = data[pos + 1]
        if pos + 2 + ln <= n:
            mag = int.from_bytes(data[pos + 2:pos + 2 + ln], 'little', signed=True)
            return (mag, pos + 2 + ln, 'LONG1')
    if op == LONG4 and pos + 5 <= n:
        ln = struct.unpack('<I', data[pos + 1:pos + 5])[0]
        if pos + 5 + ln <= n:
            mag = int.from_bytes(data[pos + 5:pos + 5 + ln], 'little', signed=True)
            return (mag, pos + 5 + ln, 'LONG4')
    if op == BINSTRING and pos + 5 <= n:
        ln = struct.unpack('<I', data[pos + 1:pos + 5])[0]
        if pos + 5 + ln <= n:
            return (data[pos + 5:pos + 5 + ln].decode('latin1', 'replace'), pos + 5 + ln, 'BINSTRING')
    if op == SHORT_BINSTRING and pos + 2 <= n:
        ln = data[pos + 1]
        if pos + 2 + ln <= n:
            return (data[pos + 2:pos + 2 + ln].decode('latin1', 'replace'), pos + 2 + ln, 'SHORT_BINSTRING')
    if op == ord('S'):
        end = data.find(b'\n', pos)
        if end != -1:
            txt = data[pos + 1:end]
            try:
                s = txt.decode('ascii')
                if s.startswith("'") and s.endswith("'"):
                    return (s[1:-1].replace("\\'", "'"), end + 1, 'STRING')
            except Exception:
                return None
    
    return None


def _encode_scalar(value):
    """Encode a scalar value into pickle bytecode."""
    if isinstance(value, bool):
        return b"\x88" if value else b"\x89"
    if isinstance(value, int):
        if 0 <= value <= 0xFF:
            return b"\x4b" + bytes([value])
        if 0 <= value <= 0xFFFF:
            return b"\x4d" + struct.pack('<H', value)
        if -0x80000000 <= value <= 0x7FFFFFFF:
            return b"\x4a" + struct.pack('<i', int(value))
        # LONG4 for very large ints
        mag = int(value).to_bytes((int(value).bit_length() + 8) // 8 or 1, 'little', signed=True)
        return b"\x8b" + struct.pack('<I', len(mag)) + mag
    if isinstance(value, float):
        return b"\x47" + struct.pack('>d', value)
    if isinstance(value, str):
        # Use BINSTRING for strings
        encoded = value.encode('latin1', 'replace')
        if len(encoded) <= 255:
            return b"\x55" + bytes([len(encoded)]) + encoded
        else:
            return b"\x54" + struct.pack('<I', len(encoded)) + encoded
    raise ValueError(f'Unsupported type for encoding: {type(value)}')


# ============================================================================
# Save file operations
# ============================================================================

def load_save_variables(save_path):
    """Load all editable variables from a save file. Returns dict of {key: value}."""
    with zipfile.ZipFile(save_path, 'r') as zf:
        log = zf.read('log')
    
    # Try to load using SafeUnpickler
    try:
        roots, _ = SafeUnpickler(io.BytesIO(log)).load()
        if isinstance(roots, dict):
            # Filter to editable types
            variables = {}
            for k, v in roots.items():
                if isinstance(k, str) and k.startswith('store.'):
                    # Only include simple editable types
                    if isinstance(v, (int, float, bool, str)):
                        variables[k] = v
            return variables, log
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load save file:\n{str(e)}")
        return {}, None
    
    return {}, None


def patch_variable_in_log(log_bytes, key, new_value):
    """Patch a variable value directly in the pickle bytecode."""
    key_b = key.encode('latin1')  # Use latin1 to match pickle string encoding
    i = 0
    n = len(log_bytes)
    matches_found = 0
    
    while i < n:
        idx = log_bytes.find(key_b, i)
        if idx == -1:
            break
        
        # Check for different string encodings
        matched = False
        pos = idx + len(key_b)
        
        # Check SHORT_BINSTRING (0x55 'U' + 1 byte length)
        if idx >= 2 and log_bytes[idx - 2] == 0x55:
            ln = log_bytes[idx - 1]
            if ln == len(key_b):
                matched = True
                matches_found += 1
        
        # Check BINSTRING (0x54 'T' + 4 byte length)
        elif idx >= 5 and log_bytes[idx - 5] == 0x54:
            ln = struct.unpack('<I', log_bytes[idx - 4:idx])[0]
            if ln == len(key_b):
                matched = True
                matches_found += 1
        
        # Check BINUNICODE (0x58 'X' + 4 byte length)
        elif idx >= 5 and log_bytes[idx - 5] == 0x58:
            ln = struct.unpack('<I', log_bytes[idx - 4:idx])[0]
            if ln == len(key_b):
                matched = True
                matches_found += 1
        
        if matched:
            # Skip optional memo opcodes
            # BINPUT 'q' (0x71)
            while pos < n and log_bytes[pos] == 0x71:
                pos += 2
            # LONG_BINPUT 'r' (0x72)
            while pos < n and log_bytes[pos] == 0x72:
                pos += 5
            
            # The value should be right after the key (and optional memo ops)
            pv = _parse_value_at(log_bytes, pos)
            if pv is not None:
                cur, vend, enc = pv
                # Found the value - replace it
                try:
                    rep = _encode_scalar(new_value)
                    return log_bytes[:pos] + rep + log_bytes[vend:]
                except ValueError as e:
                    raise KeyError(f"Cannot encode value for {key}: {e}")
        
        i = idx + 1
    
    if matches_found == 0:
        raise KeyError(f"Variable not found in pickle bytecode: {key}")
    else:
        raise KeyError(f"Variable '{key}' found {matches_found} time(s) but value encoding not recognized")


def save_modified_save(src_path, dst_path, modified_log):
    """Save modified log back to a new save file, regenerating signatures."""
    with zipfile.ZipFile(src_path, 'r') as zin:
        with zipfile.ZipFile(dst_path, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == 'log':
                    # Write modified log
                    zi = zipfile.ZipInfo(item.filename)
                    zi.date_time = item.date_time
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.external_attr = item.external_attr
                    zout.writestr(zi, modified_log)
                elif item.filename == 'signatures':
                    # Regenerate signatures for the new log
                    sig = _signatures_for_log(modified_log)
                    zi = zipfile.ZipInfo(item.filename)
                    zi.date_time = item.date_time
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.external_attr = item.external_attr
                    zout.writestr(zi, sig)
                else:
                    zout.writestr(item, zin.read(item.filename))


# ============================================================================
# GUI
# ============================================================================

class RenpySaveEditorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Ren'Py Save Editor")
        self.root.geometry("900x600")
        
        self.current_file = None
        self.original_log = None
        self.variables = {}
        self.modified_variables = {}
        
        self.create_widgets()
    
    def create_widgets(self):
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Save File...", command=self.load_file)
        file_menu.add_command(label="Save As...", command=self.save_file, state='disabled')
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Toolbar
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        ttk.Button(toolbar, text="Open Save", command=self.load_file).pack(side=tk.LEFT, padx=2)
        self.save_btn = ttk.Button(toolbar, text="Save As", command=self.save_file, state='disabled')
        self.save_btn.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(toolbar, text="Filter:").pack(side=tk.LEFT, padx=(20, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace('w', lambda *args: self.apply_filter())
        filter_entry = ttk.Entry(toolbar, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=2)
        
        # Status bar
        self.status_var = tk.StringVar(value="No file loaded")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Main content area with scrollbar
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create Treeview
        columns = ('variable', 'value', 'type')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=20)
        
        self.tree.heading('variable', text='Variable Name')
        self.tree.heading('value', text='Value')
        self.tree.heading('type', text='Type')
        
        self.tree.column('variable', width=400)
        self.tree.column('value', width=200)
        self.tree.column('type', width=100)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click to edit
        self.tree.bind('<Double-Button-1>', self.on_double_click)
        
        # Info label
        info_frame = ttk.Frame(self.root)
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(info_frame, text="💡 Double-click a value to edit it. Only simple types (int, float, bool, str) can be edited.", 
                 foreground='blue').pack(side=tk.LEFT)
    
    def load_file(self):
        filename = filedialog.askopenfilename(
            title="Select Ren'Py Save File",
            filetypes=[("Save files", "*.save"), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            self.variables, self.original_log = load_save_variables(filename)
            if not self.variables:
                messagebox.showwarning("Warning", "No editable variables found in save file.")
                return
            
            self.current_file = filename
            self.modified_variables = {}
            self.populate_tree()
            self.status_var.set(f"Loaded: {os.path.basename(filename)} ({len(self.variables)} variables)")
            self.save_btn['state'] = 'normal'
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load save file:\n{str(e)}")
    
    def populate_tree(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add variables
        filter_text = self.filter_var.get().lower()
        for key in sorted(self.variables.keys()):
            if filter_text and filter_text not in key.lower():
                continue
            
            value = self.modified_variables.get(key, self.variables[key])
            value_type = type(value).__name__
            
            # Highlight modified variables
            tags = ('modified',) if key in self.modified_variables else ()
            
            self.tree.insert('', tk.END, values=(key, value, value_type), tags=tags)
        
        # Configure tag colors
        self.tree.tag_configure('modified', background='yellow')
    
    def apply_filter(self):
        self.populate_tree()
    
    def on_double_click(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.tree.item(item, 'values')
        if not values:
            return
        
        key, current_value, value_type = values
        
        # Create edit dialog
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Edit {key}")
        dialog.geometry("500x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text=f"Variable: {key}").pack(pady=5)
        ttk.Label(dialog, text=f"Type: {value_type}").pack(pady=5)
        
        ttk.Label(dialog, text="New Value:").pack(pady=5)
        value_var = tk.StringVar(value=str(current_value))
        entry = ttk.Entry(dialog, textvariable=value_var, width=50)
        entry.pack(pady=5)
        entry.focus()
        entry.select_range(0, tk.END)
        
        def save_edit():
            try:
                new_value_str = value_var.get()
                original_value = self.variables[key]
                
                # Parse based on original type
                if isinstance(original_value, bool):
                    new_value = new_value_str.lower() in ('true', '1', 'yes')
                elif isinstance(original_value, int):
                    new_value = int(new_value_str)
                elif isinstance(original_value, float):
                    new_value = float(new_value_str)
                elif isinstance(original_value, str):
                    new_value = new_value_str
                else:
                    raise ValueError(f"Unsupported type: {type(original_value)}")
                
                self.modified_variables[key] = new_value
                self.populate_tree()
                dialog.destroy()
                self.status_var.set(f"Modified: {key} = {new_value}")
                
            except ValueError as e:
                messagebox.showerror("Invalid Value", f"Could not parse value:\n{str(e)}", parent=dialog)
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Save", command=save_edit).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key
        entry.bind('<Return>', lambda e: save_edit())
    
    def save_file(self):
        if not self.current_file or not self.modified_variables:
            messagebox.showinfo("Info", "No modifications to save.")
            return
        
        # Get output filename
        default_name = os.path.basename(self.current_file)
        filename = filedialog.asksaveasfilename(
            title="Save Modified Save File",
            initialfile=default_name,
            defaultextension=".save",
            filetypes=[("Save files", "*.save"), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            # Apply all modifications to the log
            modified_log = self.original_log
            for key, value in self.modified_variables.items():
                modified_log = patch_variable_in_log(modified_log, key, value)
            
            # Save to new file
            save_modified_save(self.current_file, filename, modified_log)
            
            messagebox.showinfo("Success", 
                f"Save file created successfully!\n\n"
                f"Modified {len(self.modified_variables)} variable(s).\n"
                f"Saved to: {os.path.basename(filename)}")
            self.status_var.set(f"Saved: {os.path.basename(filename)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file:\n{str(e)}")


def main():
    root = tk.Tk()
    app = RenpySaveEditorGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()