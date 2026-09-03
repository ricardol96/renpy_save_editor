#!/usr/bin/env python3
"""
Ren'Py Save Editor - Safe Bytecode Patching Version
Preserves save file integrity by patching values directly in pickle bytecode
"""

import sys
import os
import io
import ast
import zipfile
import base64
import struct
import pickle
import importlib
import tempfile
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
BINPUT = 0x71
LONG_BINPUT = 0x72
BINGET = 0x68
LONG_BINGET = 0x6A
EMPTY_TUPLE = 0x29
NEWOBJ = 0x81
MARK = 0x28
APPENDS = 0x65
MEMOIZE = 0x94


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
    if op == BINUNICODE and pos + 5 <= n:
        ln = struct.unpack('<I', data[pos + 1:pos + 5])[0]
        if pos + 5 + ln <= n:
            return (data[pos + 5:pos + 5 + ln].decode('utf-8', 'replace'), pos + 5 + ln, 'BINUNICODE')
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


def _skip_memo_put(data: bytes, pos: int) -> int:
    """Skip pickle memo-write opcodes following a value."""
    n = len(data)
    while pos < n:
        op = data[pos]
        if op == BINPUT and pos + 2 <= n:
            pos += 2
        elif op == LONG_BINPUT and pos + 5 <= n:
            pos += 5
        elif op == MEMOIZE:
            pos += 1
        else:
            break
    return pos


def _skip_memo_get(data: bytes, pos: int) -> int:
    """Skip one pickle memo-read opcode and return the following position."""
    n = len(data)
    if pos < n and data[pos] == BINGET and pos + 2 <= n:
        return pos + 2
    if pos < n and data[pos] == LONG_BINGET and pos + 5 <= n:
        return pos + 5
    return pos


def _key_value_positions(log_bytes: bytes, key: str):
    """Yield positions immediately after each exact pickle-encoded key."""
    key_b = key.encode('latin1')
    i = 0
    n = len(log_bytes)

    while i < n:
        idx = log_bytes.find(key_b, i)
        if idx == -1:
            return

        matched = False
        if idx >= 2 and log_bytes[idx - 2] == SHORT_BINSTRING:
            matched = log_bytes[idx - 1] == len(key_b)
        elif idx >= 5 and log_bytes[idx - 5] in (BINSTRING, BINUNICODE):
            ln = struct.unpack('<I', log_bytes[idx - 4:idx])[0]
            matched = ln == len(key_b)

        if matched:
            yield _skip_memo_put(log_bytes, idx + len(key_b))

        i = idx + 1


def _list_item_spans(log_bytes: bytes, value_pos: int):
    """Return scalar item spans for a Ren'Py RevertableList value.

    Ren'Py serializes RevertableList values as a NEWOBJ followed by MARK,
    the list items, APPENDS, and a state dictionary. This deliberately only
    accepts scalar list entries so edits cannot silently rewrite nested data.
    """
    pos = _skip_memo_get(log_bytes, value_pos)
    n = len(log_bytes)

    if pos + 2 > n or log_bytes[pos] != EMPTY_TUPLE or log_bytes[pos + 1] != NEWOBJ:
        raise ValueError('The value is not a supported Ren\'Py RevertableList.')
    pos += 2
    pos = _skip_memo_put(log_bytes, pos)

    if pos >= n or log_bytes[pos] != MARK:
        raise ValueError('The RevertableList item section could not be located.')
    pos += 1

    spans = []
    while pos < n and log_bytes[pos] != APPENDS:
        parsed = _parse_value_at(log_bytes, pos)
        if parsed is None:
            raise ValueError('The list contains a nested or unsupported value.')
        _, end_pos, _ = parsed
        spans.append((pos, end_pos))
        pos = _skip_memo_put(log_bytes, end_pos)

    if pos >= n or log_bytes[pos] != APPENDS:
        raise ValueError('The RevertableList terminator could not be located.')
    return spans


def patch_list_variable_in_log(log_bytes, key, new_value):
    """Patch a fixed-length scalar RevertableList in pickle bytecode."""
    if not isinstance(new_value, list):
        raise ValueError(f'{key} must be edited as a list.')
    if any(not isinstance(item, (bool, int, float, str)) for item in new_value):
        raise ValueError(f'{key} contains a nested or unsupported list item.')

    found = 0
    for value_pos in _key_value_positions(log_bytes, key):
        found += 1
        spans = _list_item_spans(log_bytes, value_pos)
        if len(spans) != len(new_value):
            raise ValueError(f'{key} must contain exactly {len(spans)} items.')

        patched = log_bytes
        for (start, end), item in reversed(list(zip(spans, new_value))):
            patched = patched[:start] + _encode_scalar(item) + patched[end:]
        return patched

    if found == 0:
        raise KeyError(f'Variable not found in pickle bytecode: {key}')
    raise KeyError(f'Variable {key!r} was found but its list encoding was not recognized.')


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
                    # Include scalar values and simple Ren'Py lists. Lists
                    # are edited element-by-element without re-pickling the
                    # rest of the save file.
                    if isinstance(v, (int, float, bool, str, _RevertableList)):
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
    source_path = os.path.abspath(src_path)
    destination_path = os.path.abspath(dst_path)
    same_file = os.path.normcase(os.path.realpath(source_path)) == os.path.normcase(os.path.realpath(destination_path))
    temporary_path = None
    output_path = destination_path

    # Opening the destination with mode 'w' would truncate the source if the
    # user chooses the same filename in Save As. Write beside it first, then
    # replace it only after the source ZIP has been fully read and closed.
    if same_file:
        fd, temporary_path = tempfile.mkstemp(
            prefix=os.path.basename(destination_path) + '.',
            suffix='.tmp',
            dir=os.path.dirname(destination_path) or None,
        )
        os.close(fd)
        output_path = temporary_path

    try:
        with zipfile.ZipFile(source_path, 'r') as zin:
            with zipfile.ZipFile(output_path, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
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

        if same_file:
            os.replace(output_path, destination_path)
            temporary_path = None
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.remove(temporary_path)


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
        self.inline_editor = None
        self.inline_editor_key = None
        
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
        
        # Edit directly in the value column. Booleans toggle on click; other
        # supported values use an in-place entry overlay.
        self.tree.bind('<Button-1>', self.on_tree_click)
        
        # Info label
        info_frame = ttk.Frame(self.root)
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(info_frame, text="💡 Click a value to edit it in place. Boolean values toggle directly; lists must keep their original length.",
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
        if self.inline_editor is not None:
            self._cancel_inline_edit()

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
            # Tkinter converts nested Python lists to Tcl list syntax when
            # passed directly as a Treeview value (for example, "True True").
            # Use Python notation so the displayed value is also valid input
            # for the list editor: "[True, True]".
            display_value = repr(value) if isinstance(value, (list, dict, set)) else str(value)
            
            # Highlight modified variables
            tags = ('modified',) if key in self.modified_variables else ()
            
            self.tree.insert('', tk.END, values=(key, display_value, value_type), tags=tags)
        
        # Configure tag colors
        self.tree.tag_configure('modified', background='yellow')
    
    def apply_filter(self):
        self.populate_tree()

    def _parse_inline_value(self, original_value, text):
        """Parse an in-place edit while preserving the original value type."""
        if isinstance(original_value, _RevertableList):
            new_value = ast.literal_eval(text)
            if not isinstance(new_value, list):
                raise ValueError('The new value must be a list.')
            if len(new_value) != len(original_value):
                raise ValueError(
                    f'This list must contain exactly {len(original_value)} items.'
                )
            if any(not isinstance(item, (bool, int, float, str))
                   for item in new_value):
                raise ValueError('Nested lists and dictionaries are not supported yet.')
            return new_value
        if isinstance(original_value, int):
            return int(text)
        if isinstance(original_value, float):
            return float(text)
        if isinstance(original_value, str):
            return text
        raise ValueError(f"Unsupported type: {type(original_value)}")

    def _store_modified_value(self, key, new_value):
        """Store a value and remove the highlight if it matches the original."""
        if new_value == self.variables[key]:
            self.modified_variables.pop(key, None)
        else:
            self.modified_variables[key] = new_value
        self.populate_tree()
        self.status_var.set(f"Modified: {key} = {new_value}")

    def _cancel_inline_edit(self):
        if self.inline_editor is not None:
            self.inline_editor.destroy()
        self.inline_editor = None
        self.inline_editor_key = None

    def _commit_inline_edit(self, event=None):
        if self.inline_editor is None:
            return 'break'

        editor = self.inline_editor
        key = self.inline_editor_key
        try:
            new_value = self._parse_inline_value(self.variables[key], editor.get())
        except (ValueError, SyntaxError) as error:
            messagebox.showerror(
                "Invalid Value",
                f"Could not parse value:\n{error}",
                parent=self.root,
            )
            editor.focus_set()
            return 'break'

        self._cancel_inline_edit()
        self._store_modified_value(key, new_value)
        return 'break'

    def _start_inline_edit(self, item, key):
        self._cancel_inline_edit()
        bbox = self.tree.bbox(item, '#2')
        if not bbox:
            return

        current_value = self.modified_variables.get(key, self.variables[key])
        display_value = repr(current_value) if isinstance(current_value, list) else str(current_value)
        x, y, width, height = bbox
        self.inline_editor = ttk.Entry(self.tree)
        self.inline_editor.insert(0, display_value)
        self.inline_editor.select_range(0, tk.END)
        self.inline_editor.place(x=x, y=y, width=width, height=height)
        self.inline_editor_key = key
        self.inline_editor.bind('<Return>', self._commit_inline_edit)
        self.inline_editor.bind('<FocusOut>', self._commit_inline_edit)
        self.inline_editor.bind('<Escape>', lambda event: self._cancel_inline_edit())
        self.inline_editor.focus_set()

    def on_tree_click(self, event):
        row = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        if not row or column != '#2':
            return

        self.tree.selection_set(row)
        key = self.tree.item(row, 'values')[0]
        original_value = self.variables[key]
        current_value = self.modified_variables.get(key, original_value)
        if isinstance(original_value, bool):
            self._store_modified_value(key, not bool(current_value))
        else:
            self._start_inline_edit(row, key)
        return 'break'
    
    def save_file(self):
        if not self.current_file:
            messagebox.showinfo("Info", "No save file is loaded.")
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
            modified_count = len(self.modified_variables)
            for key, value in self.modified_variables.items():
                if isinstance(self.variables[key], _RevertableList):
                    modified_log = patch_list_variable_in_log(modified_log, key, value)
                else:
                    modified_log = patch_variable_in_log(modified_log, key, value)
            
            # Save to new file
            save_modified_save(self.current_file, filename, modified_log)

            # Continue editing the file just written. Reloading preserves
            # Ren'Py container types and prevents later saves from rebuilding
            # from the older source file or reverting the chosen filename.
            new_variables, new_log = load_save_variables(filename)
            if not new_variables or new_log is None:
                raise ValueError("The saved file could not be reloaded for continued editing.")
            self.current_file = filename
            self.original_log = new_log
            self.variables = new_variables
            self.modified_variables = {}
            self.populate_tree()
            
            if modified_count:
                result = f"Modified {modified_count} variable(s)."
            else:
                result = "No variables were changed; the save was copied unchanged."
            messagebox.showinfo("Success",
                f"Save file created successfully!\n\n"
                f"{result}\n"
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
