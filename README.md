# Ren'Py Save Editor

A safe and user-friendly GUI tool for editing Ren'Py game save files. Uses bytecode patching to preserve save file integrity while allowing you to modify variable values.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-blue.svg)

## Features

✅ **Safe Editing** - Patches values directly in pickle bytecode, preserving file structure  
✅ **Simple GUI** - Easy-to-use interface with variable filtering  
✅ **Type Support** - Edit integers, floats, booleans, and strings  
✅ **Signature Handling** - Regenerates save file signatures when possible  
✅ **Lightweight** - Only one optional dependency (ecdsa)  

## Quick Start

### Option 1: Use the Executable (Easiest)

1. Find `RenpySaveEditor.exe` in `executable` folder
2. Double-click `RenpySaveEditor.exe` to launch
3. Click "Open Save" and select your `.save` file
4. Double-click any value to edit it
5. Click "Save As" to create your modified save file

**No Python installation required!**

### Option 2: Run from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/renpy_save_editor.git
cd renpy_save_editor

# Install dependencies
pip install -r requirements.txt

# Run the editor
python renpy_save_editor.py
```

## How It Works

### High-Level Overview

1. **Save File Format**: Ren'Py `.save` files are ZIP archives containing a `log` file (pickled Python data) and optional `signatures`

2. **Safe Unpickling**: The editor uses a hardened unpickler that:
   - Maps Ren'Py types (RevertableList, RevertableDict, etc.) to safe Python containers
   - Replaces unknown classes with benign proxies
   - Prevents arbitrary code execution

3. **Bytecode Patching**: When you edit a variable:
   - The editor finds the variable name in the pickle bytecode
   - Identifies the value bytes that follow
   - Replaces only those specific bytes with the new encoded value
   - Preserves all other data and structure intact

4. **Signature Regeneration**: If `ecdsa` is installed and Ren'Py signing keys are found:
   - Valid signatures are regenerated for the modified save
   - Otherwise, empty signatures are written (works fine, just may show a warning in-game)

### Technical Details

**String Encodings Supported**: SHORT_BINSTRING, BINSTRING, BINUNICODE  
**Value Types Editable**: int, float, bool, str  
**Python Version**: 3.7+  

## Usage Guide

### Opening a Save File

1. Launch the editor
2. Click **"Open Save"** or use **File → Open Save File**
3. Navigate to your Ren'Py game's save folder:
   - **Windows**: `%APPDATA%\RenPy\[GameName]\`
   - **macOS**: `~/Library/RenPy/[GameName]/`
   - **Linux**: `~/.renpy/[GameName]/`
4. Select a `.save` file

### Editing Variables

1. **Browse**: Scroll through the variable list
2. **Filter**: Use the filter box to search (e.g., type "money" to find money-related variables)
3. **Edit**: Double-click any value to open the edit dialog
4. **Type the new value**:
   - **Integers**: `100`, `-50`
   - **Floats**: `1.5`, `99.99`
   - **Booleans**: `true`, `false`, `1`, `0`
   - **Strings**: Any text
5. Click **Save** in the dialog

Modified variables are highlighted in yellow.

### Saving Your Changes

1. Click **"Save As"** when you're done editing
2. Choose where to save the modified file
3. **Important**: Either:
   - Save with a new name (recommended for testing)
   - Backup the original save first, then overwrite it

### Loading Modified Saves in Game

1. Copy the modified `.save` file to your game's save folder
2. Launch the game
3. Load the save from the load menu
4. Your changes should be applied!

## Building the Executable

If you want to build the executable yourself:

### Windows

```bash
# Run the build script
build_exe.bat
```

The executable will be created in the `executable` folder.

### Manual Build (All Platforms)

```bash
# Install PyInstaller
pip install pyinstaller

# Build the executable
pyinstaller --onefile --windowed --name "RenpySaveEditor" --distpath executable renpy_save_editor.py

# Clean up (optional)
rm -rf build
rm RenpySaveEditor.spec
```

## Dependencies

### Runtime
- **Python 3.7+** (with tkinter)
- **ecdsa** (optional) - For regenerating save file signatures

### Build
- **pyinstaller** (only needed to create executable)

Install all dependencies:
```bash
pip install -r requirements.txt
```

## Limitations

- ✅ **Editable**: Simple scalar values (int, float, bool, str)
- ❌ **Not Editable**: Complex objects, lists, dictionaries, nested structures
- ⚠️ **Warning**: Editing game state variables may cause unexpected behavior or break game logic

**Always backup your saves before editing!**

## Troubleshooting

### "No editable variables found"
- The save file might be from a very old Ren'Py version
- Try a different save file from the same game

### "Variable not found"
- The variable might use an unsupported encoding
- Try editing a different variable

### Game won't load the edited save
- Make sure you're editing `store.variablename` values
- Don't modify variables that start with `_` (internal Ren'Py variables)
- Verify the save file is in the correct location

### Signature warnings in-game
- Install `ecdsa`: `pip install ecdsa`
- Or ignore the warning (it's usually harmless)

## Project Structure

```
renpy_save_editor/
├── renpy_save_editor.py    # Main application
├── requirements.txt         # Python dependencies
├── build_exe.bat           # Windows build script
├── README.md               # This file
└── executable/             # Built executables (after building)
    └── RenpySaveEditor.exe
```

## Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests

## License

MIT License - Feel free to use, modify, and distribute.

## Disclaimer

This tool modifies game save files. While it uses safe patching methods:
- **Always backup your saves** before editing
- Use at your own risk
- The authors are not responsible for corrupted saves or game issues

## Credits

Created for editing Ren'Py visual novel save files.  
Uses Python's pickle bytecode patching for safe, targeted modifications.

---

**Enjoy your edited saves! 🎮✨**
