# Python Stack Unwinder

This Python C extension provides stack unwinding capabilities using three different methods:
- GNU Backtrace
- libunwind
- libdw (DWARF debug info)

## Unwinders

- `get_stack_gnu()`: Fast stack unwinding using GNU's backtrace functions
- `get_stack_unwind()`: Detailed stack unwinding using libunwind
- `get_stack_dwarf()`: Advanced stack unwinding with DWARF debug information using libdw

## Requirements

The following libraries are required to build the extension:
- libunwind
- libdw
- libelf
- Python development headers

### Installing Dependencies

On Debian/Ubuntu:
```bash
sudo apt-get install python3-dev libunwind-dev libdw-dev libelf-dev
```

On Fedora/RHEL:
```bash
sudo dnf install python3-devel libunwind-devel elfutils-devel
```

On Arch Linux:
```bash
sudo pacman -S python libunwind elfutils
```

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd python-stack-unwinder
```

2. Build the extension:
```bash
python setup.py build_ext --inplace
```

## Usage

```python
import stackunwind

# Get stack trace using GNU backtrace
stack = stackunwind.get_stack_gnu()
print("GNU Backtrace:")
for frame in stack:
    print(f"  {frame}")

# Get stack trace using libunwind
stack = stackunwind.get_stack_unwind()
print("\nlibunwind:")
for frame in stack:
    print(f"  {frame}")

# Get stack trace using libdw
stack = stackunwind.get_stack_dwarf()
print("\nlibdw:")
for frame in stack:
    print(f"  {frame}")
```
