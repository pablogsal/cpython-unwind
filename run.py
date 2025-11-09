import stackunwind
import operator
import os
import sys
import time


# ANSI color codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'

    # Headers
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'

    # Backgrounds
    BG_BLUE = '\033[44m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_CYAN = '\033[46m'
    BG_MAGENTA = '\033[45m'


# Color schemes for each unwinding method
METHOD_COLORS = {
    'GNU backtrace': Colors.GREEN,
    'libunwind': Colors.CYAN,
    'libdw (DWARF)': Colors.YELLOW,
    'Manual frame pointers': Colors.RED,
    'libunwind-ptrace (remote)': Colors.HEADER,
    'elfutils native (remote)': Colors.BLUE,
}


def foo(n, unwinder):
    if not n:
        return unwinder()
    for _ in range(2):
        x = operator.call(foo, n - 1, unwinder)
    return x


def print_section(title, color=Colors.BLUE):
    """Print a section header"""
    print(f"\n{color}{Colors.BOLD}{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}{Colors.RESET}")


def get_jit_status():
    """Get current JIT status"""
    jit_info = {}
    try:
        if hasattr(sys, '_jit'):
            jit_info = {
                'available': sys._jit.is_available(),
                'enabled': sys._jit.is_enabled(),
                'active': sys._jit.is_active(),
            }
    except:
        pass
    return jit_info


def print_stack(method_name, stack, show_count=10):
    """Print stack trace in a formatted way"""
    color = METHOD_COLORS.get(method_name, Colors.RESET)

    print(f"\n{color}{Colors.BOLD}[{method_name}]{Colors.RESET}")
    print(f"{color}Total frames: {len(stack)}{Colors.RESET}")
    print(f"{color}Showing first {min(show_count, len(stack))} frames:{Colors.RESET}")

    for i, frame in enumerate(stack[:show_count]):
        print(f"{color}  #{i:2d}{Colors.RESET}  {frame}")

    if len(stack) > show_count:
        print(f"{color}  ... ({len(stack) - show_count} more frames){Colors.RESET}")


def child_process():
    """Child process that builds a call stack and signals parent"""
    def level_5():
        # Tell parent we're ready and sleep
        print(f"{Colors.CYAN}[Child {os.getpid()}] Ready for sampling{Colors.RESET}", flush=True)
        time.sleep(100)  # Sleep long enough for parent to sample us

    def level_4():
        level_5()

    def level_3():
        level_4()

    def level_2():
        level_3()

    def level_1():
        level_2()

    # Build the call stack
    level_1()


if __name__ == "__main__":
    # Show JIT status at start
    jit_info = get_jit_status()
    if jit_info:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Python JIT Status:{Colors.RESET}")
        print(f"  Available: {Colors.GREEN if jit_info['available'] else Colors.RED}{jit_info['available']}{Colors.RESET}")
        print(f"  Enabled:   {Colors.GREEN if jit_info['enabled'] else Colors.RED}{jit_info['enabled']}{Colors.RESET}")
        print(f"  Active:    {Colors.GREEN if jit_info['active'] else Colors.RED}{jit_info['active']}{Colors.RESET}")

    # Get stack trace using different methods (local unwinding)
    print_section("Local Stack Unwinding Tests", Colors.BLUE)
    print(f"\n{Colors.BOLD}Testing various unwinding methods on the same deep call stack...{Colors.RESET}")

    print_stack("GNU backtrace", foo(10, stackunwind.get_stack_gnu))
    print_stack("libunwind", foo(10, stackunwind.get_stack_unwind))
    print_stack("libdw (DWARF)", foo(10, stackunwind.get_stack_dwarf))
    print_stack("Manual frame pointers", foo(10, stackunwind.get_stack_frame_pointer))

    # Test remote unwinding
    print_section("Remote Stack Unwinding Test (libunwind-ptrace)", Colors.HEADER)

    # Create a pipe for synchronization
    read_fd, write_fd = os.pipe()

    pid = os.fork()
    if pid == 0:
        # Child process
        os.close(read_fd)

        # Build call stack and signal parent
        try:
            # Signal parent we're ready (close write end)
            os.close(write_fd)
            child_process()
        except KeyboardInterrupt:
            pass
        sys.exit(0)
    else:
        # Parent process
        os.close(write_fd)

        # Wait for child to be ready (read will return when child closes pipe)
        os.read(read_fd, 1)
        os.close(read_fd)

        print(f"\n{Colors.BOLD}[Parent] Attaching to child process (PID: {pid})...{Colors.RESET}")

        # Give child a moment to get deep into the call stack
        time.sleep(0.5)

        # Sample the child's stack with both remote methods
        try:
            stack = stackunwind.get_stack_remote(pid)
            print_stack("libunwind-ptrace (remote)", stack, show_count=15)
        except Exception as e:
            print(f"{Colors.RED}[Parent] Error sampling child (libunwind-ptrace): {e}{Colors.RESET}")

        try:
            stack = stackunwind.get_stack_remote_elfutils(pid)
            print_stack("elfutils native (remote)", stack, show_count=15)
        except Exception as e:
            print(f"{Colors.RED}[Parent] Error sampling child (elfutils native): {e}{Colors.RESET}")

        # Kill the child
        print(f"\n{Colors.BOLD}[Parent] Detaching and terminating child...{Colors.RESET}")
        os.kill(pid, 9)
        os.waitpid(pid, 0)

    print_section("Tests Complete", Colors.GREEN)
    print()
