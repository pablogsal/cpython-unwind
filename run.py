import stackunwind
import pprint

import operator


def foo(n, unwinder):
    if not n:
        return unwinder()
    for _ in range(2):
        x = operator.call(foo, n - 1, unwinder)
    return x


# Get stack trace using different methods
pprint.pprint("GNU backtrace")
pprint.pprint(foo(10, stackunwind.get_stack_gnu))
pprint.pprint("libdw")
pprint.pprint(foo(10, stackunwind.get_stack_unwind))
pprint.pprint("libuwind")
pprint.pprint(foo(10, stackunwind.get_stack_dwarf))
pprint.pprint("manual frame pointers")
pprint.pprint(foo(10, stackunwind.get_stack_frame_pointer))
