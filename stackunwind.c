#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <execinfo.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>

// Get the current frame pointer
#if defined(__x86_64__)
#define GET_FRAME_POINTER(fp) asm volatile("movq %%rbp, %0" : "=r"(fp))
#elif defined(__i386__)
#define GET_FRAME_POINTER(fp) asm volatile("movl %%ebp, %0" : "=r"(fp))
#else
#error "Architecture not supported"
#endif

void print_stack_frames(void) {
  printf("Stack trace (most recent call first):\n");
}

// Manual frame pointer unwinding implementation
static PyObject *get_stack_frame_pointer(PyObject *self, PyObject *args) {
  void *addresses[100];
  int frame_count = 0;
  PyObject *result;

  // Get current frame pointer
  uintptr_t *frame_pointer;
  GET_FRAME_POINTER(frame_pointer);

  // Walk the frame chain
  while (frame_pointer) {
    // The frame pointer points to the saved previous frame pointer
    // The return address is stored right after it
    uintptr_t return_addr = *(frame_pointer + 1);

    addresses[frame_count++] = (void *)return_addr;

    // Move to the previous frame
    // frame_pointer[0] contains the saved previous frame pointer
    frame_pointer = (uintptr_t *)*frame_pointer;

    frame_count++;

    // Basic sanity check for frame pointer
    if ((uintptr_t)frame_pointer < 0x1000) {
      break;
    }
  }

  // Create Python list of frame information
  result = PyList_New(frame_count);
  for (int i = 0; i < frame_count; i++) {
    PyList_SET_ITEM(result, i, PyUnicode_FromFormat("%p", addresses[i]));
  }
  return result;
}

// GNU Backtrace implementation
static PyObject *get_stack_gnu(PyObject *self, PyObject *args) {
  void *buffer[100];
  char **strings;
  int nptrs;
  PyObject *result;

  nptrs = backtrace(buffer, 100);
  strings = backtrace_symbols(buffer, nptrs);

  if (strings == NULL) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to get backtrace symbols");
    return NULL;
  }

  result = PyList_New(nptrs);
  for (int i = 0; i < nptrs; i++) {
    PyList_SET_ITEM(result, i, PyUnicode_FromString(strings[i]));
  }

  free(strings);
  return result;
}

// libunwind implementation
static PyObject *get_stack_unwind(PyObject *self, PyObject *args) {
  unw_cursor_t cursor;
  unw_context_t context;
  PyObject *result;
  char name[256];
  unw_word_t offset;

  unw_getcontext(&context);
  unw_init_local(&cursor, &context);

  result = PyList_New(0);

  while (unw_step(&cursor) > 0) {
    if (unw_get_proc_name(&cursor, name, sizeof(name), &offset) == 0) {
      PyObject *frame_info = PyUnicode_FromFormat("%s+0x%lx", name, offset);
      PyList_Append(result, frame_info);
      Py_DECREF(frame_info);
    } else {
      PyObject *unknown = PyUnicode_FromString("<unknown>");
      PyList_Append(result, unknown);
      Py_DECREF(unknown);
    }
  }

  return result;
}

// libdw implementation
static char *get_function_name(Dwfl_Module *module, Dwarf_Addr addr) {
  GElf_Sym sym;
  GElf_Off off;
  const char *name = dwfl_module_addrname(module, addr);
  return name ? strdup(name) : strdup("<unknown>");
}

static PyObject *get_stack_dwarf(PyObject *self, PyObject *args) {
  static char *debuginfo_path = NULL;
  static Dwfl_Callbacks callbacks = {
      .find_elf = dwfl_linux_proc_find_elf,
      .find_debuginfo = dwfl_standard_find_debuginfo,
      .debuginfo_path = &debuginfo_path,
  };

  Dwfl *dwfl = dwfl_begin(&callbacks);
  if (dwfl == NULL) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to initialize dwfl");
    return NULL;
  }

  if (dwfl_linux_proc_report(dwfl, getpid()) != 0) {
    dwfl_end(dwfl);
    PyErr_SetString(PyExc_RuntimeError, "Failed to load process information");
    return NULL;
  }

  if (dwfl_report_end(dwfl, NULL, NULL) != 0) {
    dwfl_end(dwfl);
    PyErr_SetString(PyExc_RuntimeError, "Failed to finish reporting");
    return NULL;
  }

  unw_cursor_t cursor;
  unw_context_t context;
  PyObject *result = PyList_New(0);

  unw_getcontext(&context);
  unw_init_local(&cursor, &context);

  while (unw_step(&cursor) > 0) {
    unw_word_t ip;
    unw_get_reg(&cursor, UNW_REG_IP, &ip);

    Dwfl_Module *module = dwfl_addrmodule(dwfl, ip);
    if (module) {
      char *name = get_function_name(module, ip);
      PyObject *frame_info = PyUnicode_FromString(name);
      PyList_Append(result, frame_info);
      Py_DECREF(frame_info);
      free(name);
    } else {
      PyObject *unknown = PyUnicode_FromString("<unknown>");
      PyList_Append(result, unknown);
      Py_DECREF(unknown);
    }
  }

  dwfl_end(dwfl);
  return result;
}

// libunwind remote implementation
static PyObject *get_stack_remote(PyObject *self, PyObject *args) {
  pid_t pid;
  int status;
  unw_addr_space_t addr_space = NULL;
  struct UPT_info* upt_info = NULL;
  unw_cursor_t cursor;
  int ret;
  PyObject *result = NULL;

  if (!PyArg_ParseTuple(args, "i", &pid)) {
    return NULL;
  }

  // Attach to the process
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
    PyErr_SetFromErrno(PyExc_OSError);
    return NULL;
  }

  // Wait for the process to stop
  if (waitpid(pid, &status, 0) == -1) {
    PyErr_SetFromErrno(PyExc_OSError);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return NULL;
  }

  if (!WIFSTOPPED(status)) {
    PyErr_SetString(PyExc_RuntimeError, "Process did not stop");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return NULL;
  }

  // Create address space for remote unwinding
  addr_space = unw_create_addr_space(&_UPT_accessors, 0);
  if (!addr_space) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to create address space");
    goto cleanup;
  }

  upt_info = (struct UPT_info*) _UPT_create(pid);
  if (!upt_info) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to create UPT info");
    goto cleanup;
  }

  ret = unw_init_remote(&cursor, addr_space, upt_info);
  if (ret < 0) {
    PyErr_Format(PyExc_RuntimeError, "unw_init_remote failed: %d", ret);
    goto cleanup;
  }

  result = PyList_New(0);

  do {
    unw_word_t pc, sp;
    unw_word_t off = 0;
    char buf[512];

    ret = unw_get_reg(&cursor, UNW_REG_IP, &pc);
    if (ret < 0) {
      break;
    }
    ret = unw_get_reg(&cursor, UNW_REG_SP, &sp);
    if (ret < 0) {
      break;
    }

    buf[0] = '\0';
    if (unw_get_proc_name_by_ip(addr_space, pc, buf, sizeof(buf), &off, upt_info) >= 0
            && buf[0] != '\0') {
      PyObject *frame_info = PyUnicode_FromFormat("0x%016lx in %s + 0x%lx (sp=0x%016lx)",
                                                   pc, buf, off, sp);
      PyList_Append(result, frame_info);
      Py_DECREF(frame_info);
    } else {
      PyObject *frame_info = PyUnicode_FromFormat("0x%016lx in <unknown> (sp=0x%016lx)",
                                                   pc, sp);
      PyList_Append(result, frame_info);
      Py_DECREF(frame_info);
    }

    ret = unw_step(&cursor);
  } while (ret > 0);

cleanup:
  if (upt_info) {
    _UPT_destroy(upt_info);
  }
  if (addr_space) {
    unw_destroy_addr_space(addr_space);
  }

  // Detach from the process
  ptrace(PTRACE_DETACH, pid, NULL, NULL);

  return result;
}

// Structure to hold frame information for dwfl callback
struct frame_info_list {
  PyObject *list;
  Dwfl *dwfl;
};

// Callback for dwfl_getthread_frames
static int
elfutils_frame_callback(Dwfl_Frame *state, void *arg) {
  struct frame_info_list *info = (struct frame_info_list *)arg;
  Dwarf_Addr pc;
  bool isactivation;

  if (!dwfl_frame_pc(state, &pc, &isactivation)) {
    return DWARF_CB_ABORT;
  }

  // Adjust PC for non-activation frames
  Dwarf_Addr pc_adjusted = pc - (isactivation ? 0 : 1);

  // Get module and symbol information
  Dwfl_Module *mod = dwfl_addrmodule(info->dwfl, pc_adjusted);
  const char *symname = NULL;

  if (mod) {
    symname = dwfl_module_addrname(mod, pc_adjusted);

    // Try to get source file and line information
    Dwfl_Line *line = dwfl_module_getsrc(mod, pc_adjusted);
    if (line != NULL) {
      int nline;
      const char *filename = dwfl_lineinfo(line, NULL, &nline, NULL, NULL, NULL);

      if (filename != NULL) {
        // Extract just the basename of the file
        const char *basename = strrchr(filename, '/');
        if (basename) {
          basename++; // Skip the '/'
        } else {
          basename = filename;
        }

        PyObject *frame_info = PyUnicode_FromFormat("%s (%s:%d)",
                                                     symname ? symname : "<unknown>",
                                                     basename, nline);
        PyList_Append(info->list, frame_info);
        Py_DECREF(frame_info);
        return DWARF_CB_OK;
      }
    }

    // No line info, just show function name and address
    if (symname) {
      PyObject *frame_info = PyUnicode_FromFormat("%s (0x%lx)", symname, pc_adjusted);
      PyList_Append(info->list, frame_info);
      Py_DECREF(frame_info);
      return DWARF_CB_OK;
    }
  }

  // Unknown - just show address
  PyObject *unknown = PyUnicode_FromFormat("<unknown> (0x%lx)", pc_adjusted);
  PyList_Append(info->list, unknown);
  Py_DECREF(unknown);

  return DWARF_CB_OK;
}

// Native elfutils remote unwinding (using dwfl_getthread_frames)
static PyObject *get_stack_remote_elfutils(PyObject *self, PyObject *args) {
  pid_t pid;
  PyObject *result = NULL;

  if (!PyArg_ParseTuple(args, "i", &pid)) {
    return NULL;
  }

  // Set up dwfl for remote process
  char *debuginfo_path = NULL;
  Dwfl_Callbacks callbacks = {
      .find_elf = dwfl_linux_proc_find_elf,
      .find_debuginfo = dwfl_standard_find_debuginfo,
      .debuginfo_path = &debuginfo_path,
  };

  Dwfl *dwfl = dwfl_begin(&callbacks);
  if (dwfl == NULL) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to initialize dwfl");
    return NULL;
  }

  // Report modules for the remote process
  int err = dwfl_linux_proc_report(dwfl, pid);
  if (err < 0) {
    dwfl_end(dwfl);
    PyErr_Format(PyExc_RuntimeError, "dwfl_linux_proc_report failed: %d", err);
    return NULL;
  }

  if (dwfl_report_end(dwfl, NULL, NULL) != 0) {
    dwfl_end(dwfl);
    PyErr_SetString(PyExc_RuntimeError, "Failed to finish reporting");
    return NULL;
  }

  // Attach to the process for unwinding
  err = dwfl_linux_proc_attach(dwfl, pid, false);
  if (err != 0) {
    dwfl_end(dwfl);
    PyErr_Format(PyExc_RuntimeError, "dwfl_linux_proc_attach failed: %d", err);
    return NULL;
  }

  // Create result list
  result = PyList_New(0);
  if (result == NULL) {
    dwfl_end(dwfl);
    return NULL;
  }

  // Set up callback data
  struct frame_info_list info = {
    .list = result,
    .dwfl = dwfl,
  };

  // Walk the stack frames
  switch (dwfl_getthread_frames(dwfl, pid, elfutils_frame_callback, &info)) {
    case DWARF_CB_OK:
    case DWARF_CB_ABORT:
      break;
    case -1:
      Py_DECREF(result);
      dwfl_end(dwfl);
      PyErr_SetString(PyExc_RuntimeError, "dwfl_getthread_frames failed");
      return NULL;
    default:
      Py_DECREF(result);
      dwfl_end(dwfl);
      PyErr_SetString(PyExc_RuntimeError, "Unexpected error in dwfl_getthread_frames");
      return NULL;
  }

  // Cleanup
  dwfl_end(dwfl);

  return result;
}

static PyMethodDef StackMethods[] = {
    {"get_stack_gnu", get_stack_gnu, METH_NOARGS,
     "Get stack trace using GNU backtrace"},
    {"get_stack_unwind", get_stack_unwind, METH_NOARGS,
     "Get stack trace using libunwind"},
    {"get_stack_dwarf", get_stack_dwarf, METH_NOARGS,
     "Get stack trace using libdw"},
    {"get_stack_frame_pointer", get_stack_frame_pointer, METH_NOARGS,
     "Get stack trace by manually walking frame pointers"},
    {"get_stack_remote", get_stack_remote, METH_VARARGS,
     "Get stack trace of a remote process using libunwind-ptrace"},
    {"get_stack_remote_elfutils", get_stack_remote_elfutils, METH_VARARGS,
     "Get stack trace of a remote process using native elfutils (dwfl_getthread_frames)"},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef stackmodule = {
    PyModuleDef_HEAD_INIT, "stackunwind",
    "Module for stack unwinding using various methods", -1, StackMethods};

PyMODINIT_FUNC PyInit_stackunwind(void) {
  return PyModule_Create(&stackmodule);
}
