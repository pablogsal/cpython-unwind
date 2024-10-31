#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <execinfo.h>
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <stdio.h>
#include <stdlib.h>

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

static PyMethodDef StackMethods[] = {
    {"get_stack_gnu", get_stack_gnu, METH_NOARGS,
     "Get stack trace using GNU backtrace"},
    {"get_stack_unwind", get_stack_unwind, METH_NOARGS,
     "Get stack trace using libunwind"},
    {"get_stack_dwarf", get_stack_dwarf, METH_NOARGS,
     "Get stack trace using libdw"},
    {"get_stack_frame_pointer", get_stack_frame_pointer, METH_NOARGS,
     "Get stack trace by manually walking frame pointers"},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef stackmodule = {
    PyModuleDef_HEAD_INIT, "stackunwind",
    "Module for stack unwinding using various methods", -1, StackMethods};

PyMODINIT_FUNC PyInit_stackunwind(void) {
  return PyModule_Create(&stackmodule);
}
