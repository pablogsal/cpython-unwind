from setuptools import setup, Extension

stackunwind_module = Extension(
    "stackunwind",
    sources=["stackunwind.c"],
    libraries=["unwind", "unwind-ptrace", "unwind-x86_64", "dw", "elf"],
    extra_compile_args=["-g", "-O0"],  # Include debug symbols
    extra_link_args=["-g"],
)

setup(
    name="stackunwind",
    version="1.0",
    description="Stack unwinding module using multiple methods",
    ext_modules=[stackunwind_module],
)
