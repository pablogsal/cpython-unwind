python setup.py clean --all  # Clean previous build
python setup.py build_ext --inplace
PYTHON_JIT=0 python run.py
PYTHON_JIT=1 python run.py
