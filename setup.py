from setuptools import setup, find_packages, Command
import os

version = "0.1"

def read(*rnames):
    return open(os.path.join(os.path.dirname(__file__), *rnames)).read()

long_description = (
    read("README.rst")
    )

class PyTest(Command):
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        import sys,subprocess
        errno = subprocess.call([sys.executable, 'runtests.py'])
        raise SystemExit(errno)

class PyTestWithCov(PyTest):
    def run(self):
        import sys,subprocess
        errno = subprocess.call([sys.executable, 'runtests.py', '--cov-report=html', '--cov=.', '--pdb'])
        raise SystemExit(errno)

setup(
    name="pycrypto-PKCS7",
    version=version,
    description="Python Cryptography Toolkit (pycrypto) Public-Key Cryptography Standards (PKCS) #7: Cryptographic Message Syntax Version 1.5",
    long_description=long_description,
    classifiers=[
      #"Development Status :: 5 - Production/Stable",
      "License :: MIT",
      "Intended Audience :: Developers",
      "Operating System :: Unix",
      "Operating System :: Microsoft :: Windows",
      "Operating System :: MacOS :: MacOS X",
      "Topic :: Security :: Cryptography",
      "Programming Language :: Python :: 2.6",
      "Programming Language :: Python :: 2.7",
      "Programming Language :: Python :: 3.2",
      "Programming Language :: Python :: Implementation :: PyPy",
    ],
    keywords="",
    license="MIT",
    packages=find_packages(where="lib"),
    package_dir={"": "lib"},
    namespace_packages=["Crypto", "Crypto.Signature"],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        "pycrypto",
        ],
    extras_require = dict(
        test=['pytest >= 2.0'],
    ),
    cmdclass = {
      'test': PyTest,
      'cov': PyTestWithCov,
    },
    )
