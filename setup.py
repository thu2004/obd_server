from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="obd-server",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A DoIP (Diagnostics over IP) server implementation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/obd-server",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        # List your project's dependencies here
        # e.g., 'requests>=2.25.1',
    ],
    extras_require={
        'test': [
            'pytest>=6.0.0',
            'pytest-cov>=2.0.0',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Testing",
    ],
    entry_points={
        "console_scripts": [
            "obd-server=obd_server.main:main",
        ],
    },
)
