import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="reassembler", 
    version="2.1.1",
    author="MarkBaggett",
    author_email="lo127001@gmail.com",
    description="Reassemble overlapping fragments into new pcaps with different OS reassembly policies.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/markbaggett/reassembler",
    license = "GNU General Public License v3 (GPLv3",
    packages=setuptools.find_packages(),
    install_requires = [
        'scapy==2.4.4', 
        ],
    include_package_data = True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    entry_points = {
        'console_scripts': ['reassembler=reassembler.__main__:cli'
                            ],
    }
)
