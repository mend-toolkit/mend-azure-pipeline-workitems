import setuptools
from mend_azure_wi_sync._version import __version__, __description__, __tool_name__

mend_name = f"mend_{__tool_name__}"

setuptools.setup(
    name=mend_name,
    entry_points={
        'console_scripts': [
            f'{__tool_name__}={mend_name}.{__tool_name__}:main'
        ]},
    packages=setuptools.find_packages(),
    version=__version__,
    author="Mend Professional Services",
    author_email="ps@mend.io",
    # Spelled out rather than derived from __tool_name__: the repo is named after the pipeline
    # integration, not the console script, so deriving it produced a 404 on the PyPI page.
    url="https://github.com/mend-toolkit/mend-azure-pipeline-workitems",
    description=__description__,
    license='LICENSE.txt',
    python_requires='>=3.12',
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    install_requires=[line.strip() for line in open("requirements.txt", encoding="utf-8").readlines()],
    classifiers=[
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)
