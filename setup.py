from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="zerotrust-compliance-scanner",
    version="1.0.0",
    author="Zero-Trust Security Team",
    author_email="security@example.com",
    description="A fully automated serverless compliance scanner for CIS benchmarks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/leonkaushikdeka/Zero-Trust-Compliance-Scanner-2.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    install_requires=[
        "boto3>=1.26.0",
        "botocore>=1.29.0",
        "requests>=2.28.0",
        "pyhcl2>=1.1.0",
        "dataclasses-json>=0.5.0",
        "pytz>=2023.3",
        "pyyaml>=6.0",
        "click>=8.1.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.11.0",
        ],
        "aws": [
            "boto3>=1.26.0",
        ],
        "azure": [
            "azure-identity>=1.13.0",
            "azure-mgmt-resource>=23.0.0",
            "azure-mgmt-storage>=21.0.0",
            "azure-mgmt-network>=20.0.0",
        ],
        "gcp": [
            "google-cloud-storage>=2.10.0",
            "google-cloud-compute>=1.10.0",
            "google-cloud-oslogin>=1.10.0",
            "google-cloud-resource-manager>=1.10.0",
        ],
        "kubernetes": [
            "kubernetes>=27.2.0",
        ],
        "lambda": [
            "aws-lambda-powertools>=2.13.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "compliance-scan=src.integrations.cicd_integration:main",
        ],
    },
    include_package_data=True,
    package_data={
        "src": ["**/*.py", "**/*.json", "**/*.yaml"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
    keywords="security, compliance, cis, aws, azure, gcp, kubernetes, terraform",
)
