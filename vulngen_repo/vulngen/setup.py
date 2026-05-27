from setuptools import setup, find_packages

setup(
    name="vulngen",
    version="1.0.0",
    description="Security vulnerability analysis pipeline for LLM-generated code",
    author="Anuansh Tiwari",
    author_email="anuanshtiwari191@gmail.com",
    url="https://github.com/glassgotlazy/vulngen",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "openai>=1.30.0",
        "pandas>=2.0.0",
        "numpy>=1.26.0",
        "scipy>=1.12.0",
        "scikit-learn>=1.4.0",
        "matplotlib>=3.8.0",
        "seaborn>=0.13.0",
        "tqdm>=4.66.0",
        "pyyaml>=6.0.1",
        "python-dotenv>=1.0.0",
        "click>=8.1.7",
        "loguru>=0.7.2",
        "rich>=13.7.0",
        "PyGithub>=2.3.0",
        "requests>=2.31.0",
        "cvss>=2.6",
        "pingouin>=0.5.4",
        "bandit>=1.7.8",
        "semgrep>=1.70.0",
        "statsmodels>=0.14.0",
    ],
    entry_points={
        "console_scripts": [
            "vulngen=scripts.run_pipeline:main",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
