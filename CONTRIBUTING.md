# Contributor Guide

## Code of Conduct

Contributors are asked to adhere to the [Python Community Code of Conduct](https://www.python.org/psf/conduct/).

## Development Environment

Linux is the preferred operating system to use while contributing to the csaf tool.

Only use a supported version of Python (this is any version of Python from version 3.7).

It is recommended that a virtual python environment [virtualenv](https://virtualenv.pypa.io/en/latest/) is used to minimise
interference that dependencies may have on your environment. It also enables the use of the tool using different versions of Python.

To install it:

```bash
pip install virtualenv
```

To make a new venv using python 3.9:

```bash
virtualenv -p python3.9 ~/Code/venv3.9
```

Each time you want to use a virtualenv, you "activate" it using the activate script:

```bash
source ~/Code/venv3.9/bin/activate
```

And when you're done with the venv, you can deactivate it using the `deactivate` command.

While you're in a venv, the `python` command will point to whatever version you specified when the venv was created, and pip command will install things only in that venv so you don't have to worry about conflicts with other versions or system packages.

## Getting and maintaining a local copy of the source code

If you're planning to contribute, first you'll want to
[get a local copy of the source code (also known as "cloning the repository")](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/cloning-a-repository)

Once you've got the copy, you can update it using

`git pull`

You're also going to want to have your own "fork" of the repository on GitHub.
To make a fork on GitHub, read the instructions at [Fork a
repo](https://help.github.com/en/github/getting-started-with-github/fork-a-repo).
A fork is a copy of the main repository that you control, and you'll be using
it to store and share your code with others.  You only need to make the fork once.

## Installing dependencies

Any additional packages needed are listed in the `requirements.txt` file in the main directory.
These can be installed using the following pip command:

```bash
pip install -U -r requirements.txt
```

The `-U` in that line above will update you to the latest versions of packages as needed, which is recommended
in order to have all the latest updates available. The `-r requirements.txt` specifies the file with all the requirements.

```bash
pip install -r dev-requirements.txt
```

## Running a local copy 

One of the reasons that virtualenv is suggested is that it makes it easier to do this section.

To run a local copy, the recommended way is to install it locally. From the main directory, run:

```bash
python3 -m pip install --user -e .
```

You should then be able to type `sbom4python --help` on the command line, and it should show the help information. If this does not
work, then double check that you have setup the local environment correctly, have downloaded and installed the code correctly,
that you are in your virtual environment and that the latest versions of
any dependent components have been installed.

## Running linters

The following tools can be used to improve code quality and readability:

- `isort` sorts imports alphabetically and by type
- `black` provides automatic style formatting.  This will give you basic [PEP8](https://www.python.org/dev/peps/pep-0008/) compliance. (PEP8 is where the default python style guide is defined.)
- `flake8` provides additional code "linting" for more complex errors like unused imports.
- `pyupgrade` helps to be forward compatible with new versions of python.

### Running isort by itself

To format the imports using isort, you run `isort --profile black` followed by the filename. You will have to add `--profile black` when calling isort to make it compatible with Black formatter. For formatting a particular file name filename.py.

```bash
isort --profile black filename.py
```

Alternatively, you can run isort recursively for all the files by adding `.` instead of filename

```bash
isort --profile black .
```

### Running black by itself

To format the code, you run `black` followed by the filename you wish to reformat.  For formatting a particular file name filename.py.

```bash
black filename.py
```

`black` should be run after `isort`.

### Other tools

As well as `black` for automatically making sure code adheres to the style guide, `flake8` is used to help find things like unused imports.  The [flake8 documentation](https://flake8.pycqa.org/en/latest/user/index.html) covers what you need to know about running it.

[pyupgrade](https://github.com/asottile/pyupgrade) is used to ensure any syntax is updated to fit new versions of python.

## Style Guide

Most of our "style" stuff is caught by the `black` and `flake8` linters, but we also recommend that
contributions use f-strings for formatted strings:

### String Formatting

Python provides multiple ways to format a string (you can read about them [here](https://realpython.com/python-formatted-output/)) .
This tool uses f-string formatting.

- **Example:** Formatting string using f-string

```python
#Program prints a string containing name and age of person
name = "John Doe"
age = 23
print(f"Name of the person is {name} and his age is {age}")

#Output
# "Name of the person is John Doe and his age is 23"
```

Note that the string started with the `f` followed by the string. Values are always added in the curly braces. Also we don't need to convert age into string. (we may have used `str(age)` before using it in the string) f-strings are useful as they provide many cool features. You can read more about features and the good practices to use f-strings [here](https://realpython.com/python-f-strings/#f-strings-a-new-and-improved-way-to-format-strings-in-python).

## Documentation

The documentation is within the README.md file, which is stored in the main directory.

Any updates to the usage of the tool, particularly any updates to command line options or limitations should be described in the README.md file

Note that the contents of the README.md file is included in the documentation when the tool is released to [pypi](https://pypi.org/).