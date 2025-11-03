import os
import sys
import json
import platform
import requests
import tempfile
import zipfile
from shutil import rmtree, copytree, copyfile
from distutils.dir_util import copy_tree
from glob import glob
from io import BytesIO
from urllib.request import urlopen
from http.client import HTTPResponse
from galaxy.tools import zip_folder_to_file

from invoke import task
from invoke.exceptions import Exit

GUID = "ca27391f-2675-49b1-92c0-896d43afa4f8"
system = platform.system()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROTOC_DIR = os.path.join(BASE_DIR, "protoc")

# Platform-specific protoc configuration
if sys.platform == 'win32':
    PROTOC_EXE = os.path.join(PROTOC_DIR, "bin", "protoc.exe")
    PROTOC_INCLUDE_DIR = os.path.join(PROTOC_DIR, "include")
    PROTOC_DOWNLOAD_URL = "https://github.com/protocolbuffers/protobuf/releases/download/v3.19.4/protoc-3.19.4-win32.zip"
elif sys.platform == 'darwin':
    PROTOC_EXE = os.path.join(PROTOC_DIR, "bin", "protoc")
    PROTOC_INCLUDE_DIR = os.path.join(PROTOC_DIR, "include")
    PROTOC_DOWNLOAD_URL = "https://github.com/protocolbuffers/protobuf/releases/download/v3.19.4/protoc-3.19.4-osx-x86_64.zip"

def load_version():
    script_dir = os.path.abspath(os.path.dirname(__file__))
    version_file = os.path.join(script_dir, "src", "version.py")
    version = {}
    exec(open(version_file).read(), version)
    return version["__version__"]

# Protobuf helper functions
def _read_url(response: HTTPResponse) -> str:
    charset = response.headers.get_content_charset('utf-8')
    raw_data = response.read()
    return raw_data.decode(charset)


def _get_filename_from_url(url: str) -> str:
    return url.split("/")[-1]


def _protobuf_target_dir() -> str:
    return os.path.join(BASE_DIR, "protobuf_files", "proto")

def _prepare_clean_target_dir(target_dir: str):
    try:
        rmtree(target_dir)
    except Exception:
        pass  # directory probably just didn't exist

    os.makedirs(target_dir, exist_ok=True)

def _pull_protobufs_internal(c, selection: str, silent: bool = False):
    target_dir = _protobuf_target_dir()
    list_file = os.path.join(BASE_DIR, "protobuf_files", f"protobuf_{selection}.txt")

    with open(list_file, "r") as file:
        urls = filter(None, file.read().split("\n"))  # filter(None, ...) is used to strip empty lines from the collection

    for url in urls:
        if not silent:
            print("Retrieving: " + url)

        file_name = _get_filename_from_url(url)

        response = urlopen(url)
        data = _read_url(response)

        # needed to avoid packages of the form ...steam_auth.steamclient_pb2
        if ".steamclient.proto" in file_name:
            file_name = file_name.replace(".steamclient.proto", ".proto")
        if ".steamclient.proto" in data:
            data = data.replace(".steamclient.proto", ".proto")

        if "cc_generic_services" in data:
            data = data.replace("cc_generic_services", "py_generic_services")

        if selection == "webui":
            # lil' hack to avoid name collisions; the definitions are (almost) identical so this shouldn't break anything
            data = data.replace("common_base.proto", "steammessages_unified_base.proto")
            data = data.replace("common.proto", "steammessages_base.proto")

        # force proto2 syntax if not yet enforced
        if "proto2" not in data:
            data = f'syntax = "proto2";\n' + data

        with open(os.path.join(target_dir, file_name), "w") as dest:
            dest.write(data)

@task(aliases=["req"])
def requirements(c):
    """Install python requirements"""
    c.run("pip install -r requirements/dev.txt")

@task(optional=["output", "ziparchive"])
def build(c, output="output", ziparchive=None):
    """Build plugin package"""

    env = {}
    if system == "Windows":
        pip_platform = "win32"
    elif system == "Darwin":
        pip_platform = "macosx_10_13_x86_64"
        env["MACOSX_DEPLOYMENT_TARGET"] = "10.13" # for building from sources
    else:
        Exit(f"System {system} not supported")

    if os.path.exists(output):
        print(f'--> Removing {output} directory')
        rmtree(output)

    # Firstly dependencies need to be "flattened" with pip-compile,
    # as pip requires --no-deps if --platform is used.
    print('--> Flattening dependencies to temporary requirements file')
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
        c.run(f'pip-compile requirements/app.txt --output-file=-', out_stream=tmp)

    # Then install all stuff with pip to output folder
    print('--> Installing with pip for specific version')
    args = [
        'pip', 'install',
        '-r', tmp.name,
        '--python-version', '37',
        '--platform', pip_platform,
        f'--target "{output}"',
        '--no-compile',
        '--no-deps'
    ]
    c.run(" ".join(args), echo=True)
    os.unlink(tmp.name)

    print('--> Copying source files')
    copy_tree("src", output)

    # remove dependencies tests
    for test in glob(f"{output}/**/test_*.py", recursive=True):
        os.remove(test)
    for test in glob(f"{output}/**/*_test.py", recursive=True):
        os.remove(test)

    # remove pycache directories
    for pycache in glob(f"{output}/**/__pycache__", recursive=True):
        rmtree(pycache, ignore_errors=True)

    # remove any dependencies' readmes that might've ended up in plugin root
    for readme in glob(f"{output}/[rR][eE][aA][dD][mM][eE]*"):
        os.remove(readme)

    # copy plugin readme
    copyfile("README.md", os.path.join(output, "README.md"))

    # create manifest
    manifest = {
        "name": "Galaxy Steam plugin",
        "platform": "steam",
        "guid": GUID,
        "version": load_version(),
        "description": "Galaxy Steam plugin",
        "author": "Friends of Galaxy",
        "email": "friendsofgalaxy@gmail.com",
        "url": "https://github.com/FriendsOfGalaxy/galaxy-integration-steam",
        "update_url": "https://raw.githubusercontent.com/FriendsOfGalaxy/galaxy-integration-steam/master/current_version.json",
        "script": "plugin.py"
    }
    with open(os.path.join(output, "manifest.json"), "w") as file_:
        json.dump(manifest, file_, indent=4)

    if ziparchive is not None:
        print(f'--> Compressing to {ziparchive}')
        zip_folder_to_file(output, ziparchive)

@task()
def install(c, output="output"):
    """Install plugin in local galaxy instance"""
    if system == "Windows":
        plugins_dir = os.path.expandvars("%LOCALAPPDATA%/GOG.com/Galaxy/plugins/installed")
    elif system == "Darwin":
        plugins_dir = os.path.expanduser("~/Library/Application Support/GOG.com/Galaxy/plugins/installed")

    dst = os.path.join(plugins_dir, f"steam_{GUID}")
    if os.path.exists(dst):
        rmtree(dst)
    copytree(output, dst)

@task(aliases=["ut"])
def unit_tests(c):
    """Run unit tests"""
    c.run('pytest -m "not integration" --cache-clear --ignore=src/steam_network/protocol/messages')

@task(aliases=["it"])
def integration_tests(c):
    """Run integration tests"""
    c.run("pytest -m integration --cache-clear -s")

@task(unit_tests, build, integration_tests)
def all(_):
    """Test, build and run integration tests"""
    pass

# Protobuf management tasks
@task
def install_protoc(c):
    """Install protoc compiler locally"""
    if os.path.exists(PROTOC_DIR) and os.path.isdir(PROTOC_DIR):
        print("protoc directory already exists, remove it if you want to reinstall protoc")
        return

    os.makedirs(PROTOC_DIR)

    resp = requests.get(PROTOC_DOWNLOAD_URL, stream=True)
    resp.raise_for_status()

    with zipfile.PyZipFile(BytesIO(resp.content)) as zipf:
        zipf.extractall(PROTOC_DIR)

    print("protoc successfully installed")


@task
def pull_protobuf_files(c, silent=False):
    """Pull all protobuf files from GitHub"""
    _prepare_clean_target_dir(_protobuf_target_dir())
    _pull_protobufs_internal(c, "steammessages", silent)
    _pull_protobufs_internal(c, "webui", silent)


@task
def clear_protobuf_files(c):
    """Clear downloaded protobuf files"""
    filelist = [f for f in os.listdir("protobuf_files/proto") if f.endswith(".proto")]
    for f in filelist:
        os.remove(os.path.join("protobuf_files/proto", f))


@task
def generate_protobuf_messages(c):
    """Generate Python protobuf messages using local protoc"""
    proto_files_dir = os.path.join(BASE_DIR, "protobuf_files", "proto")

    out_dir = os.path.join(BASE_DIR, "src", "steam_network", "protocol", "messages")

    try:
        rmtree(os.path.join(out_dir))
    except Exception:
        pass  # directory probably just didn't exist

    os.makedirs(os.path.join(out_dir), exist_ok=True)

    # make sure __init__.py is there
    with open(os.path.join(out_dir, "__init__.py"), "wb") as fp:
        fp.write(b"")

    all_files = " ".join(map(lambda x: '"' + os.path.join(proto_files_dir, x) + '"', os.listdir(proto_files_dir)))
    print(f'{PROTOC_EXE} -I "{proto_files_dir}" --python_out="{out_dir}" {all_files}')
    c.run(f'{PROTOC_EXE} -I "{proto_files_dir}" --python_out="{out_dir}" {all_files}')


@task
def clear_generated_protobuf(c, genFile=True):
    """Clear generated protobuf Python files"""
    out_dir = "./protobuf_files/gen/" if genFile else "src/steam_network/protocol/messages"
    filelist = [f for f in os.listdir(out_dir) if f.endswith(".py")]
    for f in filelist:
        os.remove(os.path.join(out_dir, f))
