# Protocol Buffers, Protoc, and Steam:

## About:
Steam uses Google's Protocol Buffer format (aka Protobuf) to send data between systems. Usually, this is between the Steam servers and the Steam Client, but in our case, we're acting like a Steam Client. In order for us to do so, we need to do three things: Get the latest protobuf files (aka `.proto`), compile them to something python understands, then actually use them in the plugin code. Normally, protbuf files are backwards-compatible, so in theory we only need to do this once. However, Steam occasionally changes how they do things (the most notable being the new auth flow introduced in March 2023), so we need the ability to retrieve and update our protobuf definitions and compiled versions. Caution is advised when doing so, however, because Steam can rename or move messages or fields, and while the old calls will work, if you update a proto but don't update the underlying python code, it will error. Usually, however, if you check what's changed in the proto files you'll be fine. 

## Getting started:
1. You must have python 3.7, specifically 3.7.9 or newer. 
2. You must have the modules defined in `requirements/dev.txt` installed. It is highly recommended you set up a virtual environment first. Instructions are part of the regular readme.

## Available Commands:
The following invoke tasks are available for protobuf management:
- `inv install-protoc` - Install protoc compiler locally
- `inv pull-protobuf-files` - Pull all protobuf files from GitHub
- `inv clear-protobuf-files` - Clear downloaded protobuf files
- `inv generate-protobuf-messages` - Generate Python protobuf messages using local protoc
- `inv clear-generated-protobuf` - Clear generated protobuf Python files 

## Getting the latest Proto Files:
The protobuf files that are retrieved from the urls in the `protobuf_steammessages.txt` and `protobuf_webui.txt` files. If Steam moves functions we use, these may need to be updated, but some versions have conflicts so keep that in mind. The instructions are as follows:
1. Make sure your virtual environment has `invoke` installed. If not, install the version in `requirements/dev.txt`
2. (Optional) Backup any existing `.proto` files. There may have been breaking changes. While you can view the py files instead to check for changes, it will be much easier to compare the protos instead. 
3. From the main directory, execute the following command:
  - `inv pull-protobuf-files` will retrieve both the steammessages and webui files. This command automatically handles conflicts by replacing webui import statements with their steammessages versions.
  - `inv clear-protobuf-files` will clear all downloaded protobuf files if you need to start fresh.

## Getting Protoc
In order for us to use the proto files retrieved in the previous part, we need to convert them to python. The tool to do this is called `protoc`. The problem with Protoc is it has occasionally introduced breaking changes, so we need to be careful with what version we used. This is made worse by the fact that python itself is very susceptible to breaking changes, as most modules are third-party and they tend to introduce breaking changes far too often to keep most projects up to date. So, we have provided a tool that gets the version of protoc we use for you and place it in this project. This program is portable in that it won't install anything on your computer, but is also an executable so we don't want to include it in our repo. 
The command is `inv install-protoc`. It makes a folder called `protoc` in the base directory of this project, then retrieves the protoc release for your OS, unzips it, and places it in this folder. You can do this manually if you prefer. If for whatever reason your version is incorrect, you can delete that folder and rerun the command to reinstall it. As of this writing, we use protoc 3.19.4. Later versions introduce breaking changes and we're not risking it.

## Updating the python files.
Now that we have protoc, we need to actually do the conversion. This process is fairly straightforward:
1. (Optional) Copy all existing files in `src/steam_network/protocol/messages/` to a backup directory. If you did not do this as part of the "Pull" process, do it here. 
2. Run `inv generate-protobuf-messages`. This will convert all `.proto` files found in the `protobuf_files/proto` directory into their `.py` form. These are placed in the `src/steam_network/protocol/messages` folder.
3. (Optional) Run `inv clear-generated-protobuf` to clear generated protobuf Python files if you need to start fresh.
4. If you made a backup of messages directory, you can compare the files to see if anything changed. `Diff`, `windiff`, `winmerge`, or `git diff` can all be useful here. If you did not make a backup, continue to the next step.
5. Build the plugin and **thoroughly** check that it works, especially features which may be affected by changes in their protobuf messages. This means checking all cases, not just the simple ones. This is much easier to do if you compare the compiled py files because you can see what changed, and anything unchanged does not need to be checked. 

## Sources

* <https://github.com/steamdatabase/protobufs>
* <https://github.com/ValvePython/steam>
* Uses Google's Protocol Buffers compiler (protoc) version 3.19.4 to generate Python code from .proto files. 