# Python library for testing Orchestration APIs
`Developed using Python 3.8.0 and requests 2.20.1`

## TOC
<!-- TABLE OF CONTENTS -->
* [About The Project](#about-the-project)
* [Setup](#setup)
* [Configuration](#configuration)
* [Dependencies](#dependencies)
* [Usage](#usage)
* [Project Structure](#project-structure)
* [Flow of Execution](#flow-of-execution)
* [Additional Details](#additional-details)
* [License](#license)


## About The Project
This library/project is created to test the orchestration APIs and Policy planner APIs.
We have provided all the required code and sample JSON data that you need to pass as a request body to APIs.Also, You need to update sample JSON files as per your requirement before calling APIs.

## Setup

**Setup - PyPi Install:**
* To **install** the library, run the following command from the terminal.

```console
pip install security-manager-apis
```

**Setup - PyPi Upgrade:**

To **upgrade** the library, run the following command from the terminal.

```console
pip install --upgrade security-manager-apis
```
* __Note__: Currently, security-manager-apis module is not available on PyPi. So, you can't install this module from PyPi.
But, you can still install this module locally as shown in below section.
We will update you here once this module is available on PyPi. 

**Setup - Local Install:**

If you are planning to make modifications to this project or you would like to access it
before it has been indexed on `PyPi`. I would recommend you either install this project
in `editable` mode or do a `local install`. For those of you, who want to make modifications
to this project. I would recommend you install the library in `editable` mode.

If you want to install the library in `editable` mode, make sure to run the `setup.py`
file, so you can install any dependencies you may need. To run the `setup.py` file,
run the following command in your terminal.

```console
pip install -e .
```

If you don't plan to make any modifications to the project but still want to use it across
your different projects, then do a local install.

```console
pip install .
```

This will install all the dependencies listed in the `setup.py` file. Once done
you can use the library wherever you want.

## Configuration
__Required Fields__ - Make sure you pass these fields while creating instance of PolicyPlannerApis and
OrchestrationApis classes :
* __host__: Pointing to your firemon server.
* __username__: The username that would be used to create the API connection to firemon.
* __password__: The API password for the given user.
* __verify_ssl__: Enabled by default. If you are running demo/test environment, good chance you'll need to set this one to `false`.

__IMP Note__ : If you are providing any other workflow(workflow_name) other than “service now“ workflow to create_pp_ticket method then you need to remove below mentioned fields from request payload of create policy planner ticket API
* __scReqItemSysId__
* __scReqItemNumber__
* __scRequestNumber__
* __externalTicketId__


## Dependencies
__Pre-requisite__ - Python 3.6 or greater version should be installed on your machine.

**Upgrade pip on Mac:**
* __NOTE__ : This is important because, apparently, some Mac apps rely on Python 2 version, so if you attempt to upgrade the Python 2.x to Python 3.x on Mac OS, you will eventually break some apps, perhaps critical apps.
With that in mind, you should not attempt to upgrade the current preinstalled Python release on the Mac; instead, you will just have the co-installation of Python 3 for full compatibility.
```console
brew install python3
```
**Upgrade pip on Windows:**
```console
python -m pip install --upgrade pip
```

## Usage
1. Open terminal or command prompt
2. Go to the correct package/directory `firemon_apis/security_manager_apis` using 'cd' command
3. Run the command `python orchestration_apis.py` or `python policy_planner_apis.py`


## Project Structure

* `orchestration_apis.py` - Added code to test/call orchestration APIs
* `application.properties` - All the required URLS are placed here.
* `policy_planner_apis.py` - Added code to test/call policy planner APIs
* `get_properties_data.py` - Read the properties file data and returns a parser

## Flow of Execution

As soon as you execute the command to run this library, Authentication class will be called which will internally call get_auth_token() of `authentication_api.py` from `authenticate_user` module only once and
auth token will be set in the headers.
Then we pass headers to the HTTP requests so that user should get authenticated and can access the endpoints safely.

## Additional Details
* `rulerec` - Sample JSON data is placed in `./RuleRec/rulerec_request_payload.json` file.
              You can update the fields as per your requirement and save the file.
* `pca` - Sample JSON data is placed in `./PCA/pca_request_payload.json` file.
          You can update the fields as per your requirement and save the file.
* `policy planner` - Sample JSON is placed in `./PolicyPlanner/create_pp_ticket_request_payload.json`                       file.You can update the fields as per your requirement and save the file.

## License
MIT. 
See the full license [here](LICENSE).
