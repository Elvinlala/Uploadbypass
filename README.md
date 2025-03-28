# Upload Bypass

## Overview

Upload Bypass is a powerful tool designed to exploit file upload vulnerabilities. It provides  techniques to bypass file upload restrictions, automate common bypass methods, and support custom headers and user-agent manipulations.

![Upload Bypass Tool](https://github.com/Elvinlala/Uploadbypass/blob/main/Screenshot%202025-03-23%20165440.png)

## Features

- **Simple Bypass Functionality**  
  Easily craft malformed requests to bypass common file upload restrictions.

- **Scripting Common File Upload Bypass Techniques**  
  Automate the process of using common techniques to bypass file upload restrictions, saving time and effort.

- **User-Agent Bypass & Content-Type**  
  Modify User-Agent headers and Content-Type to evade detection and restrictions.

- **Custom Header Support**  
  Flexible header configurations, including custom headers, to adapt to various upload scenarios.

## Usage

To use the Upload Bypass tool, follow the instructions in the [Installation](#installation) section to set up the tool. Once set up, you can start using the various features to test and exploit file upload vulnerabilities.

### Running the Tool

Once you've set up the project, you can run the tool with the following command:

```bash
python3 Uploadbypass.py -r res.txt --extensions "payload/file_extensions.txt" --content-type "payload/content_type.txt" --user-agent "payload/user_agent.txt" --custom-header "X-Forwarded-For: 127.0.0.1" --time 5
